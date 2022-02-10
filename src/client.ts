import SpecAuthApi from './api'
import { isBrowser, uuid } from './lib/helpers'
import { SPEC_AUTH_URL, DEFAULT_HEADERS, STORAGE_KEY } from './lib/constants'
import { polyfillGlobalThis } from './lib/polyfills'
import events from './lib/events'
import { Fetch } from './lib/fetch'
import type {
    ApiError,
    Session,
    User,
    MessageNonce,
    PersistedSessions,
    Subscription,
} from './lib/types'

polyfillGlobalThis() // Make "globalThis" available

const DEFAULT_OPTIONS = {
    url: SPEC_AUTH_URL,
    autoRefreshToken: true,
    persistSessions: true,
    recoverSessions: true,
    headers: DEFAULT_HEADERS,
}

type AnyFunction = (...args: any[]) => any

type MaybePromisify<T> = T | Promise<T>

type PromisifyMethods<T> = {
    [K in keyof T]: T[K] extends AnyFunction
        ? (...args: Parameters<T[K]>) => MaybePromisify<ReturnType<T[K]>>
        : T[K]
}

type SupportedStorage = PromisifyMethods<Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>>

export default class SpecAuthClient {
    /**
     * Namespace for the SpecAuth API methods.
     */
    api: SpecAuthApi
    /**
     * The currently logged in user or null.
     */
    protected currentUser: User | null
    /**
     * The session object for the currently logged in user or null.
     */
    protected currentSession: Session | null

    protected autoRefreshToken: boolean
    protected persistSessions: boolean
    protected localStorage: SupportedStorage
    protected stateChangeEmitters: Map<string, Subscription> = new Map()
    protected refreshTokenTimer?: ReturnType<typeof setTimeout>
    protected loading: boolean = true

    /**
     * Create a new client for use in the browser.
     * @param options.url The URL of the SpecAuth server.
     * @param options.headers Any additional headers to send to the SpecAuth server.
     * @param options.autoRefreshToken Set to "true" if you want to automatically refresh the token before expiring.
     * @param options.persistSessions Set to "true" if you want to automatically save the user sessions into local storage.
     * @param options.recoverSessions Set to "true" if you want to automatically recover sessions from local storage on init.
     * @param options.localStorage Provide your own local storage implementation to use instead of the browser's local storage.
     * @param options.fetch A custom fetch implementation.
     */
    constructor(options: {
        url?: string
        headers?: { [key: string]: string }
        autoRefreshToken?: boolean
        persistSessions?: boolean
        recoverSessions?: boolean
        localStorage?: SupportedStorage
        fetch?: Fetch
    }) {
        const settings = { ...DEFAULT_OPTIONS, ...options }
        this.currentUser = null
        this.currentSession = null
        this.autoRefreshToken = settings.autoRefreshToken
        this.persistSessions = settings.persistSessions && isBrowser()
        this.localStorage = settings.localStorage || globalThis.localStorage
        this.api = new SpecAuthApi({
            url: settings.url,
            headers: settings.headers,
            fetch: settings.fetch,
        })

        if (settings.recoverSessions) {
            this._recoverActiveSession()
            this._recoverAndRefresh()
        } else {
            this._removeSessions()
            this.loading = false
        }
    }

    /**
     * Returns whether the initial auth state is still being determined.
     */
    isLoading(): boolean {
        return this.loading
    }

    /**
     * Returns the user data, if there is a logged in user.
     */
    user(): User | null {
        return this.currentUser
    }

    /**
     * Returns the session data, if there is an active session.
     */
    session(): Session | null {
        return this.currentSession
    }

    /**
     * Initialize the auth flow by requesting a message for a user to sign.
     * @param address The user's account address.
     */
    async init(address: string): Promise<{ data: MessageNonce | null; error: ApiError | null }> {
        try {
            const { data, error } = await this.api.initAuth(address)
            if (error) throw error
            if (!data) throw 'An error occurred requesting a message to sign.'

            return { data, error: null }
        } catch (e) {
            return { data: null, error: e as ApiError }
        }
    }

    /**
     * Verify a signed message to receive a new auth session for a user.
     * @param address The user's account address.
     * @param signature The signed message.
     */
    async verify(
        address: string,
        signature: string
    ): Promise<{
        session: Session | null
        user: User | null
        isNewUser: boolean
        error: ApiError | null
    }> {
        try {
            const { data, error } = await this.api.verifyAuth(address, signature)
            if (error) throw error
            if (!data) throw 'An error occurred on sign-in.'

            const { session, user, isNewUser } = data
            this._saveSession(session)
            this._notifyAllSubscribers(events.SIGNED_IN)

            return { session, user, isNewUser, error: null }
        } catch (e) {
            return { session: null, user: null, isNewUser: false, error: e as ApiError }
        }
    }

    async switchToInactiveSession(address: string): Promise<boolean> {
        try {
            // Don't do anything if this address is already the active session user.
            if (this.currentUser?.id === address) return true

            // Get map of sessions persisted to storage.
            const persistedSessions = await this._getFromStorage(STORAGE_KEY)
            if (!persistedSessions) return false

            // Get stored inactive session for the given address (if it exists).
            const { sessions = {} } = persistedSessions
            const inactiveSession = sessions[address]
            if (!inactiveSession || !inactiveSession.expiresAt || !inactiveSession.user)
                return false

            // If not expired yet, use this session as the active one.
            const timeNow = Math.round(Date.now() / 1000)
            const isExpired = timeNow > inactiveSession.expiresAt
            if (!isExpired) {
                this._saveSession(inactiveSession)
                this._notifyAllSubscribers(events.SIGNED_IN)
                return true
            }

            // Try refreshing the session using a refresh token (if configured to do so)
            // before switching to it as the active one.
            if (this.autoRefreshToken && inactiveSession.refreshToken) {
                const { error } = await this._callRefreshToken(
                    inactiveSession.refreshToken,
                    inactiveSession.user,
                )
                if (error) {
                    console.error(error)
                    await this._removeSessions()
                    return false
                }
                return true
            }

            return false
        } catch (error) {
            console.error(error)
            return false
        }
    }

    /**
     * Receive a notification every time an auth event happens.
     * @returns {Subscription} A subscription object which can be used to unsubscribe itself.
     */
    onStateChange(callback: (event: string, user: User | null) => void): {
        listener: Subscription | null
        error: ApiError | null
    } {
        try {
            const id: string = uuid()
            const subscription: Subscription = {
                id,
                callback,
                unsubscribe: () => {
                    this.stateChangeEmitters.delete(id)
                },
            }
            this.stateChangeEmitters.set(id, subscription)
            return { listener: subscription, error: null }
        } catch (err) {
            return { listener: null, error: err as ApiError }
        }
    }

    /**
     * Remove the logged in user from the session, removing all items from localstorage.
     */
    async signOut(): Promise<{ error: ApiError | null }> {
        const accessToken = this.currentSession?.accessToken
        this._removeSessions()
        this._notifyAllSubscribers(events.SIGNED_OUT)

        if (accessToken) {
            const { error } = await this.api.signOut(accessToken)
            if (error) return { error }
        }

        return { error: null }
    }

    /**
     * Attempts to get the session from LocalStorage
     * Note: this should never be async (even for React Native), as we need it to return immediately in the constructor.
     */
    private _recoverActiveSession() {
        try {
            // Get map of sessions persisted to storage.
            const persistedSessions = this._getFromStorageSync(STORAGE_KEY)
            if (!persistedSessions) return

            // Get the current session using the stored "active" address.
            const { sessions = {}, activeAddress } = persistedSessions
            const currentSession = activeAddress && sessions[activeAddress]
            if (!currentSession) return

            // Use session as current one if not expired.
            const timeNow = Math.round(Date.now() / 1000)
            const expiresAt = currentSession.expiresAt
            if (expiresAt && expiresAt >= timeNow && currentSession.user) {
                this._saveSession(currentSession)
                this._notifyAllSubscribers(events.INITIAL_STATE_LOADED)
                this._notifyAllSubscribers(events.SIGNED_IN)
            }
        } catch (error) {
            console.error('error attempting session recovery', error)
        }
    }

    /**
     * Recovers the session from LocalStorage and refreshes
     * Note: this method is async to accommodate for AsyncStorage e.g. in React native.
     */
    private async _recoverAndRefresh() {
        try {
            // Get map of sessions persisted to storage.
            const persistedSessions = await this._getFromStorage(STORAGE_KEY)
            if (!persistedSessions) {
                this.loading = false
                this._notifyAllSubscribers(events.INITIAL_STATE_LOADED)
                return
            }

            // Get the current session using the stored "active" address.
            const { sessions = {}, activeAddress } = persistedSessions
            const currentSession = activeAddress && sessions[activeAddress]

            const timeNow = Math.round(Date.now() / 1000)
            const expiresAt = currentSession?.expiresAt

            // If recovered session is expired...
            if (expiresAt && expiresAt < timeNow) {
                // Refresh the session using a refresh token (if configured to do so).
                if (this.autoRefreshToken && currentSession.refreshToken) {
                    const { error } = await this._callRefreshToken(
                        currentSession.refreshToken,
                        currentSession.user,
                    )
                    if (error) {
                        console.log(error.message)
                        await this._removeSessions()
                    }
                } else {
                    this._removeSessions()
                }
            } else if (!expiresAt || !currentSession || !currentSession.user) {
                console.log('Current session is missing data.')
                this._removeSessions()
            } else {
                // Use session as current one if not expired.
                // Should be handled on _recoverActiveSession method already,
                // but we still need the code here to accommodate for AsyncStorage e.g. in React native.
                this._saveSession(currentSession)
                this._notifyAllSubscribers(events.SIGNED_IN)
            }
        } catch (err) {
            console.error(err)
        }
        this.loading = false
        this._notifyAllSubscribers(events.INITIAL_STATE_LOADED)
    }

    private async _callRefreshToken(
        refreshToken: string | undefined = this.currentSession?.refreshToken,
        user: User | null = this.currentUser
    ): Promise<{
        data: Session | null
        error: ApiError | null
    }> {
        try {
            if (!refreshToken) throw new Error('No current session.')

            // Use the refresh token to get a new full session, with an access token.
            const { data: session, error } = await this.api.refreshAccessToken(refreshToken)
            if (error) throw error
            if (!session || !session.user) throw Error('Invalid session data.')

            // Allow user to be overridden so that the API call above doesn't have to always
            // return full user data and can just focus on refreshing a session.
            session.user = user || session.user

            this._saveSession(session)
            this._notifyAllSubscribers(events.TOKEN_REFRESHED)
            this._notifyAllSubscribers(events.SIGNED_IN)

            return { data: session, error: null }
        } catch (err) {
            return { data: null, error: err as ApiError }
        }
    }

    /**
     * set currentSession and currentUser
     * process to _startAutoRefreshToken if possible
     */
    private _saveSession(session: Session) {
        this.loading = false
        this.currentSession = session
        this.currentUser = session.user

        const expiresAt = session.expiresAt
        if (expiresAt) {
            const timeNow = Math.round(Date.now() / 1000)
            const expiresIn = expiresAt - timeNow
            const refreshDurationBeforeExpires = expiresIn > 60 ? 60 : 0.5
            this._startAutoRefreshToken((expiresIn - refreshDurationBeforeExpires) * 1000)
        }

        if (!this.currentUser) {
            console.log('Current session is missing data.')
        }

        if (isBrowser() && this.persistSessions) {
            this._persistSessions(this.currentSession)
        }
    }

    private async _persistSessions(currentSession: Session) {
        const persistedSessions = await this._getPersistedSessions()
        const currentUserAddress = currentSession.user.id
        persistedSessions.sessions[currentUserAddress] = currentSession
        persistedSessions.activeAddress = currentUserAddress
        await this._setToStorage(STORAGE_KEY, persistedSessions)
    }

    private async _getPersistedSessions(): Promise<PersistedSessions> {
        return (
            (await this._getFromStorage(STORAGE_KEY)) || {
                sessions: {},
                activeAddress: '',
            }
        )
    }

    private async _removeSessions() {
        this.currentSession = null
        this.currentUser = null
        this.refreshTokenTimer && clearTimeout(this.refreshTokenTimer)
        isBrowser() && (await this._removeFromStorage(STORAGE_KEY))
    }

    /**
     * Clear and re-create refresh token timer
     * @param value time intervals in milliseconds
     */
    private _startAutoRefreshToken(value: number) {
        if (this.refreshTokenTimer) clearTimeout(this.refreshTokenTimer)
        if (value <= 0 || !this.autoRefreshToken) return

        this.refreshTokenTimer = setTimeout(() => this._callRefreshToken(), value)
        if (typeof this.refreshTokenTimer.unref === 'function') this.refreshTokenTimer.unref()
    }

    private _notifyAllSubscribers(event: string) {
        this.stateChangeEmitters.forEach((x) => x.callback(event, this.currentUser))
    }

    private async _getFromStorage(key: string): Promise<any> {
        const json = isBrowser() && (await this.localStorage?.getItem(key))
        return this._parseStorageJSON(json)
    }

    private _getFromStorageSync(key: string): any {
        const json = isBrowser() && this.localStorage?.getItem(key)
        return this._parseStorageJSON(json)
    }

    private _parseStorageJSON(json: any): any {
        if (!json || typeof json !== 'string') {
            return null
        }

        try {
            return JSON.parse(json)
        } catch (e) {
            console.error('json error', e)
            return null
        }
    }

    private async _setToStorage(key: string, value: any) {
        if (!isBrowser()) return
        let json
        try {
            json = JSON.stringify(value)
        } catch (e) {
            console.error('json error', e)
            return
        }

        await this.localStorage.setItem(key, json)
    }

    private async _removeFromStorage(key: string) {
        isBrowser() && (await this.localStorage.removeItem(key))
    }
}
