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
    persistSession: true,
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
    protected persistSession: boolean
    protected localStorage: SupportedStorage
    protected stateChangeEmitters: Map<string, Subscription> = new Map()
    protected refreshTokenTimer?: ReturnType<typeof setTimeout>

    /**
     * Create a new client for use in the browser.
     * @param options.url The URL of the SpecAuth server.
     * @param options.headers Any additional headers to send to the SpecAuth server.
     * @param options.autoRefreshToken Set to "true" if you want to automatically refresh the token before expiring.
     * @param options.persistSession Set to "true" if you want to automatically save the user session into local storage.
     * @param options.localStorage Provide your own local storage implementation to use instead of the browser's local storage.
     * @param options.fetch A custom fetch implementation.
     */
    constructor(options: {
        url?: string
        headers?: { [key: string]: string }
        autoRefreshToken?: boolean
        persistSession?: boolean
        localStorage?: SupportedStorage
        fetch?: Fetch
    }) {
        const settings = { ...DEFAULT_OPTIONS, ...options }
        this.currentUser = null
        this.currentSession = null
        this.autoRefreshToken = settings.autoRefreshToken
        this.persistSession = settings.persistSession && isBrowser()
        this.localStorage = settings.localStorage || globalThis.localStorage
        this.api = new SpecAuthApi({
            url: settings.url,
            headers: settings.headers,
            fetch: settings.fetch,
        })
        this._recoverActiveSession()
        this._recoverAndRefresh()
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

    /**
     * Force refreshes the session including the user data in case it was updated in a different session.
     */
    async refreshSession(): Promise<{
        session: Session | null
        user: User | null
        error: ApiError | null
    }> {
        try {
            if (!this.currentSession?.accessToken) throw new Error('Not logged in.')

            // currentSession and currentUser will be updated to latest on _callRefreshToken
            const { error } = await this._callRefreshToken()
            if (error) throw error

            return { session: this.currentSession, user: this.currentUser, error: null }
        } catch (e) {
            return { session: null, user: null, error: e as ApiError }
        }
    }

    /**
     * Sets the session data from refreshToken and returns current Session and Error
     * @param refreshToken a JWT token
     */
    async setSession(
        refreshToken: string
    ): Promise<{ session: Session | null; error: ApiError | null }> {
        try {
            if (!refreshToken) {
                throw new Error('No current session.')
            }

            const { data, error } = await this.api.refreshAccessToken(refreshToken)
            if (error) throw error
            if (!data) throw Error('Invalid session data.')

            this._saveSession(data)
            this._notifyAllSubscribers(events.SIGNED_IN)

            return { session: data, error: null }
        } catch (e) {
            return { error: e as ApiError, session: null }
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
            if (!inactiveSession || !inactiveSession.expiresAt || !inactiveSession.user) return false

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
                const { error } = await this._callRefreshToken(inactiveSession.refreshToken)
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
     onStateChange(callback: (event: string, session: Session | null) => void): {
        data: Subscription | null
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
            return { data: subscription, error: null }
        } catch (err) {
            return { data: null, error: err as ApiError }
        }
    }

    /**
     * Inside a browser context, `signOut()` will remove the logged in user from the browser session
     * and log them out - removing all items from localstorage.
     *
     * For server-side management, you can disable sessions by passing a JWT through to `auth.api.signOut(JWT: string)`
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
            if (!persistedSessions) return

            // Get the current session using the stored "active" address.
            const { sessions = {}, activeAddress } = persistedSessions
            const currentSession = activeAddress && sessions[activeAddress]

            const timeNow = Math.round(Date.now() / 1000)
            const expiresAt = currentSession?.expiresAt

            // If recovered session is expired...
            if (expiresAt && expiresAt < timeNow) {
                // Refresh the session using a refresh token (if configured to do so).
                if (this.autoRefreshToken && currentSession.refreshToken) {
                    const { error } = await this._callRefreshToken(currentSession.refreshToken)
                    if (error) {
                        console.log(error.message)
                        await this._removeSessions()
                    }
                } else {
                    this._removeSessions()
                }
            }
            // Remove any incomplete persisted session data.
            else if (!expiresAt || !currentSession || !currentSession.user) {
                console.log('Current session is missing data.')
                this._removeSessions()
            }
            // Use session as current one if not expired.
            else {
                // should be handled on _recoverActiveSession method already
                // But we still need the code here to accommodate for AsyncStorage e.g. in React native
                this._saveSession(currentSession)
                this._notifyAllSubscribers(events.SIGNED_IN)
            }
        } catch (err) {
            console.error(err)
            return null
        }
    }

    private async _callRefreshToken(refreshToken = this.currentSession?.refreshToken) {
        try {
            if (!refreshToken) {
                throw new Error('No current session.')
            }
            const { data, error } = await this.api.refreshAccessToken(refreshToken)
            if (error) throw error
            if (!data) throw Error('Invalid session data.')

            this._saveSession(data)
            this._notifyAllSubscribers(events.TOKEN_REFRESHED)
            this._notifyAllSubscribers(events.SIGNED_IN)

            return { data, error: null }
        } catch (e) {
            return { data: null, error: e as ApiError }
        }
    }

    /**
     * set currentSession and currentUser
     * process to _startAutoRefreshToken if possible
     */
    private _saveSession(session: Session) {
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

        if (isBrowser() && this.persistSession) {
            this._persistSession(this.currentSession)
        }
    }

    private async _persistSession(currentSession: Session) {
        const persistedSessions = await this._getPersistedSessions()
        const currentUserAddress = currentSession.user.id
        persistedSessions.sessions[currentUserAddress] = currentSession
        persistedSessions.activeAddress = currentUserAddress
        await this._setToStorage(STORAGE_KEY, persistedSessions)
    }

    private async _getPersistedSessions(): Promise<PersistedSessions> {
        return await this._getFromStorage(STORAGE_KEY) || {
            sessions: {},
            activeAddress: '',
        }
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
        this.stateChangeEmitters.forEach((x) => x.callback(event, this.currentSession))
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
