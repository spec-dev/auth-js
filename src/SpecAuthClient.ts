import SpecAuthApi from './SpecAuthApi'
import { isBrowser } from './lib/helpers'
import { SPEC_AUTH_URL, DEFAULT_HEADERS, STORAGE_KEY } from './lib/constants'
import { polyfillGlobalThis } from './lib/polyfills'
import { Fetch } from './lib/fetch'
import type { ApiError, Session, User, MessageNonce } from './lib/types'

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
        this.persistSession = settings.persistSession
        this.localStorage = settings.localStorage || globalThis.localStorage
        this.api = new SpecAuthApi({
            url: settings.url,
            headers: settings.headers,
            fetch: settings.fetch,
        })
        this._recoverSession()
        this._recoverAndRefresh()
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
        isNewUser: boolean
        error: ApiError | null
    }> {
        try {
            this._removeSession()

            const { data, error } = await this.api.verifyAuth(address, signature)
            if (error) throw error
            if (!data) throw 'An error occurred on sign-in.'

            const { session, isNewUser } = data
            this._saveSession(session)

            return { session, isNewUser, error: null }
        } catch (e) {
            return { session: null, isNewUser: false, error: e as ApiError }
        }
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
     * Force refreshes the session including the user data in case it was updated in a different session.
     */
    async refreshSession(): Promise<{
        data: Session | null
        user: User | null
        error: ApiError | null
    }> {
        try {
            if (!this.currentSession?.accessToken) throw new Error('Not logged in.')

            // currentSession and currentUser will be updated to latest on _callRefreshToken
            const { error } = await this._callRefreshToken()
            if (error) throw error

            return { data: this.currentSession, user: this.currentUser, error: null }
        } catch (e) {
            return { data: null, user: null, error: e as ApiError }
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
            if (error) {
                return { session: null, error: error }
            }

            this._saveSession(data!)

            return { session: data, error: null }
        } catch (e) {
            return { error: e as ApiError, session: null }
        }
    }

    /**
     * Inside a browser context, `signOut()` will remove the logged in user from the browser session
     * and log them out - removing all items from localstorage.
     *
     * For server-side management, you can disable sessions by passing a JWT through to `auth.api.signOut(JWT: string)`
     */
    async signOut(): Promise<{ error: ApiError | null }> {
        this._removeSession()
        const accessToken = this.currentSession?.accessToken

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
    private _recoverSession() {
        try {
            const json = isBrowser() && this.localStorage?.getItem(STORAGE_KEY)
            if (!json || typeof json !== 'string') {
                return null
            }

            const data = JSON.parse(json)
            const { currentSession, expiresAt } = data
            const timeNow = Math.round(Date.now() / 1000)

            if (expiresAt >= timeNow && currentSession?.user) {
                this._saveSession(currentSession)
            }
        } catch (error) {
            console.log('error', error)
        }
    }

    /**
     * Recovers the session from LocalStorage and refreshes
     * Note: this method is async to accommodate for AsyncStorage e.g. in React native.
     */
    private async _recoverAndRefresh() {
        try {
            const json = isBrowser() && (await this.localStorage.getItem(STORAGE_KEY))
            if (!json) {
                return null
            }

            const data = JSON.parse(json)
            const { currentSession, expiresAt } = data
            const timeNow = Math.round(Date.now() / 1000)

            if (expiresAt < timeNow) {
                if (this.autoRefreshToken && currentSession.refreshToken) {
                    const { error } = await this._callRefreshToken(currentSession.refreshToken)
                    if (error) {
                        console.log(error.message)
                        await this._removeSession()
                    }
                } else {
                    this._removeSession()
                }
            } else if (!currentSession || !currentSession.user) {
                console.log('Current session is missing data.')
                this._removeSession()
            } else {
                // should be handled on _recoverSession method already
                // But we still need the code here to accommodate for AsyncStorage e.g. in React native
                this._saveSession(currentSession)
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

        // Do we need any extra check before persist session
        // accessToken or user ?
        if (this.persistSession && session.expiresAt) {
            this._persistSession(this.currentSession)
        }
    }

    private _persistSession(currentSession: Session) {
        const data = { currentSession, expiresAt: currentSession.expiresAt }
        isBrowser() && this.localStorage.setItem(STORAGE_KEY, JSON.stringify(data))
    }

    private async _removeSession() {
        this.currentSession = null
        this.currentUser = null
        if (this.refreshTokenTimer) clearTimeout(this.refreshTokenTimer)
        isBrowser() && (await this.localStorage.removeItem(STORAGE_KEY))
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
}
