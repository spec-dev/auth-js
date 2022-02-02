export interface ApiError {
    message: string
    status: number
}

export interface MessageNonce {
    message: string
}

export interface AuthSuccess {
    session: Session
    user: User
    isNewUser: boolean
}

export interface Session {
    accessToken: string
    /**
     * The number of seconds until the token expires (since it was issued). Returned when a login is confirmed.
     */
    expiresIn?: number
    /**
     * A timestamp of when the token will expire. Returned when a login is confirmed.
     */
    expiresAt?: number
    refreshToken?: string
    tokenType: string
    user: User
}

export interface User {
    id: string
}

export interface PersistedSessions {
    sessions: { [key: string]: Session }
    activeAddress: string
}

export interface Subscription {
    /**
     * The subscriber UUID. This will be set by the client.
     */
    id: string
    /**
     * The function to call every time there is an event. eg: (eventName) => {}
     */
    callback: (event: string, session: Session | null) => void
    /**
     * Call this to remove the listener.
     */
    unsubscribe: () => void
}
