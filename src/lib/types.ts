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
    user: User | null
}

export interface User {
    id: string
}
