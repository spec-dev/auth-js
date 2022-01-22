import { Fetch, post } from './lib/fetch'
import { MessageNonce, Session, AuthSuccess } from './lib/types'
import { expiresAt } from './lib/helpers'
import { paths } from './lib/paths'
import type { ApiError } from './lib/types'

export default class SpecAuthApi {
    protected url: string
    protected headers: {
        [key: string]: string
    }
    protected fetch?: Fetch

    constructor({
        url = '',
        headers = {},
        fetch,
    }: {
        url: string
        headers?: {
            [key: string]: string
        }
        fetch?: Fetch
    }) {
        this.url = url
        this.headers = headers
        this.fetch = fetch
    }

    /**
     * Initialize the auth flow by requesting a message for a user to sign.
     * @param address The user's account address.
     */
    async initAuth(
        address: string
    ): Promise<{ data: MessageNonce | null; error: ApiError | null }> {
        try {
            const headers = { ...this.headers }
            const data = await post(this.fetch, this.url + paths.INIT, { address }, { headers })
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
    async verifyAuth(
        address: string,
        signature: string
    ): Promise<{ data: AuthSuccess | null; error: ApiError | null }> {
        try {
            const headers = { ...this.headers }
            const data = await post(
                this.fetch,
                this.url + paths.VERIFY,
                { address, signature },
                { headers }
            )
            if (data.session.expiresIn) {
                data.session.expiresAt = expiresAt(data.session.expiresIn)
            }
            return { data, error: null }
        } catch (e) {
            return { data: null, error: e as ApiError }
        }
    }

    /**
     * Generates a new JWT.
     * @param token A valid refresh token that was returned on login.
     */
    async refreshAccessToken(
        token: string
    ): Promise<{ data: Session | null; error: ApiError | null }> {
        try {
            const data: any = await post(
                this.fetch,
                this.url + paths.REFRESH,
                { token },
                { headers: this.headers }
            )
            const session = { ...data }
            if (session.expiresIn) session.expiresAt = expiresAt(data.expiresIn)
            return { data: session, error: null }
        } catch (e) {
            return { data: null, error: e as ApiError }
        }
    }

    /**
     * Removes a logged-in session.
     * @param jwt A valid, logged-in JWT.
     */
    async signOut(jwt: string): Promise<{ error: ApiError | null }> {
        try {
            await post(
                this.fetch,
                this.url + paths.SIGN_OUT,
                {},
                { headers: this._createRequestHeaders(jwt), noResolveJson: true }
            )
            return { error: null }
        } catch (e) {
            return { error: e as ApiError }
        }
    }

    /**
     * Create a temporary object with all configured headers and
     * adds the Authorization token to be used on request methods
     * @param jwt A valid, logged-in JWT.
     */
    private _createRequestHeaders(jwt: string) {
        const headers = { ...this.headers }
        headers['Authorization'] = `Bearer ${jwt}`
        return headers
    }
}
