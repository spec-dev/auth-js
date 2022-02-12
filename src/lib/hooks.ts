import crossFetch from 'cross-fetch'
import { post } from './fetch'
import { SPEC_API_KEY_HEADER } from './constants'
import { ApiError, User } from './types'

export async function performAuthHook(
    user: User,
    webhookUrl: string,
    webhookApiKey?: string | null
): Promise<{ user: User | null; error: ApiError | null }> {
    try {
        const data = await post(
            crossFetch,
            webhookUrl,
            { user },
            { headers: { [SPEC_API_KEY_HEADER]: webhookApiKey || '' } }
        )

        return { user: data?.user, error: null }
    } catch (e) {
        return { user: null, error: e as ApiError }
    }
}
