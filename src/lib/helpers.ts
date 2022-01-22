export function expiresAt(expiresIn: number) {
    const timeNow = Math.round(Date.now() / 1000)
    return timeNow + expiresIn
}

export const isBrowser = () => typeof window !== 'undefined'
