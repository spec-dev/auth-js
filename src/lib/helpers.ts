export function expiresAt(expiresIn: number) {
    const timeNow = Math.round(Date.now() / 1000)
    return timeNow + expiresIn
}

export function uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = (Math.random() * 16) | 0,
            v = c == 'x' ? r : (r & 0x3) | 0x8
        return v.toString(16)
    })
}

export const isBrowser = () => typeof window !== 'undefined'
