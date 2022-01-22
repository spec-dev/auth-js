import { version } from './version'
export const SPEC_AUTH_URL = 'http://localhost:8000/auth/v1'
export const DEFAULT_HEADERS = { 'X-Client-Info': `auth-js/${version}` }
export const EXPIRY_MARGIN = 60 * 1000
export const STORAGE_KEY = 'spec.auth.token'
