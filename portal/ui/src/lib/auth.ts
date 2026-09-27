const ACCESS_TOKEN_KEY  = 'portal_access_token'
const REFRESH_TOKEN_KEY = 'portal_refresh_token'

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY)
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY)
}

export function saveTokens(accessToken: string, refreshToken: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY,  accessToken)
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY)
  localStorage.removeItem(REFRESH_TOKEN_KEY)
}

export function isAuthenticated(): boolean {
  const token = getAccessToken()
  if (!token) return false
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    return payload.exp * 1000 > Date.now()
  } catch {
    return false
  }
}

export function getAppAccessFromToken(): string[] {
  const token = getAccessToken()
  if (!token) return []
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    return payload.app_access ?? []
  } catch {
    return []
  }
}

export function isAdmin(): boolean {
  const token = getAccessToken()
  if (!token) return false
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    return payload.role === 'admin'
  } catch {
    return false
  }
}

/** Build a deep-link URL: app's base URL + ?auth_token=<jwt> so the app can auto-login */
export function buildAppUrl(appUrl: string): string {
  const token = getAccessToken()
  if (!token) return appUrl
  const sep = appUrl.includes('?') ? '&' : '?'
  return `${appUrl}${sep}auth_token=${token}`
}
