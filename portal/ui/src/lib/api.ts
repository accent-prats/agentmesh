import { getAccessToken, getRefreshToken, saveTokens, clearTokens } from './auth'

const BASE = '/api'

async function request<T>(
  path: string,
  options: RequestInit = {},
  retry = true,
): Promise<T> {
  const token = getAccessToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(`${BASE}${path}`, { ...options, headers })

  if (res.status === 401 && retry) {
    const refreshed = await tryRefresh()
    if (refreshed) return request<T>(path, options, false)
    clearTokens()
    window.location.href = '/login'
    throw new Error('Session expired')
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body?.detail ?? `HTTP ${res.status}`)
  }

  return res.json() as Promise<T>
}

async function tryRefresh(): Promise<boolean> {
  const refreshToken = getRefreshToken()
  if (!refreshToken) return false
  try {
    const res = await fetch(`${BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!res.ok) return false
    const data = await res.json()
    saveTokens(data.access_token, data.refresh_token)
    return true
  } catch {
    return false
  }
}

export interface LoginResponse {
  access_token:  string
  refresh_token: string
  token_type:    string
  app_access:    string[]
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    const detail = err?.detail
    const message = typeof detail === 'string'
      ? detail
      : Array.isArray(detail)
        ? detail.map((d: { msg?: string }) => d.msg ?? String(d)).join('; ')
        : 'Login failed'
    throw new Error(message)
  }
  return res.json()
}

export interface AppInfo {
  id:          string
  name:        string
  description: string
  url:         string
  icon:        string
  color:       string
  version:     string
}

export async function fetchApps(): Promise<AppInfo[]> {
  return request<AppInfo[]>('/apps')
}

export interface UserProfile {
  id:         string
  email:      string
  full_name:  string
  role:       string
  is_active:  boolean
  app_access: string[]
}

export async function fetchMe(): Promise<UserProfile> {
  return request<UserProfile>('/auth/me')
}

// ── Admin: user management ────────────────────────────────────────────────────

export async function listUsers(): Promise<UserProfile[]> {
  return request<UserProfile[]>('/auth/users')
}

export async function createUser(body: {
  email: string
  full_name: string
  password: string
  role: string
  app_access: string[]
}): Promise<UserProfile> {
  return request<UserProfile>('/auth/users', {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export async function updateUser(id: string, body: {
  role?: string
  is_active?: boolean
  app_access?: string[]
}): Promise<UserProfile> {
  return request<UserProfile>(`/auth/users/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  })
}

// ── Passwords ────────────────────────────────────────────────────────────────

/** Any authenticated user: change their own password. */
export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  return request('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  })
}

/** Admin: reset any user's password without knowing the current one. */
export async function adminResetPassword(userId: string, newPassword: string): Promise<void> {
  return request(`/auth/users/${userId}/reset-password`, {
    method: 'POST',
    body: JSON.stringify({ new_password: newPassword }),
  })
}

// ── Admin: AI providers ───────────────────────────────────────────────────────
// Platform-wide - shared by every app that needs an LLM call (Culprit's deep
// RCA agent today), not per-app. Admin-only; see portal/api/routers/ai_providers.py.

export interface AIProviderView {
  provider:            string
  label:               string
  base_url:            string
  model:               string
  model_options:       string[]
  api_version:         string
  deployment:          string
  api_key_configured:  boolean
  requires_api_key:    boolean
  is_azure:            boolean
  configured:          boolean
  last_tested_at:      string | null
  last_test_ok:        boolean | null
  last_test_message:   string
}

export interface AIProvidersView {
  active_provider: string
  providers: Record<string, AIProviderView>
}

export interface AIProviderInput {
  base_url?:    string
  model?:       string
  api_key?:     string
  api_version?: string
  deployment?:  string
}

export async function getAIProviders(): Promise<AIProvidersView> {
  return request<AIProvidersView>('/ai-providers')
}

export async function saveAIProvider(provider: string, body: AIProviderInput): Promise<AIProviderView> {
  return request<AIProviderView>(`/ai-providers/${provider}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  })
}

export async function testAIProvider(provider: string, body: AIProviderInput = {}): Promise<{ ok: boolean; message: string }> {
  return request(`/ai-providers/${provider}/test`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export async function setActiveAIProvider(provider: string): Promise<AIProvidersView> {
  return request<AIProvidersView>('/ai-providers/active', {
    method: 'PUT',
    body: JSON.stringify({ provider }),
  })
}
