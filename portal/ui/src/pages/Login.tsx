import { useState, FormEvent } from 'react'
import { login } from '../lib/api'
import { saveTokens } from '../lib/auth'

interface Props {
  onSuccess: () => void
}

export default function Login({ onSuccess }: Props) {
  const [email,    setEmail]    = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState<string | null>(null)
  const [loading,  setLoading]  = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const data = await login(email, password)
      saveTokens(data.access_token, data.refresh_token)
      onSuccess()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-brand-900 via-brand-800 to-brand-700 px-4 py-12">

      {/* Platform wordmark removed for clean presentation */}

      <div className="w-full max-w-md">

        {/* ── Hero block ───────────────────────────────────────────── */}
        <div className="text-center mb-10">
          {/* Product icon */}
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white/10 ring-2 ring-white/20 backdrop-blur-sm mb-6">
            <svg viewBox="0 0 32 32" className="w-9 h-9" aria-hidden="true">
              <text
                x="16" y="23"
                fontSize="20"
                textAnchor="middle"
                fontFamily="system-ui, sans-serif"
                fontWeight="900"
                fill="white"
              >
                A
              </text>
            </svg>
          </div>

          <h1 className="text-4xl font-extrabold text-white tracking-tight leading-tight">
            AgentMesh
          </h1>

          <p className="text-brand-200 mt-3 text-base font-medium">
            Enterprise Agentic Platform — any agent, any domain
          </p>

          {/* Divider dots */}
          <div className="flex items-center justify-center gap-1.5 mt-6">
            <span className="w-1.5 h-1.5 rounded-full bg-brand-400 opacity-60" />
            <span className="w-1.5 h-1.5 rounded-full bg-brand-300 opacity-40" />
            <span className="w-1.5 h-1.5 rounded-full bg-brand-400 opacity-60" />
          </div>
        </div>

        {/* ── Login card ───────────────────────────────────────────── */}
        <div className="bg-white rounded-2xl shadow-2xl shadow-black/30 p-8">
          <h2 className="text-lg font-semibold text-gray-900 mb-6">Sign in to your workspace</h2>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                Email address
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition text-sm"
                placeholder="you@company.com"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition text-sm"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg px-4 py-3">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-brand-600 hover:bg-brand-700 disabled:opacity-60 text-white font-semibold rounded-lg transition text-sm"
            >
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </div>

        <p className="text-center text-brand-300 text-xs mt-6">
          Contact your administrator to request access.
        </p>
      </div>
    </div>
  )
}
