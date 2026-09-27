/**
 * ChangePasswordModal
 *
 * Two modes:
 *  - "self"  — authenticated user changes their own password (requires current password)
 *  - "admin" — admin resets another user's password (no current password field)
 */
import { useState, FormEvent } from 'react'
import { Eye, EyeOff, X, KeyRound, ShieldCheck } from 'lucide-react'
import { changePassword, adminResetPassword } from '../lib/api'

// ── Password strength ──────────────────────────────────────────────────────────

function passwordStrength(pwd: string): { score: number; label: string; color: string } {
  if (!pwd) return { score: 0, label: '', color: '' }
  let score = 0
  if (pwd.length >= 8)                    score++
  if (pwd.length >= 12)                   score++
  if (/[A-Z]/.test(pwd))                  score++
  if (/[0-9]/.test(pwd))                  score++
  if (/[^A-Za-z0-9]/.test(pwd))          score++

  if (score <= 1) return { score, label: 'Weak',   color: 'bg-red-500' }
  if (score === 2) return { score, label: 'Fair',   color: 'bg-orange-400' }
  if (score === 3) return { score, label: 'Good',   color: 'bg-yellow-400' }
  if (score === 4) return { score, label: 'Strong', color: 'bg-green-500' }
  return             { score, label: 'Very strong', color: 'bg-green-600' }
}

// ── Props ──────────────────────────────────────────────────────────────────────

interface SelfProps {
  mode: 'self'
  onClose: () => void
  onSuccess?: () => void
}

interface AdminProps {
  mode: 'admin'
  targetUserId: string
  targetUserName: string
  onClose: () => void
  onSuccess?: () => void
}

type Props = SelfProps | AdminProps

// ── Component ─────────────────────────────────────────────────────────────────

export default function ChangePasswordModal(props: Props) {
  const { mode, onClose, onSuccess } = props

  const [currentPwd,  setCurrentPwd]  = useState('')
  const [newPwd,      setNewPwd]      = useState('')
  const [confirmPwd,  setConfirmPwd]  = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew,     setShowNew]     = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [submitting,  setSubmitting]  = useState(false)
  const [error,       setError]       = useState<string | null>(null)
  const [success,     setSuccess]     = useState(false)

  const strength      = passwordStrength(newPwd)
  const passwordsMatch = newPwd === confirmPwd
  const canSubmit =
    !submitting &&
    (mode === 'admin' || currentPwd.trim().length > 0) &&
    newPwd.length >= 8 &&
    passwordsMatch &&
    confirmPwd.length > 0

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!canSubmit) return
    setSubmitting(true)
    setError(null)
    try {
      if (mode === 'self') {
        await changePassword(currentPwd, newPwd)
      } else {
        await adminResetPassword((props as AdminProps).targetUserId, newPwd)
      }
      setSuccess(true)
      setTimeout(() => { onSuccess?.(); onClose() }, 1500)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
    } finally {
      setSubmitting(false)
    }
  }

  const title    = mode === 'self' ? 'Change password' : `Reset password`
  const subtitle = mode === 'admin'
    ? `Set a new password for ${(props as AdminProps).targetUserName}`
    : 'Choose a strong password for your account'

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm px-4"
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      {/* Card */}
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-6 pb-4 border-b border-gray-100">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-brand-100 flex items-center justify-center shrink-0">
              <KeyRound size={18} className="text-brand-600" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-gray-900">{title}</h2>
              <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors rounded-lg p-1"
          >
            <X size={18} />
          </button>
        </div>

        {/* Success state */}
        {success ? (
          <div className="px-6 py-10 flex flex-col items-center gap-3 text-center">
            <div className="w-14 h-14 rounded-full bg-green-100 flex items-center justify-center">
              <ShieldCheck size={28} className="text-green-600" />
            </div>
            <p className="font-semibold text-gray-900">Password updated!</p>
            <p className="text-sm text-gray-500">
              {mode === 'self' ? 'Your password has been changed.' : 'The password has been reset.'}
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">

            {/* Current password (self mode only) */}
            {mode === 'self' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1.5">
                  Current password
                </label>
                <div className="relative">
                  <input
                    type={showCurrent ? 'text' : 'password'}
                    value={currentPwd}
                    onChange={e => setCurrentPwd(e.target.value)}
                    autoComplete="current-password"
                    placeholder="Enter your current password"
                    className="w-full px-3 py-2.5 pr-10 border border-gray-300 rounded-lg text-sm
                               focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition"
                    required
                  />
                  <button
                    type="button"
                    tabIndex={-1}
                    onClick={() => setShowCurrent(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showCurrent ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
            )}

            {/* New password */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">
                New password
              </label>
              <div className="relative">
                <input
                  type={showNew ? 'text' : 'password'}
                  value={newPwd}
                  onChange={e => setNewPwd(e.target.value)}
                  autoComplete="new-password"
                  placeholder="At least 8 characters"
                  className="w-full px-3 py-2.5 pr-10 border border-gray-300 rounded-lg text-sm
                             focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition"
                  required
                  minLength={8}
                />
                <button
                  type="button"
                  tabIndex={-1}
                  onClick={() => setShowNew(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showNew ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>

              {/* Strength bar */}
              {newPwd.length > 0 && (
                <div className="mt-2 space-y-1">
                  <div className="flex gap-1">
                    {[1, 2, 3, 4, 5].map(i => (
                      <div
                        key={i}
                        className={`h-1.5 flex-1 rounded-full transition-all duration-300 ${
                          i <= strength.score ? strength.color : 'bg-gray-200'
                        }`}
                      />
                    ))}
                  </div>
                  <p className={`text-xs font-medium ${
                    strength.score <= 1 ? 'text-red-500' :
                    strength.score === 2 ? 'text-orange-500' :
                    strength.score === 3 ? 'text-yellow-600' :
                    'text-green-600'
                  }`}>
                    {strength.label}
                  </p>
                </div>
              )}
            </div>

            {/* Confirm password */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">
                Confirm new password
              </label>
              <div className="relative">
                <input
                  type={showConfirm ? 'text' : 'password'}
                  value={confirmPwd}
                  onChange={e => setConfirmPwd(e.target.value)}
                  autoComplete="new-password"
                  placeholder="Re-enter new password"
                  className={`w-full px-3 py-2.5 pr-10 border rounded-lg text-sm outline-none transition
                    focus:ring-2 focus:ring-brand-500 focus:border-brand-500
                    ${confirmPwd.length > 0 && !passwordsMatch
                      ? 'border-red-400 bg-red-50'
                      : confirmPwd.length > 0 && passwordsMatch
                        ? 'border-green-400 bg-green-50'
                        : 'border-gray-300'
                    }`}
                  required
                />
                <button
                  type="button"
                  tabIndex={-1}
                  onClick={() => setShowConfirm(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {confirmPwd.length > 0 && !passwordsMatch && (
                <p className="mt-1 text-xs text-red-500">Passwords do not match</p>
              )}
            </div>

            {/* Error */}
            {error && (
              <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
                {error}
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-3 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 py-2.5 px-4 border border-gray-300 rounded-lg text-sm font-medium
                           text-gray-700 hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!canSubmit}
                className="flex-1 py-2.5 px-4 bg-brand-600 hover:bg-brand-700 disabled:opacity-50
                           disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium
                           transition-colors flex items-center justify-center gap-2"
              >
                {submitting ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Saving…
                  </>
                ) : (
                  mode === 'self' ? 'Update password' : 'Reset password'
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
