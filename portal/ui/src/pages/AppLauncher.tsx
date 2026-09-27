import { useEffect, useRef, useState } from 'react'
import { useFeatureIsOn } from '@growthbook/growthbook-react'
import { fetchApps, fetchMe, AppInfo, UserProfile } from '../lib/api'
import { clearTokens, buildAppUrl } from '../lib/auth'
import { AlertTriangle, ChevronDown, KeyRound, LogOut, ExternalLink, Settings, Sparkles } from 'lucide-react'
import ChangePasswordModal from '../components/ChangePasswordModal'

interface Props {
  onLogout: () => void
}

const APP_COLORS: Record<string, string> = {
  culprit: 'from-rose-600 to-red-900',
}

const APP_ICONS: Record<string, string> = {
  culprit: '⚑',
}

const APP_TYPE: Record<string, string> = {
  culprit: 'RCA Agent',
}

export default function AppLauncher({ onLogout }: Props) {
  const maintenanceBanner  = useFeatureIsOn('portal.launcher.maintenance-banner')
  const readonlyMode       = useFeatureIsOn('shared.maintenance.readonly-mode')
  const betaEarlyAccess    = useFeatureIsOn('shared.beta.early-access')

  const [apps,    setApps]    = useState<AppInfo[]>([])
  const [user,    setUser]    = useState<UserProfile | null>(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)
  const [showChangePwd, setShowChangePwd] = useState(false)
  const [showUserMenu,  setShowUserMenu]  = useState(false)
  const userMenuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    Promise.all([fetchApps(), fetchMe()])
      .then(([appList, profile]) => { setApps(appList); setUser(profile) })
      .catch(err => setError(err instanceof Error ? err.message : 'Failed to load'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!showUserMenu) return
    function onClickOutside(e: MouseEvent) {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setShowUserMenu(false)
      }
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [showUserMenu])

  function handleLogout() {
    clearTokens()
    onLogout()
  }

  function launchApp(app: AppInfo) {
    window.location.href = buildAppUrl(app.url)
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="w-10 h-10 border-4 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-gray-500 text-sm">Loading your workspace…</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <p className="text-red-600 font-medium">{error}</p>
          <button type="button" onClick={handleLogout} className="mt-4 text-sm text-gray-500 underline">
            Sign out
          </button>
        </div>
      </div>
    )
  }

  const firstName = user?.full_name?.split(' ')[0] ?? 'there'

  return (
    <div className="min-h-screen bg-gray-50">

      {/* ── Dark brand header ──────────────────────────────────── */}
      <header className="bg-brand-900 shadow-lg">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">

          {/* Platform name */}
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-brand-600 flex items-center justify-center shrink-0">
              <span className="text-white text-xs font-black leading-none">A</span>
            </div>
            <span className="text-white font-bold text-base tracking-tight">
              AgentMesh
            </span>
            <span className="text-brand-300 text-xs font-medium hidden sm:block">Enterprise Agentic Platform</span>
          </div>

          {/* Right: admin + user + logout */}
          <div className="flex items-center gap-5">
            {user?.role === 'admin' && (
              <a
                href="/admin"
                className="flex items-center gap-1.5 text-sm text-brand-200 hover:text-white transition-colors"
              >
                <Settings size={14} />
                Admin
              </a>
            )}
            <div className="relative" ref={userMenuRef}>
              <button
                type="button"
                onClick={() => setShowUserMenu(v => !v)}
                className="flex items-center gap-2 text-sm text-brand-100 hover:text-white transition-colors rounded-lg px-1.5 py-1 hover:bg-white/10"
              >
                <div className="w-7 h-7 rounded-full bg-brand-700 ring-1 ring-white/20 flex items-center justify-center text-xs font-semibold text-white shrink-0">
                  {user?.full_name?.[0]?.toUpperCase() ?? '?'}
                </div>
                <span className="hidden sm:inline">{user?.full_name}</span>
                <ChevronDown size={14} className={`transition-transform ${showUserMenu ? 'rotate-180' : ''}`} />
              </button>

              {showUserMenu && (
                <div className="absolute right-0 mt-2 w-52 bg-white rounded-xl shadow-lg border border-gray-100 py-1.5 z-10">
                  <button
                    type="button"
                    onClick={() => { setShowUserMenu(false); setShowChangePwd(true) }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
                  >
                    <KeyRound size={14} className="text-gray-400" />
                    Change password
                  </button>
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
                  >
                    <LogOut size={14} className="text-gray-400" />
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* ── Read-only mode banner (shared.maintenance.readonly-mode) ─── */}
      {readonlyMode && (
        <div className="bg-red-600 text-white text-sm text-center py-2 px-4 flex items-center justify-center gap-2">
          <AlertTriangle size={14} className="shrink-0" />
          <span><strong>Read-only mode active.</strong> All write operations are temporarily disabled. Contact your administrator for more information.</span>
        </div>
      )}

      {/* ── Maintenance banner (portal.launcher.maintenance-banner) ─── */}
      {maintenanceBanner && !readonlyMode && (
        <div className="bg-amber-500 text-white text-sm text-center py-2 px-4 flex items-center justify-center gap-2">
          <AlertTriangle size={14} className="shrink-0" />
          <span><strong>Scheduled maintenance:</strong> Some features may be temporarily unavailable. We'll be back shortly.</span>
        </div>
      )}

      {/* ── Hero strip ────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-6xl mx-auto px-6 py-10">
          <p className="text-xs font-bold text-brand-600 uppercase tracking-widest mb-2 flex items-center gap-2">
            AI-powered agents for strategy &amp; operations
            {betaEarlyAccess && (
              <span className="inline-flex items-center gap-1 text-[10px] font-bold bg-violet-100 text-violet-700 px-2 py-0.5 rounded-full uppercase tracking-wide">
                ✦ Early Access
              </span>
            )}
          </p>
          <h1 className="text-3xl font-extrabold text-gray-900 tracking-tight">
            Welcome back, {firstName}
          </h1>
          <p className="text-gray-400 mt-1.5 text-sm">
            {apps.length > 0
              ? `You have access to ${apps.length} agent${apps.length !== 1 ? 's' : ''} — click any card to launch.`
              : 'No agents are assigned to your account yet.'}
          </p>
        </div>
      </div>

      {/* ── App grid ──────────────────────────────────────────────── */}
      <main className="max-w-6xl mx-auto px-6 py-10">
        {apps.length === 0 ? (
          <div className="text-center py-24 text-gray-400">
            <Sparkles size={36} className="mx-auto mb-4 opacity-30" />
            <p className="text-lg font-medium">No apps available.</p>
            <p className="text-sm mt-1">Contact your administrator to request access.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {apps.map(app => (
              <AppCard key={app.id} app={app} onLaunch={() => launchApp(app)} />
            ))}
          </div>
        )}
      </main>

      {/* ── Footer ────────────────────────────────────────────────── */}
      <footer className="border-t border-gray-200 mt-auto">
        <div className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between">
          <p className="text-xs text-gray-400 font-semibold tracking-wide">AgentMesh</p>
          <p className="text-xs text-gray-400">Enterprise Agentic Platform</p>
        </div>
      </footer>

      {/* ── Change Password modal ─────────────────────────────────── */}
      {showChangePwd && (
        <ChangePasswordModal
          mode="self"
          onClose={() => setShowChangePwd(false)}
        />
      )}
    </div>
  )
}

function AppCard({ app, onLaunch }: { app: AppInfo; onLaunch: () => void }) {
  const gradient = APP_COLORS[app.id] ?? 'from-gray-600 to-gray-800'
  const initials  = APP_ICONS[app.id]  ?? app.name.slice(0, 2).toUpperCase()
  const agentType = APP_TYPE[app.id]   ?? 'AI Agent'

  return (
    <button
      type="button"
      onClick={onLaunch}
      className="group text-left bg-white rounded-2xl shadow-sm border border-gray-100 hover:shadow-xl hover:border-brand-200 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden"
    >
      {/* Gradient header */}
      <div className={`h-28 bg-gradient-to-br ${gradient} flex flex-col items-center justify-center gap-1 relative`}>
        <span className="text-white text-4xl font-black tracking-tighter">{initials}</span>
        {/* Agent type badge */}
        <span className="absolute top-3 right-3 text-xs font-semibold px-2 py-0.5 rounded-full bg-white/20 text-white backdrop-blur-sm">
          {agentType}
        </span>
      </div>

      {/* Body */}
      <div className="p-5">
        <div className="flex items-start justify-between mb-2">
          <div>
            <h3 className="font-bold text-gray-900 text-base group-hover:text-brand-700 transition-colors">
              {app.name}
            </h3>
            {app.version && (
              <span className="text-xs text-gray-400">v{app.version}</span>
            )}
          </div>
          <ExternalLink
            size={14}
            className="text-gray-300 group-hover:text-brand-500 transition-colors mt-0.5 shrink-0"
          />
        </div>
        <p className="text-gray-500 text-sm leading-relaxed line-clamp-2">
          {app.description}
        </p>
      </div>

      {/* Launch hint */}
      <div className="px-5 pb-4">
        <span className="text-xs font-semibold text-brand-600 group-hover:text-brand-700 transition-colors">
          Launch →
        </span>
      </div>
    </button>
  )
}
