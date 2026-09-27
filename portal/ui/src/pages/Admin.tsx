import { useEffect, useState } from 'react'
import { useFeatureIsOn } from '@growthbook/growthbook-react'
import {
  ArrowLeft, Brain, CheckCircle, KeyRound, Loader2, Shield, Upload, Users,
} from 'lucide-react'
import {
  AIProviderInput, AIProviderView, AIProvidersView,
  createUser, getAIProviders, listUsers, saveAIProvider, setActiveAIProvider,
  testAIProvider, updateUser, UserProfile,
} from '../lib/api'
import ChangePasswordModal from '../components/ChangePasswordModal'

interface Props {
  onBack: () => void
}

type Tab = 'users' | 'ai'

export default function Admin({ onBack }: Props) {
  const [tab, setTab] = useState<Tab>('users')

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-brand-900 shadow-md">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-white font-bold text-sm tracking-tight">AgentMesh</span>
              <div className="w-px h-5 bg-white/20 shrink-0" />
              <Shield size={16} className="text-brand-300" />
              <span className="text-white font-semibold text-sm">Platform Administration</span>
            </div>
          </div>
          <button
            type="button"
            onClick={onBack}
            className="flex items-center gap-1.5 text-sm text-brand-300 hover:text-white transition-colors"
          >
            <ArrowLeft size={14} />
            Back to launcher
          </button>
        </div>
      </header>

      {/* Page content */}
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Platform Settings</h1>
          <p className="text-gray-500 text-sm mt-1">Manage users, app access, and platform-wide AI providers</p>
        </div>

        <div className="flex gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => setTab('users')}
            className={`flex items-center gap-2 px-5 py-2.5 text-sm font-medium rounded-lg transition-colors ${
              tab === 'users' ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-50'
            }`}
          >
            <Users size={15} />
            User Management
          </button>
          <button
            type="button"
            onClick={() => setTab('ai')}
            className={`flex items-center gap-2 px-5 py-2.5 text-sm font-medium rounded-lg transition-colors ${
              tab === 'ai' ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-50'
            }`}
          >
            <Brain size={15} />
            AI Providers
          </button>
        </div>

        {tab === 'users' ? <UsersTab /> : <AIProvidersTab />}
      </div>
    </div>
  )
}

// ── Users Tab ─────────────────────────────────────────────────────────────────

const APP_LABELS: Record<string, string> = { culprit: 'Culprit' }
const ALL_APPS = ['culprit']

const ROLE_COLORS: Record<string, string> = {
  admin:      'bg-purple-100 text-purple-800',
  user:       'bg-blue-100 text-blue-800',
  read_only:  'bg-gray-100 text-gray-700',
  ci_service: 'bg-green-100 text-green-800',
}

/** Mask every email domain for presentation — this UI may be shown at a
 * public demo, and the underlying DB can carry real company email
 * addresses re-used from an earlier internal deployment. No DB change. */
function maskEmail(email: string): string {
  return email.replace(/@.+$/, '@demo.com')
}

function UsersTab() {
  const bulkImportEnabled = useFeatureIsOn('portal.admin.bulk-user-import')
  const [users,       setUsers]       = useState<UserProfile[]>([])
  const [loading,     setLoading]     = useState(true)
  const [editingId,   setEditingId]   = useState<string | null>(null)
  const [form, setForm] = useState({ email: '', full_name: '', password: '', role: 'user', app_access: [] as string[] })
  const [creating,    setCreating]    = useState(false)
  const [created,     setCreated]     = useState(false)
  const [createError, setCreateError] = useState('')
  const [resetPwdUser, setResetPwdUser] = useState<UserProfile | null>(null)

  useEffect(() => {
    listUsers().then(setUsers).catch(() => {}).finally(() => setLoading(false))
  }, [])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    setCreateError('')
    setCreating(true)
    try {
      const u = await createUser(form)
      setUsers(prev => [...prev, u])
      setCreated(true)
      setTimeout(() => setCreated(false), 3000)
      setForm({ email: '', full_name: '', password: '', role: 'user', app_access: [] })
    } catch (err: any) {
      setCreateError(err.message ?? 'Failed to create user')
    } finally {
      setCreating(false)
    }
  }

  async function handleToggleActive(user: UserProfile) {
    try {
      const updated = await updateUser(user.id, { is_active: !user.is_active })
      setUsers(prev => prev.map(u => u.id === updated.id ? updated : u))
    } catch { /* ignore */ }
  }

  async function handleRoleChange(user: UserProfile, role: string) {
    try {
      const updated = await updateUser(user.id, { role })
      setUsers(prev => prev.map(u => u.id === updated.id ? updated : u))
    } catch { /* ignore */ }
    setEditingId(null)
  }

  async function handleAppAccessChange(user: UserProfile, app: string, checked: boolean) {
    const newAccess = checked
      ? [...(user.app_access ?? []), app]
      : (user.app_access ?? []).filter(a => a !== app)
    try {
      const updated = await updateUser(user.id, { app_access: newAccess })
      setUsers(prev => prev.map(u => u.id === updated.id ? updated : u))
    } catch { /* ignore */ }
  }

  const toggleAppInForm = (app: string) => {
    setForm(f => ({
      ...f,
      app_access: f.app_access.includes(app)
        ? f.app_access.filter(a => a !== app)
        : [...f.app_access, app],
    }))
  }

  return (
    <div className="space-y-6">
      {/* User list */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100">
          <h3 className="font-semibold text-gray-800">All Users ({users.length})</h3>
        </div>
        {loading ? (
          <div className="p-6 text-center text-gray-400">Loading…</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-xs text-gray-500 uppercase tracking-wide">
                <tr>
                  <th className="px-5 py-3 text-left">Name</th>
                  <th className="px-5 py-3 text-left">Email</th>
                  <th className="px-5 py-3 text-left">Role</th>
                  <th className="px-5 py-3 text-left">App Access</th>
                  <th className="px-5 py-3 text-left">Status</th>
                  <th className="px-5 py-3 text-left">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {users.map(u => (
                  <tr key={u.id} className="hover:bg-gray-50/50">
                    <td className="px-5 py-3 font-medium text-gray-800">{u.full_name}</td>
                    <td className="px-5 py-3 text-gray-600">{maskEmail(u.email)}</td>
                    <td className="px-5 py-3">
                      {editingId === u.id ? (
                        <select
                          autoFocus
                          defaultValue={u.role}
                          onBlur={() => setEditingId(null)}
                          onChange={e => handleRoleChange(u, e.target.value)}
                          className="border border-gray-300 rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-brand-500"
                        >
                          <option value="user">User</option>
                          <option value="admin">Admin</option>
                          <option value="read_only">Read only</option>
                          <option value="ci_service">CI service</option>
                        </select>
                      ) : (
                        <button
                          type="button"
                          onClick={() => setEditingId(u.id)}
                          title="Click to change role"
                          className={`text-xs px-2 py-0.5 rounded font-medium ${ROLE_COLORS[u.role] ?? ROLE_COLORS.user} hover:ring-1 hover:ring-offset-1 hover:ring-gray-400`}
                        >
                          {u.role.replace('_', ' ')}
                        </button>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex gap-1.5">
                        {ALL_APPS.map(app => (
                          <label key={app} className="flex items-center gap-1 text-xs text-gray-600 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={(u.app_access ?? []).includes(app)}
                              onChange={e => handleAppAccessChange(u, app, e.target.checked)}
                              className="rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                            />
                            {APP_LABELS[app]}
                          </label>
                        ))}
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <button
                        type="button"
                        onClick={() => handleToggleActive(u)}
                        className={`text-xs font-medium px-2 py-0.5 rounded ${
                          u.is_active
                            ? 'text-emerald-700 bg-emerald-50 hover:bg-emerald-100'
                            : 'text-red-600 bg-red-50 hover:bg-red-100'
                        }`}
                      >
                        {u.is_active ? 'Active' : 'Disabled'}
                      </button>
                    </td>
                    <td className="px-5 py-3">
                      <button
                        type="button"
                        onClick={() => setResetPwdUser(u)}
                        className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-brand-600
                                   transition-colors rounded px-2 py-1 hover:bg-brand-50"
                        title="Reset password"
                      >
                        <KeyRound size={13} />
                        Reset password
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Bulk import — shown only when feature flag is ON */}
      {bulkImportEnabled && (
        <div className="bg-white rounded-xl border border-amber-200 shadow-sm p-6 space-y-3 max-w-xl">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-gray-800 flex items-center gap-2">
              <Upload size={15} className="text-amber-600" />
              Bulk Import Users
            </h3>
            <span className="text-[10px] bg-amber-100 text-amber-700 px-2 py-0.5 rounded-full font-semibold uppercase tracking-wide">
              Coming Soon
            </span>
          </div>
          <p className="text-sm text-gray-500">
            Upload a CSV file to create multiple users at once. Each row should contain:
            <code className="mx-1 text-xs bg-gray-100 px-1.5 py-0.5 rounded">full_name, email, role, app_access</code>
          </p>
          <div className="border-2 border-dashed border-amber-200 rounded-lg p-6 text-center text-gray-400 text-sm bg-amber-50/50">
            <Upload size={20} className="mx-auto mb-2 text-amber-300" />
            CSV upload will be available in a future release
          </div>
        </div>
      )}

      {/* Create user */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-6 space-y-4 max-w-xl">
        <h3 className="font-semibold text-gray-800">Add New User</h3>
        <form onSubmit={handleCreate} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Full name</label>
              <input
                required value={form.full_name}
                onChange={e => setForm({ ...form, full_name: e.target.value })}
                placeholder="Jane Smith"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Email</label>
              <input
                required type="email" value={form.email}
                onChange={e => setForm({ ...form, email: e.target.value })}
                placeholder="jane@company.com"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                Password <span className="text-gray-400 font-normal">(min 8 chars)</span>
              </label>
              <input
                required type="password" minLength={8} value={form.password}
                onChange={e => setForm({ ...form, password: e.target.value })}
                placeholder="Min 8 characters"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Role</label>
              <select
                value={form.role}
                onChange={e => setForm({ ...form, role: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
                <option value="read_only">Read only</option>
                <option value="ci_service">CI service</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-2">App Access</label>
            <div className="flex gap-4">
              {ALL_APPS.map(app => (
                <label key={app} className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.app_access.includes(app)}
                    onChange={() => toggleAppInForm(app)}
                    className="rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                  />
                  {APP_LABELS[app]}
                </label>
              ))}
            </div>
          </div>
          {createError && (
            <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{createError}</p>
          )}
          <div className="flex items-center gap-3">
            <button
              type="submit" disabled={creating}
              className="flex items-center gap-2 bg-brand-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-60 hover:bg-brand-700"
            >
              {creating && <Loader2 size={14} className="animate-spin" />}
              Create User
            </button>
            {created && (
              <span className="flex items-center gap-1 text-emerald-600 text-sm">
                <CheckCircle size={14} /> Created
              </span>
            )}
          </div>
        </form>
      </div>

      {/* Admin password reset */}
      {resetPwdUser && (
        <ChangePasswordModal
          mode="admin"
          targetUserId={resetPwdUser.id}
          targetUserName={resetPwdUser.full_name}
          onClose={() => setResetPwdUser(null)}
        />
      )}
    </div>
  )
}

// ── AI Providers Tab ────────────────────────────────────────────────────────
// Platform-wide, admin-only (portal/api/routers/ai_providers.py) - the model
// Culprit's deep RCA agent calls today, and any future app tomorrow. There is
// no default provider: until an admin picks one here, every consuming app
// keeps doing whatever it did before this screen existed (Culprit: its own
// ANTHROPIC_API_KEY env var).

function AIProvidersTab() {
  const [data, setData] = useState<AIProvidersView | null>(null)
  const [loading, setLoading] = useState(true)
  const [forms, setForms] = useState<Record<string, AIProviderInput>>({})
  const [results, setResults] = useState<Record<string, { text: string; ok: boolean | null }>>({})

  function load() {
    getAIProviders().then(v => {
      setData(v)
      setForms(prev => {
        const next = { ...prev }
        for (const [id, view] of Object.entries(v.providers)) {
          if (!next[id]) {
            next[id] = { base_url: view.base_url, model: view.model, api_version: view.api_version, deployment: view.deployment }
          }
        }
        return next
      })
    }).catch(() => {}).finally(() => setLoading(false))
  }

  useEffect(load, [])

  function updateForm(provider: string, patch: Partial<AIProviderInput>) {
    setForms(prev => ({ ...prev, [provider]: { ...prev[provider], ...patch } }))
  }

  async function handleSave(provider: string) {
    try {
      await saveAIProvider(provider, forms[provider] ?? {})
      // Clears the just-saved key from the form, same as Culprit's own
      // Azure/Datadog settings page does - it already round-tripped once,
      // and leaving it populated invites accidentally re-sending it (or
      // an unrelated field edit) as if it were a fresh value.
      setForms(prev => ({ ...prev, [provider]: { ...prev[provider], api_key: '' } }))
      setResults(prev => ({ ...prev, [provider]: { text: 'Saved.', ok: true } }))
      load()
    } catch (err: any) {
      setResults(prev => ({ ...prev, [provider]: { text: err.message ?? 'Save failed', ok: false } }))
    }
  }

  async function handleTest(provider: string) {
    setResults(prev => ({ ...prev, [provider]: { text: 'Testing…', ok: null } }))
    try {
      const res = await testAIProvider(provider, forms[provider] ?? {})
      setResults(prev => ({ ...prev, [provider]: { text: res.message, ok: res.ok } }))
      load()
    } catch (err: any) {
      setResults(prev => ({ ...prev, [provider]: { text: err.message ?? 'Test failed', ok: false } }))
    }
  }

  async function handleSetActive(provider: string) {
    try {
      await setActiveAIProvider(provider)
      load()
    } catch (err: any) {
      setResults(prev => ({ ...prev, [provider]: { text: err.message ?? 'Could not set active', ok: false } }))
    }
  }

  if (loading) return <div className="p-6 text-center text-gray-400">Loading…</div>
  if (!data) return null

  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-4 max-w-2xl">
        <p className="text-sm text-gray-500">
          Which model the deep RCA agent (the step that reasons over evidence the rule engine
          couldn't settle on its own) calls. Configure any provider below, then mark one active —
          only the active one is actually used. Leaving this unconfigured falls back to whatever
          the app's own environment variables say, same as before this screen existed.
        </p>
        {data.active_provider && (
          <button
            type="button"
            onClick={() => handleSetActive('')}
            className="shrink-0 text-xs text-gray-400 hover:text-red-600 underline whitespace-nowrap"
          >
            Clear active provider
          </button>
        )}
      </div>
      {Object.values(data.providers).map(view => (
        <AIProviderCard
          key={view.provider}
          view={view}
          active={view.provider === data.active_provider}
          form={forms[view.provider] ?? {}}
          result={results[view.provider]}
          onChange={patch => updateForm(view.provider, patch)}
          onSave={() => handleSave(view.provider)}
          onTest={() => handleTest(view.provider)}
          onSetActive={() => handleSetActive(view.provider)}
        />
      ))}
    </div>
  )
}

function AIProviderCard({
  view, active, form, result, onChange, onSave, onTest, onSetActive,
}: {
  view: AIProviderView
  active: boolean
  form: AIProviderInput
  result?: { text: string; ok: boolean | null }
  onChange: (patch: Partial<AIProviderInput>) => void
  onSave: () => void
  onTest: () => void
  onSetActive: () => void
}) {
  return (
    <div className={`bg-white rounded-xl border p-5 ${active ? 'border-brand-400 ring-1 ring-brand-200' : 'border-gray-100'}`}>
      <div className="flex items-center justify-between gap-3 mb-3">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="radio"
            name="ai-active-provider"
            checked={active}
            onChange={onSetActive}
            className="accent-brand-600"
          />
          <span className="font-semibold text-gray-800 text-sm">
            {view.label}{active ? ' (active)' : ''}
          </span>
        </label>
        <StatusBadge view={view} />
      </div>

      <div className="grid grid-cols-2 gap-4 mb-3">
        <ModelField view={view} form={form} onChange={onChange} />
        {view.provider !== 'anthropic' && (
          <Field label="Endpoint">
            <input
              value={form.base_url ?? ''}
              onChange={e => onChange({ base_url: e.target.value })}
              placeholder={view.provider === 'azure_openai' ? 'https://<resource>.openai.azure.com' : ''}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
            />
          </Field>
        )}
        {view.requires_api_key && (
          <Field label="API key">
            <input
              type="password"
              value={form.api_key ?? ''}
              onChange={e => onChange({ api_key: e.target.value })}
              placeholder={view.api_key_configured ? 'leave blank to keep saved key' : 'API key'}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
            />
          </Field>
        )}
        {view.is_azure && (
          <>
            <Field label="API version">
              <input
                value={form.api_version ?? ''}
                onChange={e => onChange({ api_version: e.target.value })}
                placeholder="2024-08-01-preview"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </Field>
            <Field label="Deployment name">
              <input
                value={form.deployment ?? ''}
                onChange={e => onChange({ deployment: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </Field>
          </>
        )}
      </div>

      <div className="flex items-center gap-3">
        <button
          type="button" onClick={onSave}
          className="bg-brand-600 hover:bg-brand-700 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition-colors"
        >
          Save
        </button>
        <button
          type="button" onClick={onTest}
          className="bg-gray-100 hover:bg-gray-200 text-gray-700 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors"
        >
          Test connection
        </button>
        {result && (
          <span className={`text-xs ${result.ok === true ? 'text-emerald-600' : result.ok === false ? 'text-red-600' : 'text-gray-500'}`}>
            {result.text}
          </span>
        )}
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-600 mb-1.5">{label}</label>
      {children}
    </div>
  )
}

const CUSTOM_MODEL = '__custom__'

function ModelField({
  view, form, onChange,
}: {
  view: AIProviderView
  form: AIProviderInput
  onChange: (patch: Partial<AIProviderInput>) => void
}) {
  const current = form.model ?? ''

  // No curated list for this provider (LM Studio: whatever's loaded
  // locally) - always a free-text field, same as before.
  if (view.model_options.length === 0) {
    return (
      <Field label="Model">
        <input
          value={current}
          onChange={e => onChange({ model: e.target.value })}
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-brand-500 focus:outline-none"
        />
      </Field>
    )
  }

  const isKnown = view.model_options.includes(current)

  return (
    <Field label="Model">
      <select
        value={isKnown ? current : CUSTOM_MODEL}
        onChange={e => onChange({ model: e.target.value === CUSTOM_MODEL ? '' : e.target.value })}
        className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm bg-white focus:ring-2 focus:ring-brand-500 focus:outline-none"
      >
        {view.model_options.map(m => <option key={m} value={m}>{m}</option>)}
        <option value={CUSTOM_MODEL}>Other (custom)…</option>
      </select>
      {!isKnown && (
        <input
          value={current}
          onChange={e => onChange({ model: e.target.value })}
          placeholder="Custom model id"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm mt-2 focus:ring-2 focus:ring-brand-500 focus:outline-none"
        />
      )}
    </Field>
  )
}

function StatusBadge({ view }: { view: AIProviderView }) {
  if (!view.configured) {
    return <span className="text-xs text-gray-400">Not configured</span>
  }
  const dotColor = view.last_test_ok === true ? 'bg-emerald-500' : view.last_test_ok === false ? 'bg-red-500' : 'bg-gray-300'
  const text = view.last_test_ok === true ? 'test passed' : view.last_test_ok === false ? 'test failed' : 'not tested yet'
  return (
    <span className="flex items-center gap-1.5 text-xs text-gray-400">
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${dotColor}`} />
      {text}
    </span>
  )
}
