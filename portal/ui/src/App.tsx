import { useState, useEffect } from 'react'
import { GrowthBookProvider } from '@growthbook/growthbook-react'
import Login from './pages/Login'
import AppLauncher from './pages/AppLauncher'
import Admin from './pages/Admin'
import { isAuthenticated, isAdmin, buildAppUrl } from './lib/auth'
import { createGrowthBook } from './lib/growthbook'

// Single GrowthBook instance for the lifetime of the Portal app.
const gb = createGrowthBook()

type View = 'login' | 'launcher'

const path = window.location.pathname
const isAdminPath = path === '/admin' || path.startsWith('/admin/')

export default function App() {
  const [view, setView] = useState<View>(() =>
    isAuthenticated() ? 'launcher' : 'login'
  )

  useEffect(() => {
    function onFocus() {
      if (view === 'launcher' && !isAuthenticated()) setView('login')
    }
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [view])

  // When a sub-app's token expires it redirects here with
  // ?return=<path>. Once authenticated, bounce back with a fresh token.
  useEffect(() => {
    if (view === 'launcher') {
      const params = new URLSearchParams(window.location.search)
      const returnTo = params.get('return')
      if (returnTo) {
        window.location.href = buildAppUrl(returnTo)
      }
    }
  }, [view])

  if (view === 'login') {
    return (
      <GrowthBookProvider growthbook={gb}>
        <Login onSuccess={() => {
          setView('launcher')
        }} />
      </GrowthBookProvider>
    )
  }

  if (isAdminPath && isAdmin()) {
    return (
      <GrowthBookProvider growthbook={gb}>
        <Admin onBack={() => { window.location.href = '/' }} />
      </GrowthBookProvider>
    )
  }

  return (
    <GrowthBookProvider growthbook={gb}>
      <AppLauncher onLogout={() => setView('login')} />
    </GrowthBookProvider>
  )
}
