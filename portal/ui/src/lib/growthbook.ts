/**
 * GrowthBook SDK helper for Portal UI.
 *
 * Flag naming convention:  {app}.{component}.{feature-name}
 * Examples:
 *   portal.admin.bulk-user-import
 *   portal.launcher.new-app-card-ui
 *   portal.integrations.azure-devops-oauth
 *   shared.ai.model-routing
 *
 * Usage inside any component:
 *   import { useFeatureIsOn, useFeatureValue } from '@growthbook/growthbook-react'
 *
 *   const showBulkImport = useFeatureIsOn('portal.admin.bulk-user-import')
 */
import { GrowthBook } from '@growthbook/growthbook-react'
import { getAccessToken } from './auth'

const API_HOST   = (import.meta as { env?: Record<string, string> }).env?.VITE_GROWTHBOOK_API_HOST ?? ''
const CLIENT_KEY = (import.meta as { env?: Record<string, string> }).env?.VITE_GROWTHBOOK_CLIENT_KEY ?? ''

function buildAttributes(): Record<string, unknown> {
  const token = getAccessToken()
  const base = { app: 'portal' }
  if (!token) return base
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    return {
      ...base,
      id:         payload.sub        ?? '',
      email:      payload.email      ?? '',
      role:       payload.role       ?? 'user',
      app_access: payload.app_access ?? [],
      company:    (payload.email ?? '').split('@')[1] ?? '',
    }
  } catch {
    return base
  }
}

export function createGrowthBook(): GrowthBook {
  const gb = new GrowthBook({
    apiHost:    API_HOST,
    clientKey:  CLIENT_KEY,
    attributes: buildAttributes(),
    enableDevMode: !!((import.meta as { env?: { DEV?: boolean } }).env?.DEV),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    trackingCallback(experiment: any, result: any) {
      if ((import.meta as { env?: { DEV?: boolean } }).env?.DEV) {
        console.debug('[GrowthBook]', experiment.key, '→ variant', result.variationId)
      }
    },
  })
  gb.init({ streaming: false })
  return gb
}
