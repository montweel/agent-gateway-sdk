import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { LicenseStatus } from '../lib/types'

export interface LicenseApi {
  /** null until the first response arrives (or if the server cannot be reached). */
  license: LicenseStatus | null
  /** True when the free Pro features are available (active trial or valid key). */
  isPro: boolean
  refresh: () => Promise<void>
  /** Replace the status with one a license request already returned. */
  setLicense: (status: LicenseStatus) => void
}

/** GET /license, or null when it cannot be read. Never throws. */
async function fetchLicense(): Promise<LicenseStatus | null> {
  try {
    return (await api.get<LicenseStatus>('/license')).data
  } catch {
    return null
  }
}

export function useLicense(): LicenseApi {
  const [license, setLicense] = useState<LicenseStatus | null>(null)

  const refresh = useCallback(async () => {
    const status = await fetchLicense()
    // Keep the last known status on failure; the rest of the dashboard works without it.
    if (status) setLicense(status)
  }, [])

  useEffect(() => {
    let live = true
    void fetchLicense().then((status) => {
      if (live && status) setLicense(status)
    })
    return () => {
      live = false
    }
  }, [])

  // PRO and AGENCY (and the Pro trial) unlock the paid features.
  return { license, isPro: license !== null && license.tier !== 'COMMUNITY', refresh, setLicense }
}
