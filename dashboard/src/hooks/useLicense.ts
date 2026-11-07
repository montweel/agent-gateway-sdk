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

export function useLicense(): LicenseApi {
  const [license, setLicense] = useState<LicenseStatus | null>(null)

  const refresh = useCallback(async () => {
    try {
      const res = await api.get<LicenseStatus>('/license')
      setLicense(res.data)
    } catch {
      // Keep the last known status; the rest of the dashboard works without it.
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  // PRO and AGENCY (and the Pro trial) unlock the paid features.
  return { license, isPro: license !== null && license.tier !== 'COMMUNITY', refresh, setLicense }
}
