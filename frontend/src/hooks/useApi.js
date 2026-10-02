import React from 'react'
// API hook with base URL handling
const BASE_URL = ''  // Empty = use proxy or same origin

export function useApi() {
  const get = async (path) => {
    const res = await fetch(BASE_URL + path)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return res.json()
  }

  const post = async (path, body) => {
    const res = await fetch(BASE_URL + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return res.json()
  }

  const upload = async (path, file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(BASE_URL + path, { method: 'POST', body: form })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return res.json()
  }

  return { get, post, upload }
}

export function useAnalysis(analysisId) {
  const { get } = useApi()
  const [data, setData] = React.useState(null)
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState(null)

  React.useEffect(() => {
    if (!analysisId) {
      setData(null)
      setLoading(false)
      return
    }
    setLoading(true)
    setError(null)
    let timeoutId = null
    let cancelled = false

    const poll = async () => {
      try {
        const result = await get(`/api/analysis/${analysisId}`)
        if (cancelled) return
        if (result.status === 'running' || result.status === 'pending') {
          timeoutId = setTimeout(poll, 1500)
        } else {
          setData(result)
          setLoading(false)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message)
          setLoading(false)
        }
      }
    }
    poll()

    return () => {
      cancelled = true
      if (timeoutId) clearTimeout(timeoutId)
    }
  }, [analysisId])

  return { data, loading, error }
}
