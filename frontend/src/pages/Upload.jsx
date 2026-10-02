import React, { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useApi } from '../hooks/useApi.js'
import { Upload, FileText, Zap } from 'lucide-react'

export default function UploadPage({ onAnalysisCreated }) {
  const { upload, post } = useApi()
  const navigate = useNavigate()
  const [dragOver, setDragOver] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [demoPcaps, setDemoPcaps] = React.useState([])
  const [demoLoading, setDemoLoading] = React.useState(false)

  React.useEffect(() => {
    fetch('/api/demo/pcaps').then(r => r.json()).then(setDemoPcaps).catch(() => {})
  }, [])

  const handleFile = useCallback(async (file) => {
    if (!file) return
    setError('')
    setUploading(true)
    setStatus(`Uploading ${file.name}...`)
    try {
      const { analysis_id } = await upload('/api/analysis/upload', file)
      setStatus('Analysis started — redirecting...')
      onAnalysisCreated?.(analysis_id)
      setTimeout(() => navigate('/'), 1000)
    } catch (err) {
      setError(`Upload failed: ${err.message}`)
      setStatus('')
    } finally {
      setUploading(false)
    }
  }, [upload, navigate, onAnalysisCreated])

  const handleDemoPcap = async (pcap) => {
    setError('')
    setUploading(true)
    setStatus(`Analysing demo PCAP: ${pcap.filename}...`)
    try {
      const { analysis_id } = await post('/api/analysis/file', { pcap_path: pcap.path })
      setStatus('Analysis started — redirecting...')
      onAnalysisCreated?.(analysis_id)
      setTimeout(() => navigate('/'), 1000)
    } catch (err) {
      setError(`Failed: ${err.message}`)
      setStatus('')
    } finally {
      setUploading(false)
    }
  }

  const handleRunDemo = async () => {
    setDemoLoading(true)
    setError('')
    try {
      const { demo_analyses } = await post('/api/demo/run', {})
      if (demo_analyses?.length > 0) {
        onAnalysisCreated?.(demo_analyses[0].analysis_id)
        setStatus(`Started ${demo_analyses.length} demo analyses`)
        setTimeout(() => navigate('/'), 1500)
      }
    } catch (err) {
      setError(`Demo failed: ${err.message}`)
    } finally {
      setDemoLoading(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h2 className="page-title">Upload PCAP</h2>
        <p className="page-subtitle">Upload a network capture containing SMTP, IMAP, or POP3 traffic</p>
      </div>

      {/* Upload zone */}
      <div
        className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
        style={{ marginBottom: '1.5rem' }}
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => {
          e.preventDefault()
          setDragOver(false)
          handleFile(e.dataTransfer.files[0])
        }}
        onClick={() => document.getElementById('file-input').click()}
      >
        <div className="upload-icon">{uploading ? '⏳' : '📁'}</div>
        <div style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.5rem' }}>
          {uploading ? status : 'Drop your PCAP file here'}
        </div>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
          Supports .pcap, .pcapng, .cap files
        </div>
        <input
          id="file-input"
          type="file"
          accept=".pcap,.pcapng,.cap"
          style={{ display: 'none' }}
          onChange={e => handleFile(e.target.files[0])}
        />
        {!uploading && (
          <button className="btn btn-primary" style={{ marginTop: '1.25rem' }}>
            <Upload size={15} /> Choose File
          </button>
        )}
      </div>

      {error && (
        <div style={{ color: 'var(--critical)', background: 'rgba(255,107,107,0.08)', border: '1px solid rgba(255,107,107,0.3)', borderRadius: 8, padding: '0.75rem 1rem', marginBottom: '1rem', fontSize: '0.85rem' }}>
          ⚠ {error}
        </div>
      )}

      {/* Demo PCAPs */}
      <div className="card" style={{ marginBottom: '1.25rem' }}>
        <div className="card-header">
          <div className="card-title">Demo PCAPs</div>
          <button className="btn btn-primary" onClick={handleRunDemo} disabled={demoLoading || demoPcaps.length === 0}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}>
            <Zap size={13} /> Run All Demos
          </button>
        </div>

        {demoPcaps.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            No demo PCAPs found. Generate them first:
            <code style={{ display: 'block', marginTop: '0.5rem', padding: '0.5rem', background: 'var(--bg-surface)', borderRadius: 4 }}>
              just gen-pcaps
            </code>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {demoPcaps.map(pcap => (
              <div key={pcap.filename} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '0.6rem 0.75rem', background: 'var(--bg-surface)', borderRadius: 6,
                border: '1px solid var(--border)'
              }}>
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 500 }}>
                    <FileText size={13} style={{ marginRight: '0.4rem', verticalAlign: 'middle' }} />
                    {pcap.filename}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    {(pcap.size_bytes / 1024).toFixed(1)} KB
                  </div>
                </div>
                <button className="btn btn-secondary" onClick={() => handleDemoPcap(pcap)}
                  disabled={uploading} style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}>
                  Analyse
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Technical notes */}
      <div className="card">
        <div className="card-title" style={{ marginBottom: '0.75rem' }}>Technical Notes</div>
        <ul style={{ fontSize: '0.83rem', color: 'var(--text-muted)', lineHeight: 2, listStyle: 'none' }}>
          <li>📊 Analysis uses <strong>tshark</strong> for protocol/TLS dissection</li>
          <li>🔐 TLS handshakes analysed for version, cipher suite, forward secrecy</li>
          <li>📜 X.509 certificates extracted where observable (TLS ≤ 1.2)</li>
          <li>⚠️ <strong>TLS 1.3:</strong> Certificates are encrypted — not observable without session keys (by design)</li>
          <li>🤖 ML anomaly detection via Isolation Forest on session metadata features</li>
          <li>🔍 All findings include traceable evidence (session, packet numbers, observed values)</li>
          <li>📋 JSON, HTML, and PDF reports available after analysis</li>
        </ul>
      </div>
    </div>
  )
}
