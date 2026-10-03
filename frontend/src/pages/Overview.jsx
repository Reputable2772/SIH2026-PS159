import React, { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield,
  Upload,
  FileText,
  BookOpen,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  FlaskConical,
  Search,
  HardDrive
} from 'lucide-react'
import { useApi } from '../hooks/useApi.js'
import DemoScenarios from '../components/DemoScenarios.jsx'
import RecentAnalyses from '../components/RecentAnalyses.jsx'

export default function Overview({ analyses = [], activeAnalysisId = null, onSelectAnalysis, onRefreshAnalyses }) {
  const { upload, post } = useApi()
  const navigate = useNavigate()
  const [dragOver, setDragOver] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [statusMessage, setStatusMessage] = useState('')
  const [errorMessage, setErrorMessage] = useState('')

  // Handle uploaded PCAP
  const handleFileUpload = useCallback(async (file) => {
    if (!file) return
    setErrorMessage('')
    setUploading(true)
    setStatusMessage(`Uploading and dissecting ${file.name}...`)

    try {
      const res = await upload('/api/analysis/upload', file)
      if (res && res.analysis_id) {
        onRefreshAnalyses?.()
        onSelectAnalysis?.(res.analysis_id)
        navigate('/analysis')
      }
    } catch (err) {
      setErrorMessage(`Capture upload failed: ${err.message}`)
      setStatusMessage('')
    } finally {
      setUploading(false)
    }
  }, [upload, onSelectAnalysis, onRefreshAnalyses, navigate])

  // Handle canonical demo scenario click
  const handleScenarioSelect = async (scenario) => {
    setErrorMessage('')
    setUploading(true)
    setStatusMessage(`Analysing evaluation scenario: ${scenario.filename}...`)

    try {
      const res = await post('/api/analysis/file', { pcap_path: `demo_pcaps/${scenario.filename}` })
      if (res && res.analysis_id) {
        onRefreshAnalyses?.()
        onSelectAnalysis?.(res.analysis_id)
        navigate('/analysis')
      }
    } catch (err) {
      setErrorMessage(`Demo scenario failed: ${err.message}`)
      setStatusMessage('')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }} className="page-fade-in">
      {/* Product Hero — Minimal, calm, and direct */}
      <div style={{ marginBottom: '1.75rem' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem', padding: '0.2rem 0.6rem', borderRadius: 20, background: 'var(--accent-dim)', color: 'var(--accent)', fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.75rem', border: '1px solid var(--accent-border)' }}>
          <Shield size={13} />
          Smart India Hackathon 2026 · PS 26159
        </div>

        <h1 className="page-title" style={{ fontSize: '1.85rem', marginBottom: '0.4rem', fontWeight: 700 }}>
          Forensic Network Investigation Workspace
        </h1>

        <p className="page-subtitle" style={{ fontSize: '0.92rem', lineHeight: 1.55, maxWidth: 840 }}>
          SecureMailScope reconstructs email sessions from passive network packet captures, validating STARTTLS negotiations, TLS cipher parameters, X.509 certificates, and detecting active downgrade tampering without inspecting user payloads.
        </p>
      </div>

      {/* Prominent PCAP Drag-and-Drop Area */}
      <div
        className={`dropzone ${dragOver ? 'active' : ''}`}
        style={{ marginBottom: '2rem' }}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragOver(false)
          if (e.dataTransfer.files?.[0]) {
            handleFileUpload(e.dataTransfer.files[0])
          }
        }}
        onClick={() => document.getElementById('sms-file-input').click()}
      >
        <div className="dropzone-icon">
          {uploading ? <div className="spinner" /> : <Upload size={22} />}
        </div>

        <div style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text)', marginBottom: '0.25rem' }}>
          {uploading ? statusMessage : 'Drop a PCAP to investigate'}
        </div>

        <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
          Accepts standard <code>.pcap</code>, <code>.pcapng</code>, and <code>.cap</code> captures containing SMTP, IMAP, or POP3 network flows
        </div>

        <input
          id="sms-file-input"
          type="file"
          accept=".pcap,.pcapng,.cap"
          style={{ display: 'none' }}
          onChange={(e) => {
            if (e.target.files?.[0]) handleFileUpload(e.target.files[0])
          }}
        />

        {!uploading && (
          <button className="btn btn-primary" style={{ padding: '0.5rem 1.25rem', gap: '0.45rem', fontSize: '0.84rem' }}>
            <Upload size={14} /> Choose PCAP File
          </button>
        )}
      </div>

      {errorMessage && (
        <div className="callout callout-critical" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
          <AlertCircle size={16} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Recent Investigations List */}
      <RecentAnalyses
        analyses={analyses}
        onSelectAnalysis={(id) => {
          onSelectAnalysis(id)
          navigate('/analysis')
        }}
        activeAnalysisId={activeAnalysisId}
      />

      {/* Demo Lab — Controlled Multi-Stream Scenario Corpus */}
      <DemoScenarios
        onSelectScenario={handleScenarioSelect}
        loading={uploading}
        activePcap={analyses.find(a => a.analysis_id === activeAnalysisId)?.pcap}
      />

      {/* Privacy & Methodology Guarantee */}
      <div style={{
        background: 'var(--bg-card-subtle)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        padding: '0.9rem 1.25rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
        fontSize: '0.8rem',
        marginTop: '2rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <CheckCircle2 size={16} color="var(--success)" />
          <span style={{ color: 'var(--text-muted)' }}>
            <strong>Zero-Payload Forensic Dissection:</strong> Only protocol verbs, status codes, and TLS handshake records are extracted. Message contents, bodies, and attachments are strictly ignored.
          </span>
        </div>

        <button
          className="btn btn-secondary"
          onClick={() => navigate('/guide')}
          style={{ fontSize: '0.76rem', padding: '0.35rem 0.75rem', gap: '0.35rem' }}
        >
          <BookOpen size={13} /> Forensic Methodology Guide <ArrowRight size={12} />
        </button>
      </div>
    </div>
  )
}
