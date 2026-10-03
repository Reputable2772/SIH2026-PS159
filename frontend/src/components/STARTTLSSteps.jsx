import React from 'react'
import { CheckCircle2, AlertOctagon, AlertTriangle, ArrowRight, ShieldCheck, Lock, Unlock } from 'lucide-react'

export default function STARTTLSSteps({ session }) {
  if (!session) return null

  const st = session.starttls_state || 'no_tls'
  const isImplicit = st === 'direct_tls' || [465, 993, 995].includes(session.dst_port)
  const isFailure = st === 'suspicious_fallback' || st === 'failed' || session.cleartext_auth_detected

  const steps = []

  // Step 1: TCP Handshake
  steps.push({
    title: 'CONNECTED',
    sub: `TCP established (${session.src_port} → ${session.dst_port})`,
    status: 'success',
    pkt: null,
  })

  if (isImplicit) {
    // Implicit TLS path (Port 465, 993, 995)
    steps.push({
      title: 'DIRECT TLS',
      sub: 'Implicit TLS required on connect',
      status: 'success',
      pkt: null,
    })
    steps.push({
      title: 'TLS HANDSHAKE',
      sub: session.tls_handshake?.tls_version || 'TLS Negotiated',
      status: 'success',
      pkt: session.tls_handshake?.client_hello_pkt || session.tls_start_pkt,
    })
    steps.push({
      title: 'ENCRYPTED TRANSPORT',
      sub: 'Session protected end-to-end',
      status: 'success',
      pkt: null,
    })
  } else if (st === 'no_tls') {
    // Pure plaintext path
    steps.push({
      title: 'EHLO / GREETING',
      sub: 'Cleartext banner exchange',
      status: 'neutral',
      pkt: null,
    })
    steps.push({
      title: 'NO STARTTLS OFFERED',
      sub: 'Server or client omitted STARTTLS',
      status: 'warning',
      pkt: null,
    })
    if (session.cleartext_auth_detected) {
      steps.push({
        title: 'CLEARTEXT AUTH',
        sub: 'Plaintext credentials exposed',
        status: 'danger',
        pkt: null,
      })
    }
    steps.push({
      title: 'UNENCRYPTED SESSION',
      sub: 'Zero cryptographic protection',
      status: 'danger',
      pkt: null,
    })
  } else {
    // Explicit STARTTLS negotiation path
    steps.push({
      title: 'EHLO / GREETING',
      sub: 'Initial banner & capabilities',
      status: 'neutral',
      pkt: null,
    })

    // STARTTLS Advertised
    if (session.starttls_advertised_pkt || ['advertised', 'requested', 'negotiated', 'suspicious_fallback', 'failed'].includes(st)) {
      steps.push({
        title: 'STARTTLS ADVERTISED',
        sub: session.starttls_advertised_pkt ? `Server advertised STARTTLS` : 'Server offered 250-STARTTLS',
        status: 'success',
        pkt: session.starttls_advertised_pkt,
      })
    }

    // STARTTLS Requested
    if (session.starttls_requested_pkt || ['requested', 'negotiated', 'failed', 'suspicious_fallback'].includes(st)) {
      steps.push({
        title: 'STARTTLS REQUESTED',
        sub: session.starttls_requested_pkt ? `Client requested upgrade` : 'Client sent STARTTLS',
        status: 'success',
        pkt: session.starttls_requested_pkt,
      })
    }

    // Outcome branching
    if (st === 'negotiated') {
      steps.push({
        title: 'TLS HANDSHAKE',
        sub: `${session.tls_handshake?.tls_version || 'TLS'} Negotiated`,
        status: 'success',
        pkt: session.tls_handshake?.client_hello_pkt || session.tls_start_pkt,
      })
      steps.push({
        title: 'ENCRYPTED TRANSPORT',
        sub: 'Cryptographic channel active',
        status: 'success',
        pkt: null,
      })
    } else if (st === 'suspicious_fallback') {
      steps.push({
        title: '454 REJECTED / STRIPPED',
        sub: 'Handshake failed or 454 rejected',
        status: 'danger',
        pkt: null,
      })
      if (session.cleartext_auth_detected) {
        steps.push({
          title: 'CLEARTEXT AUTH',
          sub: 'Credentials transmitted in cleartext',
          status: 'danger',
          pkt: null,
        })
      }
      steps.push({
        title: 'INSECURE FALLBACK',
        sub: 'Downgrade to plaintext detected',
        status: 'danger',
        pkt: null,
      })
    } else if (st === 'advertised') {
      steps.push({
        title: 'STARTTLS IGNORED',
        sub: 'Client did not initiate STARTTLS',
        status: 'warning',
        pkt: null,
      })
      if (session.cleartext_auth_detected) {
        steps.push({
          title: 'CLEARTEXT AUTH',
          sub: 'Credentials sent unencrypted',
          status: 'danger',
          pkt: null,
        })
      }
    } else if (st === 'failed') {
      steps.push({
        title: 'STARTTLS FAILED',
        sub: 'Server returned error code',
        status: 'danger',
        pkt: null,
      })
    }
  }

  return (
    <div className="card" style={{ padding: '0.85rem 1.15rem', marginBottom: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.65rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-dim)' }}>
            Protocol State Progression
          </div>
        </div>

        <span
          style={{
            fontSize: '0.7rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            padding: '0.15rem 0.5rem',
            borderRadius: 'var(--radius-sm)',
            background: isFailure ? 'var(--critical-bg)' : isImplicit || st === 'negotiated' ? 'var(--low-bg)' : 'var(--bg-card-subtle)',
            color: isFailure ? 'var(--critical)' : isImplicit || st === 'negotiated' ? 'var(--low)' : 'var(--text-muted)',
            border: `1px solid ${isFailure ? 'var(--critical-border)' : isImplicit || st === 'negotiated' ? 'var(--low-border)' : 'var(--border)'}`,
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem'
          }}
        >
          {isFailure ? <Unlock size={12} /> : <Lock size={12} />}
          {isFailure ? 'SUSPICIOUS FALLBACK / INSECURE' : isImplicit || st === 'negotiated' ? 'ENCRYPTED TRANSPORT' : 'CLEARTEXT'}
        </span>
      </div>

      <div className="state-machine-track">
        {steps.map((step, idx) => {
          let nodeClass = 'state-node'
          let textColor = 'var(--text)'
          if (step.status === 'success') {
            nodeClass += ' state-success'
            textColor = 'var(--info)'
          } else if (step.status === 'danger') {
            nodeClass += ' state-fail'
            textColor = 'var(--critical)'
          } else if (step.status === 'warning') {
            nodeClass += ' state-node'
            textColor = 'var(--high)'
          }

          return (
            <React.Fragment key={idx}>
              <div className={nodeClass}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.4rem', marginBottom: '0.2rem' }}>
                    <span style={{ fontSize: '0.72rem', fontWeight: 700, color: textColor, letterSpacing: '0.04em' }}>
                      {step.title}
                    </span>
                    {step.status === 'success' && <CheckCircle2 size={13} color="var(--info)" />}
                    {step.status === 'danger' && <AlertOctagon size={13} color="var(--critical)" />}
                    {step.status === 'warning' && <AlertTriangle size={13} color="var(--high)" />}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', lineHeight: 1.35 }}>
                    {step.sub}
                  </div>
                </div>

                {step.pkt != null && (
                  <div style={{ marginTop: '0.4rem', fontSize: '0.67rem', fontFamily: 'monospace', color: 'var(--accent)' }}>
                    Frame #{step.pkt}
                  </div>
                )}
              </div>

              {idx < steps.length - 1 && (
                <div className="state-arrow">
                  <ArrowRight size={13} />
                </div>
              )}
            </React.Fragment>
          )
        })}
      </div>
    </div>
  )
}
