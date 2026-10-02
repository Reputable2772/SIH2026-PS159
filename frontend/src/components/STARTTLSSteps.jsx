import React from 'react'
import { CheckCircle2, AlertOctagon, ArrowRight } from 'lucide-react'

export default function STARTTLSSteps({ session }) {
  if (!session) return null

  const st = session.starttls_state || 'no_tls'
  const isImplicit = st === 'direct_tls' || [465, 993, 995].includes(session.dst_port)

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
    // Standard explicit STARTTLS negotiation path
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
        sub: session.starttls_advertised_pkt ? `Server offered 250-STARTTLS (pkt #${session.starttls_advertised_pkt})` : 'Server offered 250-STARTTLS',
        status: 'success',
        pkt: session.starttls_advertised_pkt,
      })
    }

    // STARTTLS Requested
    if (session.starttls_requested_pkt || ['requested', 'negotiated', 'failed'].includes(st)) {
      steps.push({
        title: 'STARTTLS REQUESTED',
        sub: session.starttls_requested_pkt ? `Client sent STARTTLS (pkt #${session.starttls_requested_pkt})` : 'Client sent STARTTLS',
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
        title: 'ENCRYPTED APPLICATION DATA',
        sub: 'Cryptographic channel active',
        status: 'success',
        pkt: null,
      })
    } else if (st === 'suspicious_fallback') {
      steps.push({
        title: 'STARTTLS REJECTED / STRIPPED',
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
        title: 'SUSPICIOUS FALLBACK',
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
        sub: 'Server returned 454 / error code',
        status: 'danger',
        pkt: null,
      })
    }
  }

  return (
    <div style={{ padding: '0.5rem 0' }}>
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
                    <span style={{ fontSize: '0.74rem', fontWeight: 700, color: textColor, letterSpacing: '0.04em' }}>
                      {step.title}
                    </span>
                    {step.status === 'success' && <CheckCircle2 size={13} color="var(--info)" />}
                    {step.status === 'danger' && <AlertOctagon size={13} color="var(--critical)" />}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.35 }}>
                    {step.sub}
                  </div>
                </div>

                {step.pkt != null && (
                  <div style={{ marginTop: '0.45rem', fontSize: '0.68rem', fontFamily: 'monospace', color: 'var(--accent)' }}>
                    Frame #{step.pkt}
                  </div>
                )}
              </div>

              {idx < steps.length - 1 && (
                <div className="state-arrow">
                  <ArrowRight size={14} />
                </div>
              )}
            </React.Fragment>
          )
        })}
      </div>
    </div>
  )
}
