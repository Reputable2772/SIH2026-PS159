import React from 'react';
import { ArrowRight } from 'lucide-react';

export default function HandshakeFlow({ session }) {
  const isComplete = session?.tlsVersion && session.tlsVersion !== 'No TLS' && session.tlsVersion !== 'Unknown';
  const hasFallback = session?.starttlsState === 'suspicious_fallback';

  return (
    <div className="card" style={{ marginTop: '16px' }}>
      <div className="card-header">
        <span className="card-title">TLS handshake reconstruction</span>
        <span className="card-meta-tag">Selected stream + Validation control</span>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '24px',
          alignItems: 'start',
        }}
      >
        {/* Left: Selected stream */}
        <div
          style={{
            background: 'var(--bg-surface)',
            border: `1px solid ${hasFallback ? '#F3BC68' : 'var(--border-default)'}`,
            borderRadius: 'var(--radius-sm)',
            padding: '16px',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#EDF3F5' }}>
              {session?.id || 'Selected stream'} · inspected
            </span>
            <span
              style={{
                fontSize: '9.5px',
                fontWeight: 700,
                color: isComplete ? '#59D9BC' : '#F3BC68',
                background: isComplete ? '#163A34' : '#392F21',
                padding: '2px 8px',
                borderRadius: '3px',
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
              }}
            >
              {isComplete ? 'Negotiated' : hasFallback ? 'Downgrade Fallback' : 'No TLS'}
            </span>
          </div>

          {/* Sequence Steps */}
          {isComplete ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
              <span className="badge-tls-seq">ClientHello</span>
              <ArrowRight size={12} color="#778995" />
              <span className="badge-tls-seq">ServerHello ({session.tlsVersion})</span>
              <ArrowRight size={12} color="#778995" />
              <span className="badge-tls-seq">Certificates</span>
              <ArrowRight size={12} color="#778995" />
              <span className="badge-tls-seq" style={{ background: '#163A34', color: '#59D9BC' }}>Finished</span>
            </div>
          ) : hasFallback ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span
                style={{
                  padding: '3px 8px',
                  background: '#163A34',
                  color: '#59D9BC',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 600,
                }}
              >
                ClientHello
              </span>
              <ArrowRight size={13} color="#778995" />
              <span
                style={{
                  padding: '3px 8px',
                  background: '#3B1C1D',
                  color: '#F48286',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 600,
                }}
              >
                454 / Alert rejection
              </span>
              <ArrowRight size={13} color="#778995" />
              <span
                style={{
                  padding: '3px 8px',
                  background: '#392F21',
                  color: '#F3BC68',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 600,
                }}
              >
                Plaintext continuation
              </span>
            </div>
          ) : (
            <div style={{ color: '#F3BC68', fontSize: '12px' }}>
              No TLS handshake was initiated. All communications were conducted in cleartext.
            </div>
          )}

          <p style={{ fontSize: '11.5px', color: '#A5B4BF', lineHeight: 1.4 }}>
            {isComplete
              ? `Negotiated ${session.tlsVersion} cipher suite ${session.cipherSuite}. Cryptographic forward secrecy status: ${session.forwardSecrecy}.`
              : 'Reconstructed packet records confirm lack of successful key exchange or encryption layer.'}
          </p>

          <div
            style={{
              fontSize: '11.5px',
              fontFamily: 'var(--font-mono)',
              color: isComplete ? '#59D9BC' : '#F3BC68',
              paddingTop: '6px',
              borderTop: '1px solid var(--border-subtle)',
            }}
          >
            {isComplete ? `Cipher: ${session.cipherSuite}` : 'Fallback path: Cleartext authentication transmitted'}
          </div>
        </div>

        {/* Right: Validation Control Flow */}
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
            padding: '16px',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#EDF3F5' }}>
              Reference baseline · control flow
            </span>
            <span
              style={{
                fontSize: '9.5px',
                fontWeight: 700,
                color: '#59D9BC',
                background: '#163A34',
                padding: '2px 8px',
                borderRadius: '3px',
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
              }}
            >
              Complete
            </span>
          </div>

          {/* Sequence Steps */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <span className="badge-tls-seq">ClientHello</span>
            <ArrowRight size={12} color="#778995" />
            <span className="badge-tls-seq">ServerHello (TLS 1.3)</span>
            <ArrowRight size={12} color="#778995" />
            <span className="badge-tls-seq">EncryptedExt</span>
            <ArrowRight size={12} color="#778995" />
            <span className="badge-tls-seq" style={{ background: '#163A34', color: '#59D9BC' }}>Finished</span>
          </div>

          <p style={{ fontSize: '11.5px', color: '#A5B4BF', lineHeight: 1.4 }}>
            Full key exchange observed. ServerHello negotiated TLS_AES_256_GCM_SHA384 with X25519 key share and Forward Secrecy.
          </p>

          <div
            style={{
              fontSize: '11.5px',
              fontFamily: 'var(--font-mono)',
              color: '#59D9BC',
              paddingTop: '6px',
              borderTop: '1px solid var(--border-subtle)',
            }}
          >
            Forward Secrecy confirmed · ECDHE key exchange verified
          </div>
        </div>
      </div>
    </div>
  );
}
