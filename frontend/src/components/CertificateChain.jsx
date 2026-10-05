import React from 'react';
import { FileText, ArrowDown, Info, ShieldCheck, AlertCircle } from 'lucide-react';

export default function CertificateChain({ cert }) {
  const isFailed = cert?.isExpired || cert?.status?.toLowerCase().includes('expired') || cert?.isWeakSig;
  const subjectName = cert?.subjectCN || cert?.subject || 'leaf.mail.example.test';
  const issuerName = cert?.issuerCN || cert?.issuer || 'DigiCert Intermediate CA';

  const details = cert?.validationDetails || {
    leafStatus: isFailed ? 'validity failed · expired / weak' : 'valid syntax · observed in stream',
    leafIssuerReference: `issuer DN references ${issuerName}`,
    issuerStatus: 'Issuer certificate not observed in capture stream',
    issuerNote: 'Root / intermediate CA certificates unavailable in passive capture',
    validityAnalysis: isFailed ? 'Failed · expired or weak cryptographic signature' : 'Verified timestamps',
    issuerLinkage: 'Extracted from leaf Authority Information Access or Subject DN',
    signatureVerification: isFailed ? 'Alert: weak hashing algorithm' : 'Verified algorithm',
    trustChain: 'Passive observation · operating system trust store not bound',
    disclaimer: 'An incomplete presented chain is an evidence limitation, not universal proof of an untrusted certificate. No trust verification is asserted without context.',
  };

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Certificate chain validation</span>
        <span className="card-meta-tag">Evidence-based</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {/* Leaf Box */}
        <div
          style={{
            background: isFailed ? '#1C1518' : 'var(--bg-surface)',
            border: `1px solid ${isFailed ? '#F48286' : 'var(--border-default)'}`,
            borderRadius: 'var(--radius-sm)',
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileText size={16} color={isFailed ? '#F48286' : '#59D9BC'} />
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#EDF3F5', fontFamily: 'var(--font-mono)' }}>
              {subjectName}
            </span>
          </div>
          <span
            style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              fontWeight: 600,
              color: isFailed ? '#F48286' : '#59D9BC',
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
            }}
          >
            LEAF · {details.leafStatus}
          </span>
        </div>

        {/* Down Arrow / Issuer Linkage Reference */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            color: '#778995',
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            paddingLeft: '16px',
          }}
        >
          <ArrowDown size={14} color="#778995" />
          <span>{details.leafIssuerReference}</span>
        </div>

        {/* Issuer CA Box (Passive Capture Evidence) */}
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileText size={16} color="#778995" />
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#A5B4BF', fontFamily: 'var(--font-mono)' }}>
              {issuerName}
            </span>
          </div>
          <span
            style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              fontWeight: 600,
              color: '#778995',
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
            }}
          >
            ISSUER · NOT CAPTURED SEPARATELY
          </span>
        </div>

        {/* Details Key-Value List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px', marginTop: '4px' }}>
          <div className="detail-row">
            <span className="detail-key">Validity Analysis</span>
            <span className="detail-val" style={{ color: isFailed ? '#F48286' : '#59D9BC' }}>
              {details.validityAnalysis}
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-key">Signature Algorithm</span>
            <span className="detail-val" style={{ color: cert?.isWeakSig ? '#F48286' : '#EDF3F5' }}>
              {cert?.sigAlg || 'sha256WithRSAEncryption'}
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-key">Public Key Parameters</span>
            <span className="detail-val" style={{ color: cert?.isWeakKey ? '#F3BC68' : '#EDF3F5' }}>
              {cert?.key || 'RSA 2048-bit'}
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-key">Trust Store Status</span>
            <span className="detail-val">{details.trustChain}</span>
          </div>
        </div>

        {/* Disclaimer Note */}
        <div className="disclaimer-box" style={{ marginTop: '4px' }}>
          <Info size={14} />
          <span>{details.disclaimer}</span>
        </div>
      </div>
    </div>
  );
}
