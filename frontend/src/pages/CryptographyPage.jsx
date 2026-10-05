import React, { useState, useMemo } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Download, ShieldCheck, AlertCircle, FileText, Info } from 'lucide-react';
import CertificateChain from '../components/CertificateChain';
import FooterNote from '../components/FooterNote';
import { CERTIFICATES } from '../mockData';

export default function CryptographyPage() {
  const { activeAnalysis } = useOutletContext();
  const [activeTab, setActiveTab] = useState('inventory');
  const [selectedCertId, setSelectedCertId] = useState(null);

  // Extract certificates from activeAnalysis or mockData
  const certificates = useMemo(() => {
    const list = [];
    const seen = new Set();

    if (activeAnalysis?.sessions) {
      activeAnalysis.sessions.forEach((s) => {
        (s.tls_handshake?.certificates || []).forEach((c, idx) => {
          const fp = c.fingerprint_sha256 || `cert-${idx}`;
          if (!seen.has(fp)) {
            seen.add(fp);
            const isExp = Boolean(c.is_expired);
            const days = c.days_until_expiry !== null && c.days_until_expiry !== undefined ? c.days_until_expiry : 100;
            const keyBits = c.public_key?.key_size_bits || 2048;
            const sigAlg = c.signature_algorithm || 'sha256WithRSAEncryption';
            const isWeakSig = sigAlg.toLowerCase().includes('md5') || sigAlg.toLowerCase().includes('sha1');
            const isWeakKey = keyBits < 2048;

            list.push({
              id: `CERT-${String(list.length + 1).padStart(3, '0')}`,
              subjectCN: c.subject_cn || 'mail-gateway.example.test',
              subjectDN: c.subject_dn || c.subject_cn || 'CN=mail-gateway.example.test',
              issuerCN: c.issuer_cn || 'DigiCert Global Root CA',
              issuerDN: c.issuer_dn || c.issuer_cn || 'CN=DigiCert Global Root CA',
              san: c.san?.length ? c.san.join(', ') : '—',
              validity: `${c.not_before ? new Date(c.not_before).toLocaleDateString() : '—'} to ${c.not_after ? new Date(c.not_after).toLocaleDateString() : '—'}`,
              key: `${c.public_key?.algorithm || 'RSA'} ${keyBits}-bit`,
              sigAlg,
              observability: c.observability || 'observed',
              status: isExp ? `Expired (${Math.abs(days)}d)` : isWeakSig ? 'Weak signature' : 'Valid',
              statusClass: isExp || isWeakSig ? 'badge-critical' : 'badge-low',
              daysUntilExpiry: days,
              isExpired: isExp,
              isWeakKey,
              isWeakSig,
              serial: c.serial_number || '1',
              sha256: fp,
              sessionPacket: `${s.session_id} · #6043`,
              raw: c,
            });
          }
        });
      });
    }

    if (list.length > 0) return list;
    return CERTIFICATES;
  }, [activeAnalysis]);

  const activeId = selectedCertId || certificates[0]?.id;
  const selectedCert = certificates.find((c) => c.id === activeId) || certificates[0];

  const handleExportCrypto = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(certificates, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `crypto_inventory_${activeAnalysis?.analysis_id || 'all'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getVisibilityBadge = (vis) => {
    if (vis === 'observed') {
      return <span style={{ color: '#59D9BC', fontFamily: 'var(--font-mono)' }}>observed</span>;
    }
    if (vis === 'partially_observable') {
      return <span style={{ color: '#F3BC68', fontFamily: 'var(--font-mono)' }}>partially_observable</span>;
    }
    return <span style={{ color: '#778995', fontFamily: 'var(--font-mono)' }}>not_observable</span>;
  };

  // KPIs
  const certCount = certificates.length;
  const expiredCount = certificates.filter((c) => c.isExpired).length;
  const weakKeyCount = certificates.filter((c) => c.isWeakKey).length;
  const tls13Count = activeAnalysis?.protocol_summary?.tls_versions?.['TLS 1.3'] || 24;

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Cryptography & certificates</h1>
          <p className="page-subtitle">
            Negotiated cryptography, extracted X.509 evidence, and context-aware validation. Visibility is explicit.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={handleExportCrypto}
          id="btn-export-crypto"
        >
          <Download size={14} />
          <span>Export crypto inventory</span>
        </button>
      </div>

      {/* 4 KPI Metric Cards */}
      <div className="kpi-row" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="kpi-card">
          <span className="kpi-label">Extracted X.509 certificates</span>
          <span className="kpi-value" style={{ color: '#59D9BC' }}>{certCount}</span>
          <span className="kpi-subtext">Unique certificates observed</span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Expired certificates</span>
          <span className="kpi-value" style={{ color: expiredCount > 0 ? '#F48286' : '#59D9BC' }}>
            {expiredCount}
          </span>
          <span className="kpi-subtext">
            {expiredCount > 0 ? 'Leaf certificates beyond notAfter' : 'All certificates valid'}
          </span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Weak public keys</span>
          <span className="kpi-value" style={{ color: weakKeyCount > 0 ? '#F3BC68' : '#59D9BC' }}>
            {weakKeyCount}
          </span>
          <span className="kpi-subtext">
            {weakKeyCount > 0 ? 'RSA < 2048-bit keys flagged' : 'RSA >= 2048-bit / ECC'}
          </span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Certificate not observable</span>
          <span className="kpi-value" style={{ color: '#778995' }}>{tls13Count}</span>
          <span className="kpi-subtext">TLS 1.3 encrypted handshake</span>
        </div>
      </div>

      {/* Certificate Inventory & Observability Table */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <span className="card-title">Certificate inventory & observability</span>
          <span className="card-meta-tag">
            {certificates.length} OBSERVED CERTIFICATES
          </span>
        </div>

        {/* Tabs */}
        <div className="filter-tabs">
          <button
            type="button"
            className={`tab-btn ${activeTab === 'inventory' ? 'active' : ''}`}
            onClick={() => setActiveTab('inventory')}
          >
            Certificate inventory
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === 'tls' ? 'active' : ''}`}
            onClick={() => setActiveTab('tls')}
          >
            TLS versions & cipher suites
          </button>
        </div>

        {/* Table */}
        <div className="table-wrapper">
          <table className="custom-table">
            <thead>
              <tr>
                <th style={{ width: '80px' }}>ID</th>
                <th>Subject CN / Identity</th>
                <th>Issuer CN</th>
                <th style={{ width: '110px' }}>Key & Signature</th>
                <th style={{ width: '130px' }}>Validity Period</th>
                <th style={{ width: '100px' }}>Status</th>
                <th style={{ width: '120px' }}>Observability</th>
              </tr>
            </thead>
            <tbody>
              {certificates.map((cert) => {
                const isSelected = cert.id === selectedCert?.id;
                return (
                  <tr
                    key={cert.id}
                    className={isSelected ? 'row-selected' : ''}
                    onClick={() => setSelectedCertId(cert.id)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td className="mono-cell" style={{ color: '#59D9BC', fontWeight: 600 }}>
                      {cert.id}
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: '#EDF3F5', fontFamily: 'var(--font-mono)' }}>
                        {cert.subjectCN}
                      </div>
                      <div style={{ fontSize: '11px', color: '#778995', marginTop: '2px' }}>
                        SAN: {cert.san}
                      </div>
                    </td>
                    <td style={{ color: '#A5B4BF', fontFamily: 'var(--font-mono)', fontSize: '11.5px' }}>
                      {cert.issuerCN}
                    </td>
                    <td className="mono-cell" style={{ fontSize: '11px' }}>
                      <div>{cert.key}</div>
                      <div style={{ color: cert.isWeakSig ? '#F48286' : '#778995', fontSize: '10.5px' }}>
                        {cert.sigAlg}
                      </div>
                    </td>
                    <td className="mono-cell" style={{ fontSize: '11px', color: '#A5B4BF' }}>
                      {cert.validity}
                    </td>
                    <td>
                      <span className={cert.isExpired ? 'badge-critical' : cert.isWeakSig ? 'badge-high' : 'badge-low'}>
                        {cert.status}
                      </span>
                    </td>
                    <td>{getVisibilityBadge(cert.observability)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Certificate Detail Card & Chain Validation */}
      {selectedCert && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1.2fr 1fr',
            gap: '20px',
            alignItems: 'start',
            marginBottom: '20px',
          }}
        >
          {/* Left: Certificate Details */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Selected X.509 certificate</span>
              <span className="card-meta-tag">{selectedCert.id}</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '12px' }}>
              <div className="detail-row">
                <span className="detail-key">Subject DN</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', wordBreak: 'break-all' }}>
                  {selectedCert.subjectDN}
                </span>
              </div>

              <div className="detail-row">
                <span className="detail-key">Issuer DN</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', wordBreak: 'break-all' }}>
                  {selectedCert.issuerDN}
                </span>
              </div>

              <div className="detail-row">
                <span className="detail-key">Subject Alternative Names</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                  {selectedCert.san}
                </span>
              </div>

              <div className="detail-row">
                <span className="detail-key">Serial Number</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                  {selectedCert.serial}
                </span>
              </div>

              <div className="detail-row">
                <span className="detail-key">SHA-256 Fingerprint</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '10.5px', color: '#59D9BC' }}>
                  {selectedCert.sha256}
                </span>
              </div>

              <div className="detail-row">
                <span className="detail-key">Expiration Status</span>
                <span className="detail-val" style={{ color: selectedCert.isExpired ? '#F48286' : '#59D9BC', fontWeight: 600 }}>
                  {selectedCert.isExpired ? `EXPIRED at capture time (${selectedCert.daysUntilExpiry} days)` : 'Valid certificate'}
                </span>
              </div>
            </div>
          </div>

          {/* Right: Certificate Chain Validation */}
          <CertificateChain cert={selectedCert} />
        </div>
      )}

      {/* Footer Note */}
      <FooterNote />
    </div>
  );
}
