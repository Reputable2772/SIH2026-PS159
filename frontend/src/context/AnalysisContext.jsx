import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { api, formatBytes } from '../api';
import {
  DEMO_CAPTURE,
  AVAILABLE_CAPTURES,
  FINDINGS,
  SESSIONS,
  CERTIFICATES,
  TLS_DISTRIBUTION,
  CIPHER_SUITES,
  FORWARD_SECRECY_STATS,
  PROTOCOL_STATS,
} from '../mockData';

const AnalysisContext = createContext(null);

// Fallback mockup analysis in case backend is offline
const FALLBACK_ANALYSIS = {
  analysis_id: DEMO_CAPTURE.id,
  capture: {
    pcap_filename: DEMO_CAPTURE.filename,
    pcap_path: DEMO_CAPTURE.filename,
    sha256_hash: DEMO_CAPTURE.sha256,
    file_size_bytes: DEMO_CAPTURE.size,
    capture_duration_seconds: DEMO_CAPTURE.duration,
    packet_count: DEMO_CAPTURE.packetsCount,
    analyzed_at: DEMO_CAPTURE.analyzedAt,
    tool_version: DEMO_CAPTURE.toolVersion,
  },
  risk_score: {
    score: DEMO_CAPTURE.score,
    level: DEMO_CAPTURE.riskLevel,
    critical_count: FINDINGS.filter((f) => f.severity === 'critical').length,
    high_count: FINDINGS.filter((f) => f.severity === 'high').length,
    medium_count: FINDINGS.filter((f) => f.severity === 'medium').length,
    low_count: FINDINGS.filter((f) => f.severity === 'low').length,
    info_count: FINDINGS.filter((f) => f.severity === 'info').length,
    ml_anomaly_count: FINDINGS.filter((f) => f.origin === 'ML').length,
    rationale: [
      '2 SMTP sessions return to plaintext after advertising STARTTLS.',
      '3 sessions negotiate deprecated TLS 1.0.',
    ],
  },
  protocol_summary: {
    smtp_sessions: 28,
    imap_sessions: 14,
    pop3_sessions: 5,
    unknown_sessions: 1,
    tls_sessions: 40,
    plaintext_sessions: 8,
    starttls_sessions: 26,
    tls_versions: { 'TLS 1.3': 24, 'TLS 1.2': 13, 'TLS 1.0': 3 },
    cipher_suites: {
      'TLS_AES_256_GCM_SHA384': 24,
      'ECDHE-RSA-AES256-GCM-SHA384': 13,
      'ECDHE-RSA-AES128-SHA': 3,
    },
    forward_secrecy_yes: 37,
    forward_secrecy_no: 3,
    forward_secrecy_unknown: 8,
  },
  all_findings: FINDINGS.map((f) => ({
    id: f.id,
    severity: f.severity.toLowerCase(),
    category: f.category.toLowerCase().replace(/ /g, '_'),
    title: f.title,
    description: f.description,
    recommendation: f.recommendation,
    cve_references: f.cveRefs || [],
    is_ml_finding: f.origin === 'ML',
    evidence: {
      pcap_file: DEMO_CAPTURE.filename,
      session_id: f.session,
      packet_numbers: (f.packets || '').replace(/[^0-9,–-]/g, '').split(/[,–-]/).map(Number).filter(Boolean),
      field: f.field || 'traffic_sample',
      observed_value: f.observed || null,
      extra: {},
    },
  })),
  sessions: SESSIONS.map((s) => ({
    session_id: s.id,
    src_ip: s.srcIp,
    src_port: s.srcPort,
    dst_ip: s.dstIp,
    dst_port: s.dstPort,
    protocol: s.protocol,
    starttls_state: s.starttlsState,
    session_risk_score: s.riskScore,
    session_risk_level: s.riskBand,
    packet_count: s.packets,
    bytes_transferred: s.bytes,
    duration_seconds: s.duration,
    tls_handshake: {
      tls_version: s.tlsVersion,
      cipher_suite: s.cipherSuite,
      forward_secrecy: s.forwardSecrecy === 'Supported' ? 'yes' : s.forwardSecrecy === 'Not supported' ? 'no' : 'unknown',
      certificates: CERTIFICATES.filter((c) => c.sessionPacket?.includes(s.id)),
      ja3_hash: s.ja3,
      handshake_complete: s.tlsVersion !== 'No TLS',
    },
    findings: FINDINGS.filter((f) => f.session === s.id),
    is_anomalous: s.riskBand === 'CRITICAL' || s.riskBand === 'HIGH',
    anomaly_score: s.riskBand === 'CRITICAL' ? 0.28 : s.riskBand === 'HIGH' ? 0.18 : -0.15,
  })),
  recommendations: [
    'Disable SSL 3.0 and TLS 1.0/1.1 across all edge mail relays.',
    'Enforce STARTTLS mandatory policy to prevent cleartext downgrade attacks.',
    'Replace expired certificates and upgrade RSA keys to 2048-bit or ECDSA P-256.',
  ],
  limitations: [
    'Passive PCAP analysis only. No active probes conducted.',
    'Encrypted TLS 1.3 payloads cannot be decrypted without ephemeral session keys.',
  ],
  processing_time_seconds: 8.2,
};

export function AnalysisProvider({ children }) {
  const [isBackendLive, setIsBackendLive] = useState(false);
  const [pcaps, setPcaps] = useState(AVAILABLE_CAPTURES);
  const [analyses, setAnalyses] = useState([]);
  const [selectedCapture, setSelectedCapture] = useState(DEMO_CAPTURE);
  const [activeAnalysis, setActiveAnalysis] = useState(FALLBACK_ANALYSIS);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  // Initialize and check backend connection
  const checkBackendAndLoad = useCallback(async () => {
    setIsLoading(true);
    try {
      // 1. Health check
      const health = await api.health();
      setIsBackendLive(health.status === 'ok');

      // 2. Fetch PCAP list
      const pcapList = await api.listPcaps();
      if (Array.isArray(pcapList) && pcapList.length > 0) {
        const enriched = pcapList.map((p, idx) => ({
          id: `CAP-00${idx + 1}`,
          filename: p.filename,
          title: p.title || p.filename,
          description: p.description,
          category: p.category,
          size: formatBytes(p.size_bytes),
          size_bytes: p.size_bytes,
          sha256: p.sha256_hash,
          sha256_hash: p.sha256_hash,
          shortId: p.sha256_hash ? p.sha256_hash.slice(0, 8) : `cap00${idx + 1}`,
          status: 'Available',
          download_url: p.download_url,
          analyse_url: p.analyse_url,
        }));
        setPcaps(enriched);

        // 3. Load analysis for first PCAP by default
        const defaultPcap = enriched[0];
        try {
          const res = await api.getPcapAnalysis(defaultPcap.filename);
          if (res && res.capture) {
            setActiveAnalysis(res);
            setSelectedCapture({
              ...defaultPcap,
              id: res.analysis_id,
              shortId: res.analysis_id.slice(0, 8),
              score: Math.round(res.risk_score?.score ?? 0),
              riskLevel: res.risk_score?.level || 'MINIMAL',
              sessionsCount: res.sessions?.length || 0,
              encryptedCount: res.protocol_summary?.tls_sessions || 0,
              packetsCount: res.capture?.packet_count || 0,
              duration: res.capture?.capture_duration_seconds || 0,
              analyzedAt: res.capture?.analyzed_at || new Date().toISOString(),
            });
          }
        } catch (e) {
          console.warn('Could not load default pcap analysis:', e);
        }
      }

      // 4. Fetch past analyses
      const analysisList = await api.listAnalyses().catch(() => []);
      setAnalyses(analysisList);
    } catch (err) {
      console.warn('Backend unavailable, using offline fallback mode:', err);
      setIsBackendLive(false);
      setPcaps(AVAILABLE_CAPTURES);
      setSelectedCapture(DEMO_CAPTURE);
      setActiveAnalysis(FALLBACK_ANALYSIS);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkBackendAndLoad();
  }, [checkBackendAndLoad]);

  // Select a capture and load its analysis
  const selectCapture = async (pcapOrFilename) => {
    const filename = typeof pcapOrFilename === 'string' ? pcapOrFilename : pcapOrFilename.filename;
    setIsLoading(true);
    setError(null);

    // Look for matching pcap object in state
    const pcapObj = pcaps.find((p) => p.filename === filename) || {
      filename,
      title: filename,
      shortId: filename.slice(0, 8),
      size: '—',
    };

    try {
      if (isBackendLive) {
        const res = await api.getPcapAnalysis(filename);
        if (res && res.capture) {
          setActiveAnalysis(res);
          setSelectedCapture({
            ...pcapObj,
            id: res.analysis_id,
            shortId: res.analysis_id.slice(0, 8),
            score: Math.round(res.risk_score?.score ?? 0),
            riskLevel: res.risk_score?.level || 'MINIMAL',
            sessionsCount: res.sessions?.length || 0,
            encryptedCount: res.protocol_summary?.tls_sessions || 0,
            packetsCount: res.capture?.packet_count || 0,
            duration: res.capture?.capture_duration_seconds || 0,
            analyzedAt: res.capture?.analyzed_at || new Date().toISOString(),
          });
          // Refresh list of cached analyses
          const freshAnalyses = await api.listAnalyses().catch(() => []);
          setAnalyses(freshAnalyses);
          return res;
        }
      }
    } catch (err) {
      console.error(`Failed to load live analysis for ${filename}:`, err);
      setError(`Failed to analyze ${filename}: ${err.message}`);
    } finally {
      setIsLoading(false);
    }

    // Fallback if offline or failed
    setSelectedCapture(pcapObj);
    return null;
  };

  // Load an existing analysis by UUID
  const loadAnalysisById = async (analysisId) => {
    setIsLoading(true);
    try {
      const res = await api.getAnalysis(analysisId);
      if (res && res.capture) {
        setActiveAnalysis(res);
        const matchPcap = pcaps.find((p) => p.filename === res.capture.pcap_filename);
        setSelectedCapture({
          ...(matchPcap || {}),
          id: res.analysis_id,
          shortId: res.analysis_id.slice(0, 8),
          filename: res.capture.pcap_filename,
          title: matchPcap?.title || res.capture.pcap_filename,
          score: Math.round(res.risk_score?.score ?? 0),
          riskLevel: res.risk_score?.level || 'MINIMAL',
          sessionsCount: res.sessions?.length || 0,
          encryptedCount: res.protocol_summary?.tls_sessions || 0,
          packetsCount: res.capture?.packet_count || 0,
          duration: res.capture?.capture_duration_seconds || 0,
          analyzedAt: res.capture?.analyzed_at || new Date().toISOString(),
        });
        return res;
      }
    } catch (err) {
      console.error(`Failed to load analysis ${analysisId}:`, err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  // Refresh analyses and pcaps
  const refreshAnalyses = async () => {
    try {
      const [pcapList, analysisList] = await Promise.all([
        api.listPcaps().catch(() => []),
        api.listAnalyses().catch(() => []),
      ]);
      if (pcapList.length > 0) {
        setPcaps(
          pcapList.map((p, idx) => ({
            id: `CAP-00${idx + 1}`,
            filename: p.filename,
            title: p.title || p.filename,
            description: p.description,
            category: p.category,
            size: formatBytes(p.size_bytes),
            size_bytes: p.size_bytes,
            sha256: p.sha256_hash,
            sha256_hash: p.sha256_hash,
            shortId: p.sha256_hash ? p.sha256_hash.slice(0, 8) : `cap00${idx + 1}`,
            status: 'Available',
            download_url: p.download_url,
            analyse_url: p.analyse_url,
          }))
        );
      }
      setAnalyses(analysisList);
    } catch (err) {
      console.warn('Failed to refresh analyses:', err);
    }
  };

  // Run all demo scenarios
  const runAllScenarios = async () => {
    setIsLoading(true);
    try {
      const demoRes = await api.runDemo();
      // Poll briefly then refresh
      setTimeout(async () => {
        await refreshAnalyses();
        setIsLoading(false);
      }, 3000);
      return demoRes;
    } catch (err) {
      setIsLoading(false);
      throw err;
    }
  };

  return (
    <AnalysisContext.Provider
      value={{
        isBackendLive,
        pcaps,
        analyses,
        selectedCapture,
        activeAnalysis,
        isLoading,
        error,
        selectCapture,
        loadAnalysisById,
        refreshAnalyses,
        runAllScenarios,
      }}
    >
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext);
  if (!ctx) {
    throw new Error('useAnalysis must be used within an AnalysisProvider');
  }
  return ctx;
}
