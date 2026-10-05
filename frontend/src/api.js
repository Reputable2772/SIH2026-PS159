// API Client for SecureMailScope backend
const BASE_URL = import.meta.env.VITE_API_URL || '';

async function fetchJSON(path, options = {}) {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

export const api = {
  // Health
  health: () => fetchJSON('/api/health'),

  // PCAP Management
  listPcaps: () => fetchJSON('/api/pcaps'),
  downloadPcap: (filename) => `${BASE_URL}/api/pcaps/${filename}`,

  // Analysis
  uploadAndAnalyse: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch(`${BASE_URL}/api/analysis/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }
    return response.json();
  },

  analyseByName: (filename) =>
    fetchJSON(`/api/pcaps/${encodeURIComponent(filename)}/analyse`, { method: 'POST' }),

  analyseSyncByName: (filename) =>
    fetchJSON(`/api/pcaps/${encodeURIComponent(filename)}/analyse/sync`, { method: 'POST' }),

  getPcapAnalysis: (filename) =>
    fetchJSON(`/api/pcaps/${encodeURIComponent(filename)}/analysis`),

  getAnalysisStatus: (id) => fetchJSON(`/api/analysis/${id}/status`),
  getAnalysis: (id) => fetchJSON(`/api/analysis/${id}`),
  listAnalyses: () => fetchJSON('/api/analyses'),

  getSessions: (id) => fetchJSON(`/api/analysis/${id}/sessions`),
  getSession: (id, sessionId) => fetchJSON(`/api/analysis/${id}/sessions/${sessionId}`),

  getFindings: (id, { severity, category } = {}) => {
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (category) params.set('category', category);
    const qs = params.toString();
    return fetchJSON(`/api/analysis/${id}/findings${qs ? `?${qs}` : ''}`);
  },

  // Reports
  reportHtmlUrl: (id) => `${BASE_URL}/api/analysis/${id}/report/html`,
  reportPdfUrl: (id) => `${BASE_URL}/api/analysis/${id}/report/pdf`,
  reportJsonUrl: (id) => `${BASE_URL}/api/analysis/${id}/report/json`,

  // Demo
  runDemo: () => fetchJSON('/api/demo/run', { method: 'POST' }),
};

// Polling helper
export async function pollUntilDone(analysisId, onProgress, intervalMs = 1500) {
  return new Promise((resolve, reject) => {
    const interval = setInterval(async () => {
      try {
        const status = await api.getAnalysisStatus(analysisId);
        if (onProgress) onProgress(status);
        if (status.status === 'done') {
          clearInterval(interval);
          resolve(await api.getAnalysis(analysisId));
        } else if (status.status === 'error') {
          clearInterval(interval);
          reject(new Error(status.error || 'Analysis failed'));
        }
      } catch (e) {
        clearInterval(interval);
        reject(e);
      }
    }, intervalMs);
  });
}

// Utility: format bytes
export function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

// Utility: format score level
export function getRiskColor(level) {
  const map = {
    CRITICAL: '#f87171',
    HIGH: '#fb923c',
    MEDIUM: '#fbbf24',
    LOW: '#60a5fa',
    MINIMAL: '#34d399',
    minimal: '#34d399',
  };
  return map[level] || '#8892a4';
}

export function getRiskClass(level) {
  const l = (level || '').toLowerCase();
  return `badge-${l === 'minimal' ? 'minimal' : l}`;
}

export function getSeverityColor(sev) {
  const map = {
    critical: '#f87171',
    high: '#fb923c',
    medium: '#fbbf24',
    low: '#34d399',
    info: '#60a5fa',
  };
  return map[(sev || '').toLowerCase()] || '#8892a4';
}

export function getTlsBadgeClass(version) {
  if (!version) return '';
  if (version.includes('1.3')) return 'tls-13';
  if (version.includes('1.2')) return 'tls-12';
  if (version.includes('1.1')) return 'tls-11';
  if (version.includes('1.0')) return 'tls-10';
  return 'tls-ssl';
}

export function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch {
    return ts;
  }
}

export function categoryLabel(cat) {
  const map = {
    deprecated_tls: 'Deprecated TLS',
    weak_cipher: 'Weak Cipher',
    weak_key: 'Weak Key',
    weak_signature: 'Weak Signature',
    expired_certificate: 'Expired Certificate',
    invalid_certificate: 'Invalid Certificate',
    no_forward_secrecy: 'No Forward Secrecy',
    starttls_anomaly: 'STARTTLS Anomaly',
    plaintext_auth: 'Plaintext Auth',
    ml_anomaly: 'ML Anomaly',
    configuration: 'Configuration',
    info: 'Info',
  };
  return map[cat] || cat;
}

export function protocolBadgeClass(proto) {
  const map = { SMTP: 'badge-smtp', IMAP: 'badge-imap', POP3: 'badge-pop3' };
  return map[proto] || 'badge-unknown';
}

export function starttlsLabel(state) {
  const map = {
    no_tls: 'No TLS',
    advertised: 'Advertised',
    requested: 'Requested',
    negotiated: 'Negotiated',
    failed: 'Failed',
    suspicious_fallback: 'Suspicious Fallback',
    direct_tls: 'Direct TLS',
  };
  return map[state] || state;
}

export function starttlsClass(state) {
  const map = {
    no_tls: 'badge-neutral',
    advertised: 'badge-info',
    requested: 'badge-info',
    negotiated: 'badge-low',
    failed: 'badge-critical',
    suspicious_fallback: 'badge-critical',
    direct_tls: 'badge-low',
  };
  return map[state] || 'badge-neutral';
}

export function truncateHash(hash, len = 16) {
  if (!hash) return '—';
  return hash.length > len ? `${hash.slice(0, len)}…` : hash;
}
