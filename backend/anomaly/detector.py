"""
SecureMailScope — ML Anomaly Detection
Isolation Forest-based anomaly detector operating on TLS/session metadata features.
No encrypted payload contents are processed.
"""
from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

# Lazy imports for scikit-learn to avoid heavy startup time
_sklearn_loaded = False
_IsolationForest = None
_StandardScaler = None


def _load_sklearn():
    global _sklearn_loaded, _IsolationForest, _StandardScaler
    if not _sklearn_loaded:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        _IsolationForest = IsolationForest
        _StandardScaler = StandardScaler
        _sklearn_loaded = True


# ---------------------------------------------------------------------------
# Feature Definitions
# ---------------------------------------------------------------------------

# Feature names in the order they appear in the feature vector.
# These are TLS/session METADATA features only — no payload content.
FEATURE_NAMES = [
    "tls_version_num",        # Numeric: 10=TLS1.0, 11=TLS1.1, 12=TLS1.2, 13=TLS1.3, 0=none
    "cipher_strength_cat",    # 0=unknown, 1=null/export, 2=weak, 3=medium, 4=strong
    "key_exchange_cat",       # 0=unknown, 1=RSA, 2=DHE, 3=ECDHE, 4=anon
    "forward_secrecy",        # 0=no/unknown, 1=yes
    "cert_observable",        # 0=not observable, 1=observed
    "cert_expired",           # 0=no/unknown, 1=yes
    "cert_self_signed",       # 0=no/unknown, 1=yes
    "cert_key_bits_norm",     # key bits / 4096 (normalized)
    "sig_alg_weak",           # 0=ok, 1=weak sig algorithm
    "starttls_state_cat",     # 0=none, 1=direct, 2=negotiated, 3=advertised, 4=suspicious
    "cleartext_auth",         # 0=no, 1=yes
    "protocol_cat",           # 0=unknown, 1=SMTP, 2=IMAP, 3=POP3
    "offered_cipher_count",   # number of client-offered ciphers (0 if unknown)
    "extension_count",        # number of TLS extensions
    "session_duration_norm",  # session duration / 300 (capped at 1)
    "packet_count_norm",      # packet count / 100 (capped at 1)
]

N_FEATURES = len(FEATURE_NAMES)


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------

def extract_features(session) -> np.ndarray:
    """
    Extract a fixed-length feature vector from a TCPSession.
    This is the ONLY input to the ML model — no payload bytes.
    """
    from backend.models.session import (
        ForwardSecrecyStatus,
        ObservabilityStatus,
        TLSVersion,
    )
    from backend.tls.analyser import WEAK_CIPHERS

    features = np.zeros(N_FEATURES, dtype=np.float32)

    # TLS version
    tls_ver_map = {
        TLSVersion.TLS_1_0: 10.0,
        TLSVersion.TLS_1_1: 11.0,
        TLSVersion.TLS_1_2: 12.0,
        TLSVersion.TLS_1_3: 13.0,
        TLSVersion.SSL_3_0: 3.0,
        TLSVersion.SSL_2_0: 2.0,
        TLSVersion.UNKNOWN: 0.0,
    }
    hs = session.tls_handshake
    if hs:
        features[0] = tls_ver_map.get(hs.tls_version, 0.0)

        # Cipher strength category
        cipher = hs.cipher_suite or ""
        if "NULL" in cipher or "EXPORT" in cipher:
            features[1] = 1.0
        elif cipher in WEAK_CIPHERS or "RC4" in cipher or "DES" in cipher:
            features[1] = 2.0
        elif "3DES" in cipher or "RC2" in cipher:
            features[1] = 2.5
        elif "AES_128" in cipher or "CHACHA20" in cipher:
            features[1] = 4.0
        elif "AES_256" in cipher:
            features[1] = 4.0
        elif cipher:
            features[1] = 3.0

        # Key exchange
        kex = (hs.key_exchange or "").upper()
        if not kex and cipher:
            if "ECDHE" in cipher:
                kex = "ECDHE"
            elif "DHE" in cipher or "EDH" in cipher:
                kex = "DHE"
            elif "RSA" in cipher:
                kex = "RSA"
        if "ECDHE" in kex:
            features[2] = 3.0
        elif "DHE" in kex or "EDH" in kex:
            features[2] = 2.0
        elif "RSA" in kex:
            features[2] = 1.0
        elif "ANON" in kex or "DH_ANON" in kex:
            features[2] = 4.0

        # Forward secrecy
        features[3] = 1.0 if hs.forward_secrecy == ForwardSecrecyStatus.YES else 0.0

        # Certificate
        cert_obs = (hs.cert_observability == ObservabilityStatus.OBSERVED) or bool(hs.certificates)
        features[4] = 1.0 if cert_obs else 0.0
        if hs.certificates:
            cert = hs.certificates[0]
            features[5] = 1.0 if cert.is_expired else 0.0
            features[6] = 1.0 if cert.is_self_signed else 0.0
            if cert.public_key and cert.public_key.key_size_bits:
                features[7] = min(cert.public_key.key_size_bits / 4096.0, 1.0)
            # Sig algorithm weakness
            sig = (cert.signature_algorithm or "").lower()
            features[8] = 1.0 if any(w in sig for w in ["md5", "sha1", "md2"]) else 0.0

        # STARTTLS state
        starttls_map = {
            "no_tls": 0.0,
            "direct_tls": 1.0,
            "negotiated": 2.0,
            "advertised": 3.0,
            "requested": 3.0,
            "suspicious_fallback": 4.0,
            "failed": 4.0,
        }
        features[9] = starttls_map.get(session.starttls_state.value, 0.0)

        # Cleartext auth
        features[10] = 1.0 if session.cleartext_auth_detected else 0.0

        # Protocol
        proto_map = {
            "SMTP": 1.0, "IMAP": 2.0, "POP3": 3.0, "UNKNOWN": 0.0
        }
        features[11] = proto_map.get(session.protocol.value, 0.0)

        # Offered ciphers count
        features[12] = float(min(len(hs.client_offered_ciphers), 50)) / 50.0

        # Extension count
        exts = len(hs.client_tls_extensions) + len(hs.server_tls_extensions)
        features[13] = float(min(exts, 30)) / 30.0

    # Session metadata
    dur = session.duration_seconds or 0.0
    features[14] = min(dur / 300.0, 1.0)
    features[15] = min(session.packet_count / 100.0, 1.0)

    return features


# ---------------------------------------------------------------------------
# Synthetic Training Data Generation
# ---------------------------------------------------------------------------

def generate_synthetic_training_data(n_benign: int = 500, seed: int = 42) -> np.ndarray:
    """
    Generate synthetic benign TLS session feature vectors for training.
    Uses known-good parameter distributions:
    - TLS 1.2/1.3 only
    - Strong ciphers (AES-GCM, ChaCha20)
    - ECDHE/DHE key exchange
    - Valid certificates
    - Normal session patterns
    """
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n_benign):
        # TLS version: mostly 1.3, some 1.2
        tls_ver = rng.choice([12.0, 13.0], p=[0.35, 0.65])
        cipher_strength = rng.choice([3.5, 4.0], p=[0.3, 0.7])
        kex = rng.choice([2.0, 3.0], p=[0.3, 0.7])  # DHE or ECDHE
        fs = 1.0
        cert_obs = 1.0 if tls_ver == 12.0 else 0.0  # TLS1.3 → not observable
        cert_expired = 0.0
        cert_self_signed = 0.0
        cert_key_norm = rng.uniform(0.5, 1.0) if (cert_obs and rng.random() > 0.3) else 0.0
        sig_weak = 0.0
        starttls = rng.choice([1.0, 2.0], p=[0.4, 0.6])
        cleartext = 0.0
        proto = rng.choice([1.0, 2.0, 3.0], p=[0.5, 0.3, 0.2])
        cipher_count = rng.uniform(0.05, 0.8)
        ext_count = rng.uniform(0.05, 0.7)
        duration = rng.uniform(0.0, 0.3)
        pkt_count = rng.uniform(0.05, 0.5)

        rows.append([
            tls_ver, cipher_strength, kex, fs, cert_obs, cert_expired, cert_self_signed,
            cert_key_norm, sig_weak, starttls, cleartext, proto, cipher_count, ext_count,
            duration, pkt_count,
        ])

    return np.array(rows, dtype=np.float32)


# ---------------------------------------------------------------------------
# Anomaly Detector
# ---------------------------------------------------------------------------

MODEL_PATH = Path(__file__).parent / "isolation_forest.pkl"
SCALER_PATH = Path(__file__).parent / "scaler.pkl"


class TLSAnomalyDetector:
    """
    Isolation Forest anomaly detector for TLS/session metadata.
    
    Distinguishes from the rule engine:
    - Rule engine: deterministic, based on known-bad patterns
    - This detector: probabilistic, flags statistically unusual sessions
    """

    def __init__(self):
        _load_sklearn()
        self._model: Any = None
        self._scaler: Any = None
        self._trained = False

    def train(self, X: np.ndarray | None = None) -> None:
        """
        Train on benign session features.
        If X is None, uses synthetic training data.
        """
        if X is None:
            X = generate_synthetic_training_data()

        self._scaler = _StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = _IsolationForest(
            n_estimators=100,
            contamination=0.05,  # expect ~5% anomalies in real traffic
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._trained = True
        logger.info("Anomaly detector trained on %d samples", len(X))

    def save(self) -> None:
        """Persist model to disk for offline use."""
        import pickle
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self._model, f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(self._scaler, f)
        logger.info("Anomaly model saved to %s", MODEL_PATH)

    def load(self) -> bool:
        """Load a pre-trained model from disk."""
        import pickle
        if not MODEL_PATH.exists() or not SCALER_PATH.exists():
            return False
        try:
            with open(MODEL_PATH, "rb") as f:
                self._model = pickle.load(f)  # noqa: S301
            with open(SCALER_PATH, "rb") as f:
                self._scaler = pickle.load(f)  # noqa: S301
            self._trained = True
            logger.info("Anomaly model loaded from disk")
            return True
        except Exception as exc:
            logger.warning("Could not load saved model: %s", exc)
            return False

    def ensure_trained(self) -> None:
        """Ensure model is ready — load from disk or train fresh."""
        if self._trained:
            return
        if not self.load():
            self.train()
            self.save()

    def score_session(self, session) -> tuple[float, bool, dict[str, Any]]:
        """
        Score a single session.
        Returns:
            (anomaly_score_normalized, is_anomalous, feature_dict)
        
        anomaly_score_normalized: 0.0 (very normal) to 1.0 (very anomalous)
        is_anomalous: True if model predicts anomaly
        """
        self.ensure_trained()

        features = extract_features(session)
        X = features.reshape(1, -1)
        X_scaled = self._scaler.transform(X)

        # Isolation Forest: decision_function > 0 for inliers, < 0 for anomalies
        dec = float(self._model.decision_function(X_scaled)[0])
        is_anomalous = bool(self._model.predict(X_scaled)[0] == -1)

        # Normalize to [0, 1]: dec >= 0.25 -> ~0.0 (normal), dec <= -0.25 -> ~1.0 (anomalous)
        normalized = float(np.clip(0.5 - (dec / 0.5), 0.0, 1.0))

        feature_dict = {
            name: float(val)
            for name, val in zip(FEATURE_NAMES, features)
        }

        return normalized, is_anomalous, feature_dict

    def score_sessions(self, sessions: list) -> list:
        """Score all sessions and annotate with anomaly info."""
        from backend.models.session import Evidence, Finding, FindingCategory, FindingSeverity

        self.ensure_trained()
        annotated = []
        for session in sessions:
            try:
                score, is_anom, feat_dict = self.score_session(session)
                session.anomaly_score = round(score, 4)
                session.is_anomalous = is_anom
                session.anomaly_features = feat_dict

                if is_anom and score > 0.3:
                    severity = (
                        FindingSeverity.HIGH if score > 0.6 else FindingSeverity.MEDIUM
                    )
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        severity=severity,
                        category=FindingCategory.ML_ANOMALY,
                        title=f"ML Behavioural Anomaly (score={score:.2f})",
                        description=(
                            f"The Isolation Forest anomaly detector flagged this "
                            f"{session.protocol.value} session as statistically unusual "
                            f"(anomaly score={score:.3f}). "
                            "This is a probabilistic finding — it indicates the session's "
                            "TLS/protocol metadata deviates from the learned baseline of "
                            "normal sessions. It does NOT prove an attack. "
                            "Combine with deterministic findings for stronger evidence. "
                            f"Key features: cipher_strength={feat_dict.get('cipher_strength_cat', 0):.1f}, "
                            f"starttls_state={feat_dict.get('starttls_state_cat', 0):.0f}, "
                            f"forward_secrecy={feat_dict.get('forward_secrecy', 0):.0f}."
                        ),
                        evidence=Evidence(
                            pcap_file="",
                            session_id=session.session_id,
                            packet_numbers=[],
                            field="ml_anomaly_features",
                            observed_value=feat_dict,
                            extra={"anomaly_score": score, "is_anomalous": is_anom},
                        ),
                        recommendation=(
                            "Investigate this session manually. "
                            "Cross-reference with deterministic findings. "
                            "Consider whether the cipher/TLS configuration matches policy."
                        ),
                        is_ml_finding=True,
                    )
                    session.findings.append(finding)
            except Exception as exc:
                logger.warning("Anomaly scoring failed for session %s: %s", session.session_id, exc)
            annotated.append(session)
        return annotated


# Module-level singleton
_detector: TLSAnomalyDetector | None = None


def get_detector() -> TLSAnomalyDetector:
    global _detector
    if _detector is None:
        _detector = TLSAnomalyDetector()
    return _detector
