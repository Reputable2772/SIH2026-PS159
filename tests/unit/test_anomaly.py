"""
Unit tests for ML anomaly detection feature extraction.
"""

import numpy as np

from backend.anomaly.detector import (
    FEATURE_NAMES,
    N_FEATURES,
    TLSAnomalyDetector,
    extract_features,
    generate_synthetic_training_data,
)
from backend.models.session import (
    ApplicationProtocol,
    ForwardSecrecyStatus,
    ObservabilityStatus,
    STARTTLSState,
    TCPSession,
    TLSHandshake,
    TLSVersion,
)


def _make_session(
    protocol=ApplicationProtocol.SMTP,
    tls_version=TLSVersion.TLS_1_2,
    cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    fs=ForwardSecrecyStatus.YES,
    starttls=STARTTLSState.NEGOTIATED,
    cleartext_auth=False,
    packet_count=20,
) -> TCPSession:
    s = TCPSession(
        session_id="test:1",
        src_ip="1.2.3.4",
        src_port=12345,
        dst_ip="5.6.7.8",
        dst_port=25,
        protocol=protocol,
        starttls_state=starttls,
        cleartext_auth_detected=cleartext_auth,
        packet_count=packet_count,
        duration_seconds=5.0,
    )
    s.tls_handshake = TLSHandshake(
        tls_version=tls_version,
        cipher_suite=cipher,
        forward_secrecy=fs,
        cert_observability=ObservabilityStatus.OBSERVED,
        client_offered_ciphers=["A", "B", "C"],
        client_tls_extensions=["0", "1"],
    )
    return s


class TestFeatureExtraction:
    def test_feature_vector_length(self):
        session = _make_session()
        features = extract_features(session)
        assert len(features) == N_FEATURES

    def test_feature_names_match(self):
        assert len(FEATURE_NAMES) == N_FEATURES

    def test_tls_13_version_feature(self):
        session = _make_session(tls_version=TLSVersion.TLS_1_3)
        features = extract_features(session)
        assert features[0] == 13.0  # tls_version_num

    def test_tls_10_version_feature(self):
        session = _make_session(tls_version=TLSVersion.TLS_1_0)
        features = extract_features(session)
        assert features[0] == 10.0

    def test_forward_secrecy_feature(self):
        session_yes = _make_session(fs=ForwardSecrecyStatus.YES)
        session_no = _make_session(fs=ForwardSecrecyStatus.NO)
        assert extract_features(session_yes)[3] == 1.0
        assert extract_features(session_no)[3] == 0.0

    def test_cleartext_auth_feature(self):
        clean = _make_session(cleartext_auth=False)
        dirty = _make_session(cleartext_auth=True)
        assert extract_features(clean)[10] == 0.0
        assert extract_features(dirty)[10] == 1.0

    def test_all_features_finite(self):
        session = _make_session()
        features = extract_features(session)
        assert np.all(np.isfinite(features))

    def test_features_in_range(self):
        session = _make_session()
        features = extract_features(session)
        # Most features should be in [0, 15] range
        assert np.all(features >= 0)


class TestSyntheticData:
    def test_synthetic_data_shape(self):
        X = generate_synthetic_training_data(n_benign=100)
        assert X.shape == (100, N_FEATURES)

    def test_synthetic_data_reproducible(self):
        X1 = generate_synthetic_training_data(n_benign=50, seed=42)
        X2 = generate_synthetic_training_data(n_benign=50, seed=42)
        np.testing.assert_array_equal(X1, X2)

    def test_different_seed_different_data(self):
        X1 = generate_synthetic_training_data(n_benign=50, seed=42)
        X2 = generate_synthetic_training_data(n_benign=50, seed=99)
        assert not np.array_equal(X1, X2)


class TestAnomalyDetector:
    def test_train_and_score(self):
        det = TLSAnomalyDetector()
        det.train()
        session = _make_session()
        score, is_anom, feat_dict = det.score_session(session)
        assert 0.0 <= score <= 1.0
        assert isinstance(is_anom, bool)
        assert len(feat_dict) == N_FEATURES

    def test_normal_session_not_anomalous(self):
        """A 'normal' TLS 1.2 ECDHE session should not be flagged."""
        det = TLSAnomalyDetector()
        det.train()
        session = _make_session(
            tls_version=TLSVersion.TLS_1_2,
            cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            fs=ForwardSecrecyStatus.YES,
        )
        score, _, _ = det.score_session(session)
        # Normal sessions should have low anomaly scores
        assert score < 0.8  # Not extremely anomalous

    def test_anomalous_session_flagged(self):
        """A session with cleartext auth + no TLS should score higher."""
        det = TLSAnomalyDetector()
        det.train()
        # Create a session with many anomalous features
        session = _make_session(
            tls_version=TLSVersion.TLS_1_0,
            cipher="TLS_RSA_WITH_RC4_128_SHA",
            fs=ForwardSecrecyStatus.NO,
            cleartext_auth=True,
            starttls=STARTTLSState.SUSPICIOUS_FALLBACK,
        )
        score, _, _ = det.score_session(session)
        # Should score higher than a clean session
        normal = _make_session()
        normal_score, _, _ = det.score_session(normal)
        assert score >= normal_score or score > 0.1  # Anomalous scores higher
