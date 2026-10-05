import React from 'react';
import { Info } from 'lucide-react';

export default function FooterNote({ customNote }) {
  return (
    <footer className="page-footer-note">
      <div className="disclaimer-box">
        <Info size={15} />
        <span>
          {customNote ||
            'Assessment limits: one capture, not a network-wide inventory. TLS 1.3 certificates may be encrypted and not observable. Trust validation needs context; ML anomalies are review signals, not maliciousness verdicts.'}
        </span>
      </div>

      <div className="page-footer-fineprint">
        <span>DEMO DATA · Illustrative metrics and evidence · Not a real assessment</span>
        <span>03 OCT 2026 · UTC · PASSIVE ANALYSIS</span>
      </div>
    </footer>
  );
}
