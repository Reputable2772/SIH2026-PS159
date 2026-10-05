import React from 'react';

export default function DonutGauge({
  encryptedCount = 40,
  totalCount = 48,
  percentage = '83.3%',
  size = 170,
}) {
  // SVG Donut calculation
  const radius = 64;
  const strokeWidth = 14;
  const center = size / 2;
  const circumference = 2 * Math.PI * radius;

  const encFraction = encryptedCount / totalCount;
  const encDasharray = `${encFraction * circumference} ${circumference}`;
  // We rotate so the gap starts at the bottom or top
  // In the mockup, the teal starts from bottom-left around to top and right, and amber is on the bottom-right
  const rotationOffset = -90; // starts at 12 o'clock

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Background track */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="#1B242C"
          strokeWidth={strokeWidth}
        />
        {/* Plaintext segment (Amber) */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="#F3BC68"
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={0}
          transform={`rotate(${rotationOffset} ${center} ${center})`}
          strokeLinecap="round"
        />
        {/* Encrypted segment (Teal) */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="#59D9BC"
          strokeWidth={strokeWidth}
          strokeDasharray={encDasharray}
          strokeDashoffset={0}
          transform={`rotate(${rotationOffset} ${center} ${center})`}
          strokeLinecap="round"
        />
      </svg>

      {/* Center text overlay */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
          pointerEvents: 'none',
        }}
      >
        <span style={{ fontSize: '32px', fontWeight: 700, color: '#EDF3F5', lineHeight: 1 }}>
          {encryptedCount}
        </span>
        <span style={{ fontSize: '11px', color: '#778995', marginTop: '2px' }}>
          of {totalCount} encrypted
        </span>
        <span
          style={{
            fontSize: '9.5px',
            color: '#59D9BC',
            fontWeight: 700,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginTop: '3px',
          }}
        >
          {percentage} OBSERVED
        </span>
      </div>
    </div>
  );
}
