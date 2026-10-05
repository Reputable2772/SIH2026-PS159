import React from 'react';
import { ACTIVITY_TIMELINE } from '../mockData';

export default function ActivityChart({
  packets = "18,426 packets",
  duration = "14m 32s duration",
  analyzedAt = "Analyzed 09:16:08 UTC",
  size = "12.8 MiB",
  starttls = "26 STARTTLS negotiated",
  toolInfo = "v0.1.0 · processed in 8.2s",
}) {
  const width = 680;
  const height = 120;
  const paddingX = 10;
  const paddingY = 15;

  const data = ACTIVITY_TIMELINE;
  const maxVal = Math.max(...data.map((d) => d.value));
  const minVal = 0;

  const points = data.map((d, i) => {
    const x = paddingX + (i / (data.length - 1)) * (width - 2 * paddingX);
    const y = height - paddingY - ((d.value - minVal) / (maxVal - minVal)) * (height - 2 * paddingY);
    return { x, y };
  });

  const pathD = points.reduce((acc, pt, i) => {
    if (i === 0) return `M ${pt.x},${pt.y}`;
    // Simple line to point
    return `${acc} L ${pt.x},${pt.y}`;
  }, '');

  const areaD = `${pathD} L ${points[points.length - 1].x},${height - paddingY} L ${points[0].x},${height - paddingY} Z`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', width: '100%' }}>
      {/* SVG Timeline Chart */}
      <div style={{ width: '100%', overflow: 'hidden' }}>
        <svg
          viewBox={`0 0 ${width} ${height}`}
          style={{ width: '100%', height: '110px', display: 'block' }}
          preserveAspectRatio="none"
        >
          <defs>
            <linearGradient id="activityGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#59D9BC" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#59D9BC" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Base baseline */}
          <line
            x1={paddingX}
            y1={height - paddingY}
            x2={width - paddingX}
            y2={height - paddingY}
            stroke="#2A353E"
            strokeWidth="1"
          />

          {/* Filled area */}
          <path d={areaD} fill="url(#activityGradient)" />

          {/* Stroke path */}
          <path
            d={pathD}
            fill="none"
            stroke="#59D9BC"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>

        {/* X-axis labels */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            fontSize: '10.5px',
            color: '#778995',
            fontFamily: 'var(--font-mono)',
            marginTop: '2px',
            padding: '0 4px',
          }}
        >
          <span>09:00</span>
          <span>09:07</span>
          <span>09:14</span>
        </div>
      </div>

      {/* Metrics Row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '8px',
          paddingTop: '10px',
          borderTop: '1px solid var(--border-subtle)',
          fontSize: '11.5px',
          fontFamily: 'var(--font-mono)',
        }}
      >
        <span style={{ color: '#EDF3F5' }}>{packets}</span>
        <span style={{ color: '#A5B4BF' }}>{duration}</span>
        <span style={{ color: '#778995', textAlign: 'right' }}>{analyzedAt}</span>

        <span style={{ color: '#EDF3F5' }}>{size}</span>
        <span style={{ color: '#59D9BC' }}>{starttls}</span>
        <span style={{ color: '#778995', textAlign: 'right' }}>{toolInfo}</span>
      </div>
    </div>
  );
}
