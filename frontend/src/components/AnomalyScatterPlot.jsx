import React from 'react';
import { SCATTER_PLOT_POINTS } from '../mockData';

export default function AnomalyScatterPlot({
  selectedId = 'S-017',
  onSelectSession,
  points = SCATTER_PLOT_POINTS,
}) {
  const width = 720;
  const height = 240;
  const paddingLeft = 55;
  const paddingRight = 30;
  const paddingTop = 25;
  const paddingBottom = 45;

  const plotWidth = width - paddingLeft - paddingRight;
  const plotHeight = height - paddingTop - paddingBottom;

  const dataPoints = Array.isArray(points) && points.length > 0 ? points : SCATTER_PLOT_POINTS;

  // X range: 0 to 16
  const minX = 0;
  const maxX = 16;
  // Y range: -0.30 to +0.30 (or scale dynamic)
  const minY = -0.30;
  const maxY = 0.30;

  const scaleX = (x) => paddingLeft + (Math.max(0, Math.min(16, x) - minX) / (maxX - minX)) * plotWidth;
  const scaleY = (y) => paddingTop + ((maxY - Math.max(-0.3, Math.min(0.3, y))) / (maxY - minY)) * plotHeight;

  const yTicks = [0.30, 0.10, -0.10, -0.30];
  const xTicks = [0, 8, 16];

  const anomalousCount = dataPoints.filter((p) => p.isAnomalous).length;
  const normalCount = dataPoints.length - anomalousCount;

  return (
    <div style={{ width: '100%', position: 'relative' }}>
      {/* Legend */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '18px',
          fontSize: '11px',
          color: '#A5B4BF',
          marginBottom: '10px',
        }}
      >
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#59D9BC' }}></span>
          {normalCount} not flagged
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#F3BC68' }}></span>
          {anomalousCount} ML anomalies
        </span>
        <span style={{ color: '#778995', fontStyle: 'italic' }}>
          Ring = selected session
        </span>
      </div>

      {/* SVG Canvas */}
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: '100%', height: 'auto', display: 'block', overflow: 'visible' }}
      >
        {/* Y Axis Title */}
        <text
          x={paddingLeft - 8}
          y={paddingTop - 10}
          fill="#778995"
          fontSize="9.5"
          fontWeight="600"
          fontFamily="var(--font-mono)"
          letterSpacing="0.08em"
        >
          MODEL-SPECIFIC ANOMALY SCORE
        </text>

        {/* Grid lines and Y ticks */}
        {yTicks.map((val) => {
          const yPos = scaleY(val);
          return (
            <g key={val}>
              <line
                x1={paddingLeft}
                y1={yPos}
                x2={width - paddingRight}
                y2={yPos}
                stroke={val === 0 ? '#3A4753' : '#1C2630'}
                strokeWidth={val === 0 ? '1.2' : '1'}
                strokeDasharray={val === 0 ? 'none' : '3 3'}
              />
              <text
                x={paddingLeft - 10}
                y={yPos + 3.5}
                fill="#778995"
                fontSize="10"
                fontFamily="var(--font-mono)"
                textAnchor="end"
              >
                {val > 0 ? `${val.toFixed(2)}` : val.toFixed(2)}
              </text>
            </g>
          );
        })}

        {/* X Ticks and Labels */}
        {xTicks.map((val) => {
          const xPos = scaleX(val);
          return (
            <g key={val}>
              <line
                x1={xPos}
                y1={scaleY(minY)}
                x2={xPos}
                y2={scaleY(minY) + 5}
                stroke="#2A353E"
                strokeWidth="1"
              />
              <text
                x={xPos}
                y={scaleY(minY) + 18}
                fill="#778995"
                fontSize="10.5"
                fontFamily="var(--font-mono)"
                textAnchor="middle"
              >
                {val}
              </text>
            </g>
          );
        })}

        {/* X Axis Title */}
        <text
          x={paddingLeft + plotWidth / 2}
          y={height - 8}
          fill="#778995"
          fontSize="9.5"
          fontWeight="600"
          fontFamily="var(--font-mono)"
          letterSpacing="0.08em"
          textAnchor="middle"
        >
          OBSERVED TLS HANDSHAKE RECORD COUNT →
        </text>

        {/* Data points */}
        {dataPoints.map((pt) => {
          const cx = scaleX(pt.x ?? 4);
          const cy = scaleY(pt.y ?? 0);
          const isSelected = selectedId === pt.id;

          return (
            <g
              key={pt.id}
              onClick={() => onSelectSession?.(pt.id)}
              style={{ cursor: 'pointer' }}
            >
              {/* Outer Selection Ring */}
              {isSelected && (
                <circle
                  cx={cx}
                  cy={cy}
                  r="10"
                  fill="none"
                  stroke="#F3BC68"
                  strokeWidth="2"
                  opacity="0.9"
                />
              )}

              {/* Main Point Circle */}
              <circle
                cx={cx}
                cy={cy}
                r={isSelected ? '5.5' : pt.isAnomalous ? '4.5' : '3.5'}
                fill={pt.isAnomalous ? '#F3BC68' : '#59D9BC'}
                opacity={pt.isAnomalous ? 1.0 : 0.65}
              />

              {/* Selected Label */}
              {isSelected && (
                <text
                  x={cx + 12}
                  y={cy - 8}
                  fill="#EDF3F5"
                  fontSize="11"
                  fontWeight="600"
                  fontFamily="var(--font-mono)"
                >
                  {pt.id}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
