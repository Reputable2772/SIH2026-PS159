import React from 'react'
import {
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle2,
  Sparkles,
} from 'lucide-react'

export default function SeverityBadge({ severity, isMl = false, className = '', style = {} }) {
  const sev = (severity || 'info').toLowerCase()

  const getIcon = () => {
    if (isMl) return <Sparkles size={12} />
    switch (sev) {
      case 'critical':
        return <AlertOctagon size={12} />
      case 'high':
        return <AlertTriangle size={12} />
      case 'medium':
        return <AlertCircle size={12} />
      case 'low':
        return <Info size={12} />
      case 'info':
      case 'minimal':
        return <CheckCircle2 size={12} />
      default:
        return <Info size={12} />
    }
  }

  const badgeClass = isMl ? 'sev-badge sev-ml' : `sev-badge sev-${sev}`

  return (
    <span className={`${badgeClass} ${className}`} style={style}>
      {getIcon()}
      <span>{isMl ? 'ML Anomaly' : sev.toUpperCase()}</span>
    </span>
  )
}
