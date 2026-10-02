

export default function ProtocolTag({ protocol, style = {} }) {
  const proto = (protocol || 'UNKNOWN').toUpperCase()
  return (
    <span className={`proto-tag proto-${proto}`} style={style}>
      {proto}
    </span>
  )
}
