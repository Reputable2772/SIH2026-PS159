import React from 'react'
import { Sun, Moon } from 'lucide-react'
import { useTheme } from '../context/ThemeContext.jsx'

export default function ThemeToggle() {
  const { theme, toggleTheme } = useTheme()

  return (
    <button
      className="btn btn-secondary"
      onClick={toggleTheme}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      aria-label="Toggle theme"
      style={{
        padding: '0.4rem 0.65rem',
        fontSize: '0.8rem',
        borderRadius: 'var(--radius-sm)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.4rem',
      }}
    >
      {theme === 'dark' ? (
        <>
          <Sun size={15} color="var(--medium)" />
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Light</span>
        </>
      ) : (
        <>
          <Moon size={15} color="var(--accent)" />
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Dark</span>
        </>
      )}
    </button>
  )
}
