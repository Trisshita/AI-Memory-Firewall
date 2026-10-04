import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Zap,
  Brain,
  FileKey2,
  Sliders,
  AlertTriangle,
  ExternalLink,
  Shield,
} from 'lucide-react';
import { useAlerts } from '../context/AlertContext';

export const Sidebar = () => {
  const { unreadCount } = useAlerts();

  const navItems = [
    { to: '/', label: 'Overview Dashboard', icon: LayoutDashboard },
    { to: '/playground', label: 'Gateway & HITL Sandbox', icon: Zap },
    { to: '/memories', label: 'Memory Records', icon: Brain },
    { to: '/audit', label: 'Audit & Hash Chain', icon: FileKey2 },
    { to: '/policies', label: 'Policies & Rules', icon: Sliders },
    { to: '/alerts', label: 'Security Alerts', icon: AlertTriangle, badge: unreadCount },
  ];

  return (
    <aside
      style={{
        width: '260px',
        background: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: '24px 16px',
        flexShrink: 0,
      }}
    >
      <div>
        <div style={{ padding: '0 12px 16px 12px', fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          NAVIGATION CONSOLE
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                style={({ isActive }) => ({
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-md)',
                  color: isActive ? 'var(--cyan)' : 'var(--text-secondary)',
                  background: isActive ? 'rgba(0, 229, 255, 0.08)' : 'transparent',
                  border: isActive ? '1px solid rgba(0, 229, 255, 0.25)' : '1px solid transparent',
                  textDecoration: 'none',
                  fontWeight: isActive ? 600 : 500,
                  fontSize: '0.875rem',
                  transition: 'all var(--transition-fast)',
                })}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <Icon size={18} />
                  <span>{item.label}</span>
                </div>
                {item.badge > 0 && (
                  <span
                    style={{
                      background: 'var(--crimson)',
                      color: '#fff',
                      fontSize: '0.6875rem',
                      fontWeight: 800,
                      padding: '2px 7px',
                      borderRadius: 'var(--radius-full)',
                    }}
                  >
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Footer Info Box */}
      <div
        className="glass-card"
        style={{
          padding: '14px',
          background: 'var(--cyan-muted)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-md)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <Shield size={16} color="var(--cyan)" />
          <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            Defensive Mode
          </span>
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
          AES-256 Fernet encryption active. Real-time NLP injection shield armed.
        </p>
      </div>
    </aside>
  );
};
