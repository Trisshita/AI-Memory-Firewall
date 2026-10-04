import React from 'react';
import { Shield, Bell, Lock, User, LogOut, CheckCircle2, AlertOctagon } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useAlerts } from '../context/AlertContext';
import { Link } from 'react-router-dom';

export const Navbar = () => {
  const { user, logout, activeTenantId, setActiveTenantId, isAdmin } = useAuth();
  const { unreadCount, isChainValid } = useAlerts();

  return (
    <header
      style={{
        height: '70px',
        background: 'rgba(255, 255, 255, 0.9)',
        backdropFilter: 'blur(16px)',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 32px',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        boxShadow: '0 4px 20px rgba(148, 163, 184, 0.08)',
      }}
    >
      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div
          style={{
            width: 38,
            height: 38,
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #0284c7 0%, #4f46e5 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 4px 12px rgba(2, 132, 199, 0.3)',
          }}
        >
          <Shield size={22} color="#ffffff" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span
              style={{
                fontFamily: 'var(--font-heading)',
                fontWeight: 800,
                fontSize: '1.125rem',
                letterSpacing: '-0.02em',
                background: 'linear-gradient(90deg, #0f172a 0%, #475569 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              AI MEMORY FIREWALL
            </span>
            <span
              style={{
                fontSize: '0.65rem',
                fontWeight: 700,
                padding: '2px 6px',
                borderRadius: '4px',
                background: 'rgba(0, 229, 255, 0.1)',
                color: 'var(--cyan)',
                border: '1px solid rgba(0, 229, 255, 0.3)',
              }}
            >
              v1.0 ENTERPRISE
            </span>
          </div>
        </div>
      </div>

      {/* Right controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
        {/* Hash Chain Live Health Beacon */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '6px 14px',
            background: isChainValid ? 'rgba(0, 230, 118, 0.08)' : 'rgba(255, 23, 68, 0.1)',
            border: `1px solid ${isChainValid ? 'rgba(0, 230, 118, 0.3)' : 'rgba(255, 23, 68, 0.4)'}`,
            borderRadius: 'var(--radius-full)',
            fontSize: '0.75rem',
            fontWeight: 700,
          }}
        >
          <span className={`beacon ${isChainValid ? 'beacon-online' : ''}`} style={!isChainValid ? { background: 'var(--crimson)' } : {}} />
          <span style={{ color: isChainValid ? 'var(--emerald)' : 'var(--crimson)', letterSpacing: '0.04em' }}>
            {isChainValid ? 'SHA-256 LEDGER INTACT' : 'CHAIN TAMPER DETECTED'}
          </span>
        </div>

        {/* Alerts Bell */}
        <Link
          to="/alerts"
          style={{
            position: 'relative',
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            width: 40,
            height: 40,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: unreadCount > 0 ? 'var(--amber)' : 'var(--text-secondary)',
            textDecoration: 'none',
          }}
          title="Security Alerts"
        >
          <Bell size={18} />
          {unreadCount > 0 && (
            <span
              style={{
                position: 'absolute',
                top: -4,
                right: -4,
                background: 'var(--crimson)',
                color: '#fff',
                fontSize: '0.65rem',
                fontWeight: 800,
                width: 18,
                height: 18,
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 0 8px var(--crimson)',
              }}
            >
              {unreadCount}
            </span>
          )}
        </Link>

        {/* User Pill & Logout */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '4px 6px 4px 12px',
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-full)',
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.8125rem', fontWeight: 600 }}>{user?.email || 'Authenticated User'}</span>
            <span style={{ fontSize: '0.6875rem', color: isAdmin ? 'var(--cyan)' : 'var(--text-muted)', fontWeight: 600 }}>
              {isAdmin ? 'SYSTEM ADMIN' : 'ANALYST'}
            </span>
          </div>

          <button
            onClick={logout}
            className="btn btn-ghost"
            style={{
              width: 32,
              height: 32,
              padding: 0,
              borderRadius: '50%',
              color: 'var(--text-muted)',
            }}
            title="Sign Out"
          >
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </header>
  );
};
