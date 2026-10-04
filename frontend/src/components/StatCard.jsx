import React from 'react';

export const StatCard = ({ title, value, icon: Icon, trend, color = 'cyan', subtitle }) => {
  const colorMap = {
    cyan: { accent: 'var(--cyan)', bg: 'var(--cyan-muted)' },
    emerald: { accent: 'var(--emerald)', bg: 'var(--emerald-muted)' },
    crimson: { accent: 'var(--crimson)', bg: 'var(--crimson-muted)' },
    amber: { accent: 'var(--amber)', bg: 'var(--amber-muted)' },
    indigo: { accent: 'var(--indigo)', bg: 'var(--indigo-muted)' },
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div
      className="glass-card stat-card"
      style={{
        '--stat-accent': scheme.accent,
        '--stat-bg': scheme.bg,
      }}
    >
      <div className="stat-header">
        <span>{title}</span>
        {Icon && (
          <div className="stat-icon-wrapper">
            <Icon size={20} />
          </div>
        )}
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-footer">
        {trend && (
          <span style={{ color: scheme.accent, fontWeight: 600 }}>{trend}</span>
        )}
        <span>{subtitle || 'Real-time telemetry'}</span>
      </div>
    </div>
  );
};
