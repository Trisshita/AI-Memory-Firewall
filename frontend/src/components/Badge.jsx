import React from 'react';

export const DecisionBadge = ({ decision }) => {
  const dec = (decision || '').toUpperCase();
  let badgeClass = 'badge-audit';

  if (dec === 'ALLOW') badgeClass = 'badge-allow';
  else if (dec === 'REDACT') badgeClass = 'badge-redact';
  else if (dec === 'BLOCK') badgeClass = 'badge-block';
  else if (dec === 'QUARANTINE') badgeClass = 'badge-quarantine';
  else if (dec === 'ASK_USER') badgeClass = 'badge-ask';

  return <span className={`badge ${badgeClass}`}>{dec}</span>;
};

export const SeverityBadge = ({ severity }) => {
  const sev = (severity || 'LOW').toUpperCase();
  let style = {
    background: 'rgba(100, 116, 139, 0.15)',
    color: '#94a3b8',
    border: '1px solid rgba(148, 163, 184, 0.3)',
  };

  if (sev === 'CRITICAL') {
    style = {
      background: 'rgba(255, 23, 68, 0.15)',
      color: '#ff1744',
      border: '1px solid rgba(255, 23, 68, 0.4)',
    };
  } else if (sev === 'HIGH') {
    style = {
      background: 'rgba(255, 171, 0, 0.15)',
      color: '#ffab00',
      border: '1px solid rgba(255, 171, 0, 0.4)',
    };
  } else if (sev === 'MEDIUM') {
    style = {
      background: 'rgba(0, 229, 255, 0.15)',
      color: '#00e5ff',
      border: '1px solid rgba(0, 229, 255, 0.4)',
    };
  }

  return (
    <span className="badge" style={style}>
      {sev}
    </span>
  );
};

export const TierBadge = ({ tier }) => {
  const t = (tier || 'INTERNAL').toUpperCase();
  let color = '#94a3b8';
  let bg = 'rgba(148, 163, 184, 0.12)';

  if (t === 'CRITICAL') {
    color = '#ff1744';
    bg = 'rgba(255, 23, 68, 0.15)';
  } else if (t === 'CONFIDENTIAL') {
    color = '#d946ef';
    bg = 'rgba(217, 70, 239, 0.15)';
  } else if (t === 'INTERNAL') {
    color = '#00e5ff';
    bg = 'rgba(0, 229, 255, 0.15)';
  } else if (t === 'PUBLIC') {
    color = '#00e676';
    bg = 'rgba(0, 230, 118, 0.15)';
  }

  return (
    <span
      className="badge"
      style={{
        background: bg,
        color: color,
        border: `1px solid ${color}40`,
      }}
    >
      {t}
    </span>
  );
};
