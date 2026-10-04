import React from 'react';
import { AlertTriangle, CheckCircle, Info, XCircle, X } from 'lucide-react';
import { useAlerts } from '../context/AlertContext';

export const AlertToast = () => {
  const { toasts, removeToast } = useAlerts();

  if (!toasts || toasts.length === 0) return null;

  const iconMap = {
    error: <XCircle size={20} color="var(--crimson)" />,
    warning: <AlertTriangle size={20} color="var(--amber)" />,
    info: <Info size={20} color="var(--cyan)" />,
    success: <CheckCircle size={20} color="var(--emerald)" />,
  };

  const borderMap = {
    error: 'rgba(255, 23, 68, 0.4)',
    warning: 'rgba(255, 171, 0, 0.4)',
    info: 'rgba(0, 229, 255, 0.4)',
    success: 'rgba(0, 230, 118, 0.4)',
  };

  return (
    <div className="toast-container">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className="toast"
          style={{
            borderColor: borderMap[toast.type] || borderMap.info,
          }}
        >
          <div style={{ flexShrink: 0, marginTop: 2 }}>{iconMap[toast.type] || iconMap.info}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 700, fontSize: '0.875rem', marginBottom: 2 }}>
              {toast.title}
            </div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              {toast.message}
            </div>
          </div>
          <button
            onClick={() => removeToast(toast.id)}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: 4,
            }}
          >
            <X size={16} />
          </button>
        </div>
      ))}
    </div>
  );
};
