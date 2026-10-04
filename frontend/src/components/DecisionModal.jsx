import React, { useState } from 'react';
import { AlertCircle, CheckCircle, ShieldAlert, ShieldCheck, EyeOff, XCircle, Clock } from 'lucide-react';
import { DecisionBadge } from './Badge';

export const DecisionModal = ({ decisionData, onSubmit, onClose, loading = false }) => {
  const [selectedChoice, setSelectedChoice] = useState('ALLOW');
  const [scope, setScope] = useState('ONCE');

  if (!decisionData) return null;

  const handleSubmit = () => {
    onSubmit({
      decisionId: decisionData.id || decisionData.pending_decision_id,
      choice: selectedChoice,
      scope: selectedChoice === 'REMEMBER_FOR_SESSION' ? 'SESSION' : scope,
    });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '620px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: 'var(--radius-md)',
              background: 'var(--cyan-muted)',
              color: 'var(--cyan)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <AlertCircle size={24} />
          </div>
          <div>
            <h2 style={{ fontSize: '1.25rem' }}>Human Confirmation Required</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              Safety policy flagged sensitive data requiring human authorization.
            </p>
          </div>
        </div>

        {/* Trigger info */}
        <div
          style={{
            background: 'rgba(0, 229, 255, 0.05)',
            border: '1px solid rgba(0, 229, 255, 0.2)',
            borderRadius: 'var(--radius-md)',
            padding: '16px',
            marginBottom: 20,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Trigger Reason:</span>
            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--cyan)' }}>
              {decisionData.trigger_reason || decisionData.ask_user_details?.trigger_reason}
            </span>
          </div>
          {(decisionData.matched_text || decisionData.ask_user_details?.matched_text) && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Flagged Content:</span>
              <span className="mono" style={{ fontSize: '0.8125rem', color: 'var(--crimson)' }}>
                "{decisionData.matched_text || decisionData.ask_user_details?.matched_text}"
              </span>
            </div>
          )}
          <div style={{ marginTop: 10 }}>
            <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Sanitized Preview:
            </span>
            <div
              style={{
                background: '#070b14',
                padding: '10px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.875rem',
                color: 'var(--text-primary)',
              }}
            >
              {decisionData.sanitized_prompt || '[Sanitized Prompt Content]'}
            </div>
          </div>
        </div>

        {/* Action Choice Selection */}
        <div style={{ marginBottom: 24 }}>
          <label className="form-label" style={{ marginBottom: 10, display: 'block' }}>
            Select Human-in-the-Loop Action:
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            <button
              type="button"
              onClick={() => setSelectedChoice('ALLOW')}
              className="glass-card"
              style={{
                padding: '14px',
                textAlign: 'left',
                cursor: 'pointer',
                border: selectedChoice === 'ALLOW' ? '2px solid var(--emerald)' : '1px solid var(--border-subtle)',
                background: selectedChoice === 'ALLOW' ? 'var(--emerald-muted)' : 'var(--bg-card)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--emerald)', fontWeight: 700 }}>
                <ShieldCheck size={18} /> ALLOW
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 4 }}>
                Forward unredacted prompt to AI model for this single turn.
              </p>
            </button>

            <button
              type="button"
              onClick={() => setSelectedChoice('REDACT')}
              className="glass-card"
              style={{
                padding: '14px',
                textAlign: 'left',
                cursor: 'pointer',
                border: selectedChoice === 'REDACT' ? '2px solid var(--amber)' : '1px solid var(--border-subtle)',
                background: selectedChoice === 'REDACT' ? 'var(--amber-muted)' : 'var(--bg-card)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--amber)', fontWeight: 700 }}>
                <EyeOff size={18} /> REDACT
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 4 }}>
                Mask detected entities and forward sanitized prompt to AI.
              </p>
            </button>

            <button
              type="button"
              onClick={() => setSelectedChoice('REMEMBER_FOR_SESSION')}
              className="glass-card"
              style={{
                padding: '14px',
                textAlign: 'left',
                cursor: 'pointer',
                border: selectedChoice === 'REMEMBER_FOR_SESSION' ? '2px solid var(--cyan)' : '1px solid var(--border-subtle)',
                background: selectedChoice === 'REMEMBER_FOR_SESSION' ? 'var(--cyan-muted)' : 'var(--bg-card)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--cyan)', fontWeight: 700 }}>
                <Clock size={18} /> REMEMBER FOR SESSION
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 4 }}>
                Allow and auto-approve sensitive inquiries for this entire session.
              </p>
            </button>

            <button
              type="button"
              onClick={() => setSelectedChoice('BLOCK')}
              className="glass-card"
              style={{
                padding: '14px',
                textAlign: 'left',
                cursor: 'pointer',
                border: selectedChoice === 'BLOCK' ? '2px solid var(--crimson)' : '1px solid var(--border-subtle)',
                background: selectedChoice === 'BLOCK' ? 'var(--crimson-muted)' : 'var(--bg-card)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--crimson)', fontWeight: 700 }}>
                <XCircle size={18} /> BLOCK
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 4 }}>
                Halt execution, quarantine turn, and prevent AI response.
              </p>
            </button>
          </div>
        </div>

        {/* Modal actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
          <button type="button" onClick={onClose} className="btn btn-secondary" disabled={loading}>
            Cancel
          </button>
          <button type="button" onClick={handleSubmit} className="btn btn-primary" disabled={loading}>
            {loading ? 'Submitting...' : `Confirm & Apply ${selectedChoice}`}
          </button>
        </div>
      </div>
    </div>
  );
};
