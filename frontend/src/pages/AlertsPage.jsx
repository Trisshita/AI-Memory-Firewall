import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  Search,
  Filter,
  Clock,
  User,
  X,
} from 'lucide-react';
import { auditApi } from '../services/api';
import { SeverityBadge } from '../components/Badge';
import { CodeViewer } from '../components/CodeViewer';
import { useAlerts } from '../context/AlertContext';

export const AlertsPage = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterResolved, setFilterResolved] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [resolveNotes, setResolveNotes] = useState('');
  const [resolving, setResolving] = useState(false);

  const { addToast, resolveAlert } = useAlerts();

  const fetchAlertsList = async () => {
    setLoading(true);
    try {
      const data = await auditApi.getAlerts(filterResolved, 50);
      setAlerts(data.alerts || data.items || []);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to Fetch Alerts',
        message: err.response?.data?.detail || err.message,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlertsList();
  }, [filterResolved]);

  const handleResolveSubmit = async (e) => {
    e.preventDefault();
    if (!selectedAlert) return;
    setResolving(true);
    try {
      await resolveAlert(selectedAlert.id, resolveNotes || 'Verified and mitigated by security analyst');
      setSelectedAlert(null);
      setResolveNotes('');
      fetchAlertsList();
    } catch (err) {
      // Handled in context
    } finally {
      setResolving(false);
    }
  };

  return (
    <div className="page-body">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle color="var(--amber)" size={28} /> Real-Time Security Alerts Center
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            High-severity security incidents, prompt injection attempts, and policy breach alarms.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button onClick={fetchAlertsList} className="btn btn-secondary btn-sm" title="Refresh">
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* Filter Row */}
      <div
        className="glass-card"
        style={{
          padding: '16px 20px',
          marginBottom: 24,
          display: 'flex',
          gap: 16,
          alignItems: 'center',
        }}
      >
        <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
          Incident Status:
        </span>

        <button
          className={`btn ${!filterResolved ? 'btn-primary' : 'btn-secondary'} btn-sm`}
          onClick={() => setFilterResolved(false)}
        >
          Active Incidents
        </button>
        <button
          className={`btn ${filterResolved ? 'btn-primary' : 'btn-secondary'} btn-sm`}
          onClick={() => setFilterResolved(true)}
        >
          Resolved Archive
        </button>
      </div>

      {/* Alerts Grid */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {alerts.length === 0 ? (
          <div
            className="glass-card"
            style={{
              padding: '48px',
              textAlign: 'center',
              color: 'var(--text-muted)',
            }}
          >
            <div
              style={{
                width: 50,
                height: 50,
                borderRadius: '50%',
                background: 'var(--emerald-muted)',
                color: 'var(--emerald)',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: 16,
              }}
            >
              <ShieldCheck size={26} />
            </div>
            <h3 style={{ fontSize: '1.125rem', marginBottom: 4, color: 'var(--text-primary)' }}>
              {filterResolved ? 'No Resolved Alerts Found' : 'No Active Security Incidents'}
            </h3>
            <p style={{ fontSize: '0.875rem' }}>
              All memory firewall screening filters operating within normal safety tolerances.
            </p>
          </div>
        ) : (
          alerts.map((alt) => (
            <div
              key={alt.id}
              className="glass-card"
              style={{
                padding: '20px 24px',
                borderLeft: `4px solid ${alt.severity === 'CRITICAL' ? 'var(--crimson)' : 'var(--amber)'}`,
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: 20,
              }}
            >
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <SeverityBadge severity={alt.severity} />
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Clock size={12} /> {alt.created_at ? new Date(alt.created_at).toLocaleString() : 'Recent'}
                  </span>
                  {alt.is_resolved && (
                    <span className="badge badge-allow" style={{ fontSize: '0.6875rem' }}>
                      RESOLVED
                    </span>
                  )}
                </div>

                <h3 style={{ fontSize: '1.0625rem', marginBottom: 6 }}>
                  {alt.event_type || 'Security Violation'}: {alt.summary || alt.reason || 'High risk prompt flagged by evaluation engine.'}
                </h3>

                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: 12 }}>
                  Resource: <span className="mono" style={{ color: 'var(--cyan)' }}>{alt.resource || 'session memory'}</span> | Actor: {alt.actor || 'external user'}
                </p>

                {alt.payload && (
                  <div style={{ maxWidth: '600px' }}>
                    <CodeViewer code={alt.payload} title="Incident Details" maxHeight="120px" />
                  </div>
                )}
              </div>

              <div>
                {!alt.is_resolved ? (
                  <button
                    onClick={() => setSelectedAlert(alt)}
                    className="btn btn-emerald btn-sm"
                  >
                    <CheckCircle2 size={14} /> Resolve Alert
                  </button>
                ) : (
                  <div style={{ fontSize: '0.75rem', color: 'var(--emerald)', fontWeight: 600 }}>
                    Resolved at {alt.resolved_at ? new Date(alt.resolved_at).toLocaleTimeString() : 'N/A'}
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Resolve Alert Modal */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '520px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: '1.25rem' }}>Resolve Security Incident</h2>
              <button onClick={() => setSelectedAlert(null)} className="btn btn-ghost" style={{ padding: 4 }}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleResolveSubmit}>
              <div className="form-group">
                <label className="form-label">Resolution Notes & Mitigation Audit Justification</label>
                <textarea
                  rows={4}
                  required
                  className="textarea"
                  placeholder="e.g. False positive confirmed after security analyst review / Prompt was quarantined and policy updated."
                  value={resolveNotes}
                  onChange={(e) => setResolveNotes(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 20 }}>
                <button type="button" onClick={() => setSelectedAlert(null)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-emerald" disabled={resolving || !resolveNotes.trim()}>
                  {resolving ? 'Submitting...' : 'Mark Incident Resolved'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
