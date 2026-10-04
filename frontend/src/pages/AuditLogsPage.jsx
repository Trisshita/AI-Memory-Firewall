import React, { useState, useEffect } from 'react';
import {
  FileKey2,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  Eye,
  X,
  Link as LinkIcon,
  CheckCircle2,
} from 'lucide-react';
import { auditApi } from '../services/api';
import { SeverityBadge } from '../components/Badge';
import { CodeViewer } from '../components/CodeViewer';
import { useAlerts } from '../context/AlertContext';

export const AuditLogsPage = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [selectedEntry, setSelectedEntry] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('');

  const { addToast, isChainValid, checkChainStatus } = useAlerts();

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = { limit: 100 };
      if (severityFilter) params.severity = severityFilter;
      if (eventTypeFilter) params.event_type = eventTypeFilter;

      const data = await auditApi.getAuditLogs(params);
      setLogs(data.entries || []);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to Fetch Audit Logs',
        message: err.response?.data?.detail || err.message,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [severityFilter, eventTypeFilter]);

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await auditApi.verifyHashChain();
      setVerificationResult(res);
      await checkChainStatus();

      if (res.is_valid) {
        addToast({
          type: 'success',
          title: 'Ledger Proof Verified',
          message: `Sequential SHA-256 integrity verified across all ${res.total_entries} blocks.`,
        });
      } else {
        addToast({
          type: 'error',
          title: 'Chain Break Detected!',
          message: `Block sequence #${res.first_broken_sequence || res.broken_at_sequence || 1} failed hash signature check.`,
        });
      }
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Verification Failed',
        message: err.message,
      });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="page-body">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', display: 'flex', alignItems: 'center', gap: 10 }}>
            <FileKey2 color="var(--cyan)" size={28} /> Cryptographic SHA-256 Audit Ledger
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Immutable, tamper-proof blockchain-style sequence of all firewall actions and security state changes.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button onClick={fetchLogs} className="btn btn-secondary btn-sm" title="Refresh Logs">
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
          <button
            onClick={handleVerifyChain}
            className="btn btn-emerald btn-sm"
            disabled={verifying}
          >
            <ShieldCheck size={16} />
            {verifying ? 'Scanning Ledger...' : 'Run Cryptographic Verification'}
          </button>
        </div>
      </div>

      {/* Verification Status Banner */}
      {verificationResult && (
        <div
          className="glass-card"
          style={{
            padding: '16px 20px',
            marginBottom: 24,
            border: verificationResult.is_valid ? '1px solid rgba(0, 230, 118, 0.3)' : '1px solid rgba(255, 23, 68, 0.4)',
            background: verificationResult.is_valid ? 'rgba(0, 230, 118, 0.05)' : 'rgba(255, 23, 68, 0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {verificationResult.is_valid ? (
              <CheckCircle2 size={24} color="var(--emerald)" />
            ) : (
              <AlertTriangle size={24} color="var(--crimson)" />
            )}
            <div>
              <span style={{ fontWeight: 700, color: verificationResult.is_valid ? 'var(--emerald)' : 'var(--crimson)' }}>
                {verificationResult.is_valid
                  ? `Cryptographic Verification Successful (100% Chain Proof)`
                  : `Security Alert: Chain Break Detected at Sequence #${verificationResult.broken_at_sequence}`}
              </span>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Total Verified Blocks: {verificationResult.total_entries} | Algorithm: SHA-256 Merkle-Style Sequence
              </p>
            </div>
          </div>

          <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Status: {verificationResult.is_valid ? 'MATHEMATICALLY SEALED' : 'CORRUPTED'}
          </span>
        </div>
      )}

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
          Filter Ledger:
        </span>

        <select
          className="select"
          style={{ width: '180px' }}
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>

        <select
          className="select"
          style={{ width: '220px' }}
          value={eventTypeFilter}
          onChange={(e) => setEventTypeFilter(e.target.value)}
        >
          <option value="">All Event Types</option>
          <option value="FIREWALL_EVAL">FIREWALL_EVAL</option>
          <option value="POLICY_CHANGE">POLICY_CHANGE</option>
          <option value="AUTHENTICATION">AUTHENTICATION</option>
          <option value="ENCRYPTION_KEY_ROTATED">ENCRYPTION_KEY_ROTATED</option>
        </select>
      </div>

      {/* Audit Ledger Table */}
      <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-container">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Seq #</th>
                <th>Action</th>
                <th>Event Type</th>
                <th>Severity</th>
                <th>Actor</th>
                <th>Previous Hash ➔ Current Entry Hash</th>
                <th>Timestamp</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '36px' }}>
                    {loading ? 'Reading SHA-256 ledger blocks...' : 'No ledger entries found.'}
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id}>
                    <td className="mono" style={{ color: 'var(--cyan)', fontWeight: 700 }}>
                      #{log.sequence_number}
                    </td>
                    <td style={{ fontWeight: 600 }}>{log.action}</td>
                    <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      {log.event_type}
                    </td>
                    <td>
                      <SeverityBadge severity={log.severity} />
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.8125rem' }}>
                      {log.actor || 'system'}
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <span>{log.previous_hash?.slice(0, 8)}...</span>
                      <span style={{ color: 'var(--cyan)', margin: '0 6px' }}>➔</span>
                      <span style={{ color: '#38bdf8' }}>{log.entry_hash?.slice(0, 8)}...</span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {log.created_at ? new Date(log.created_at).toLocaleTimeString() : 'N/A'}
                    </td>
                    <td>
                      <button
                        onClick={() => setSelectedEntry(log)}
                        className="btn btn-secondary btn-sm"
                        style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                      >
                        <Eye size={12} /> Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Inspection Modal */}
      {selectedEntry && (
        <div className="modal-overlay" onClick={() => setSelectedEntry(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '720px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <FileKey2 color="var(--cyan)" size={24} />
                <h2 style={{ fontSize: '1.25rem' }}>Ledger Block #{selectedEntry.sequence_number}</h2>
              </div>
              <button onClick={() => setSelectedEntry(null)} className="btn btn-ghost" style={{ padding: 4 }}>
                <X size={18} />
              </button>
            </div>

            {/* Cryptographic Link Visualizer */}
            <div
              style={{
                background: '#070b14',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                padding: '16px',
                marginBottom: 20,
              }}
            >
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>
                  Previous Block Hash:
                </div>
                <div className="mono" style={{ fontSize: '0.8125rem', color: '#94a3b8', wordBreak: 'break-all' }}>
                  {selectedEntry.previous_hash}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--cyan)', marginBottom: 4 }}>
                  Current Sealed Entry Hash:
                </div>
                <div className="mono" style={{ fontSize: '0.8125rem', color: 'var(--cyan)', fontWeight: 700, wordBreak: 'break-all' }}>
                  {selectedEntry.entry_hash}
                </div>
              </div>
            </div>

            <CodeViewer code={selectedEntry} title="Raw Ledger Node Schema & Decrypted Payload" />
          </div>
        </div>
      )}
    </div>
  );
};
