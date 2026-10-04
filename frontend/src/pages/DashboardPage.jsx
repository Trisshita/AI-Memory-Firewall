import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Brain,
  FileKey2,
  AlertTriangle,
  Zap,
  RefreshCw,
  Clock,
  ArrowUpRight,
  ExternalLink,
} from 'lucide-react';
import { StatCard } from '../components/StatCard';
import { DecisionBadge, SeverityBadge } from '../components/Badge';
import { auditApi, gatewayApi } from '../services/api';
import { useAlerts } from '../context/AlertContext';
import { useAuth } from '../context/AuthContext';
import { DecisionModal } from '../components/DecisionModal';

export const DashboardPage = () => {
  const [summary, setSummary] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [pendingDecisions, setPendingDecisions] = useState([]);
  const [activeDecisionModal, setActiveDecisionModal] = useState(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);

  const { activeTenantId } = useAuth();
  const { addToast, isChainValid, checkChainStatus } = useAlerts();
  const navigate = useNavigate();

  const loadDashboardData = async () => {
    try {
      const [sumData, logsData] = await Promise.all([
        auditApi.getSummary(activeTenantId),
        auditApi.getAuditLogs({ limit: 8 }),
      ]);
      setSummary(sumData);
      setRecentLogs(logsData.entries || []);
    } catch (err) {
      console.error('Failed to fetch dashboard summary', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 8000);
    return () => clearInterval(interval);
  }, [activeTenantId]);

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await auditApi.verifyHashChain();
      await checkChainStatus();
      if (res.is_valid) {
        addToast({
          type: 'success',
          title: 'Hash Chain Verified',
          message: `All ${res.total_entries} cryptographic ledger blocks mathematically intact.`,
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

  const handleResolveDecision = async ({ decisionId, choice, scope }) => {
    try {
      await gatewayApi.submitDecision(decisionId, choice, scope);
      addToast({
        type: 'success',
        title: 'Decision Applied',
        message: `Action '${choice}' applied to pending request.`,
      });
      setActiveDecisionModal(null);
      loadDashboardData();
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Resolution Error',
        message: err.response?.data?.detail || err.message,
      });
    }
  };

  return (
    <div className="page-body">
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', display: 'flex', alignItems: 'center', gap: 10 }}>
            Security Operations Dashboard
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Real-time telemetry, memory encryption monitors, and SHA-256 ledger integrity.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button onClick={loadDashboardData} className="btn btn-secondary btn-sm" title="Refresh Telemetry">
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
          <button onClick={() => navigate('/playground')} className="btn btn-primary btn-sm">
            <Zap size={14} /> Open Live Gateway Sandbox
          </button>
        </div>
      </div>

      {/* Pending Human Approvals Alert Bar (if any) */}
      {summary?.pending_decisions > 0 && (
        <div
          className="glass-card"
          style={{
            background: 'rgba(0, 229, 255, 0.08)',
            border: '1px solid rgba(0, 229, 255, 0.3)',
            padding: '16px 20px',
            borderRadius: 'var(--radius-md)',
            marginBottom: 24,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Clock size={20} color="var(--cyan)" />
            <div>
              <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                {summary.pending_decisions} Pending Human-in-the-Loop Confirmation{summary.pending_decisions > 1 ? 's' : ''}
              </span>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Sensitive rule triggered. Client prompt paused awaiting approval.
              </p>
            </div>
          </div>
          <button
            onClick={() => navigate('/playground')}
            className="btn btn-primary btn-sm"
          >
            Review in Sandbox <ArrowUpRight size={14} />
          </button>
        </div>
      )}

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 18, marginBottom: 28 }}>
        <StatCard
          title="Total Screened Turns"
          value={summary?.total_events || 0}
          icon={Shield}
          color="cyan"
          trend="100% Inbound / Outbound"
        />
        <StatCard
          title="Blocked Threats"
          value={summary?.total_blocked || 0}
          icon={ShieldAlert}
          color="crimson"
          trend="Quarantine Active"
        />
        <StatCard
          title="Encrypted Memories"
          value={summary?.total_memories || 0}
          icon={Brain}
          color="emerald"
          subtitle={`${summary?.quarantined_memories || 0} quarantined records`}
        />
        <StatCard
          title="Active Alerts"
          value={summary?.active_alerts || 0}
          icon={AlertTriangle}
          color={summary?.active_alerts > 0 ? 'amber' : 'emerald'}
          subtitle="Unresolved incidents"
        />
        <StatCard
          title="Ledger Chain Height"
          value={`#${summary?.chain_length || 0}`}
          icon={FileKey2}
          color="indigo"
          subtitle="SHA-256 Sealed Blocks"
        />
      </div>

      {/* Main Grid: Cryptographic Hash Chain Card & Live Threat Feed */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 24 }}>
        {/* Left: Recent Forensic Audit Logs */}
        <div className="glass-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <div>
              <h2 style={{ fontSize: '1.125rem' }}>Live Audit & Security Event Stream</h2>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Tamper-proof event logs committed to SHA-256 ledger.
              </p>
            </div>
            <button onClick={() => navigate('/audit')} className="btn btn-ghost btn-sm">
              View Full Chain <ExternalLink size={12} />
            </button>
          </div>

          <div className="table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Seq #</th>
                  <th>Action</th>
                  <th>Severity</th>
                  <th>Actor</th>
                  <th>Current Block Hash</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>
                      No recent audit events recorded.
                    </td>
                  </tr>
                ) : (
                  recentLogs.map((log) => (
                    <tr key={log.id}>
                      <td className="mono" style={{ color: 'var(--cyan)', fontWeight: 600 }}>
                        #{log.sequence_number}
                      </td>
                      <td style={{ fontWeight: 600 }}>
                        {log.action}
                      </td>
                      <td>
                        <SeverityBadge severity={log.severity} />
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.8125rem' }}>
                        {log.actor || 'system'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {log.entry_hash?.slice(0, 16)}...
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Cryptographic Chain Verification Widget */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div
            className="glass-card"
            style={{
              padding: '24px',
              border: isChainValid ? '1px solid rgba(0, 230, 118, 0.25)' : '1px solid rgba(255, 23, 68, 0.4)',
              background: isChainValid ? 'rgba(0, 230, 118, 0.03)' : 'rgba(255, 23, 68, 0.05)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
              <div
                style={{
                  width: 42,
                  height: 42,
                  borderRadius: '10px',
                  background: isChainValid ? 'var(--emerald-muted)' : 'var(--crimson-muted)',
                  color: isChainValid ? 'var(--emerald)' : 'var(--crimson)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {isChainValid ? <ShieldCheck size={24} /> : <AlertTriangle size={24} />}
              </div>
              <div>
                <h3 style={{ fontSize: '1.0625rem' }}>Cryptographic Proof</h3>
                <span style={{ fontSize: '0.8125rem', color: isChainValid ? 'var(--emerald)' : 'var(--crimson)', fontWeight: 700 }}>
                  {isChainValid ? '100% ZERO TAMPER DETECTED' : 'CHAIN COMPROMISED'}
                </span>
              </div>
            </div>

            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 20 }}>
              Each firewall evaluation turn is sequentially chained with SHA-256 cryptographic hashes. Tampering with any historical database row instantly breaks the mathematical chain proof.
            </p>

            <button
              onClick={handleVerifyChain}
              className="btn btn-emerald"
              style={{ width: '100%' }}
              disabled={verifying}
            >
              <RefreshCw size={16} className={verifying ? 'spin' : ''} />
              {verifying ? 'Scanning Sequential Chain Hashes...' : 'Run Mathematical Verification'}
            </button>
          </div>

          {/* Memory Protection Summary */}
          <div className="glass-card" style={{ padding: '24px' }}>
            <h3 style={{ fontSize: '1.0625rem', marginBottom: 12 }}>Memory Defense Layers</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: '0.8125rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Cipher Suite:</span>
                <span className="mono" style={{ color: 'var(--cyan)', fontWeight: 600 }}>AES-256-Fernet</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Context Recall Isolation:</span>
                <span style={{ color: 'var(--emerald)', fontWeight: 600 }}>Quarantines Excluded</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>HITL Safety Gate:</span>
                <span style={{ color: 'var(--cyan)', fontWeight: 600 }}>Active (Option A Fallback)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {activeDecisionModal && (
        <DecisionModal
          decisionData={activeDecisionModal}
          onSubmit={handleResolveDecision}
          onClose={() => setActiveDecisionModal(null)}
        />
      )}
    </div>
  );
};
