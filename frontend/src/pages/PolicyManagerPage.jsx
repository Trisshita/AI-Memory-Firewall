import React, { useState, useEffect } from 'react';
import {
  Sliders,
  Shield,
  Plus,
  Trash2,
  Edit2,
  RefreshCw,
  Play,
  CheckCircle,
  AlertTriangle,
  Lock,
  X,
} from 'lucide-react';
import { policyApi } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useAlerts } from '../context/AlertContext';
import { DecisionBadge, SeverityBadge } from '../components/Badge';
import { CodeViewer } from '../components/CodeViewer';

export const PolicyManagerPage = () => {
  const [activeTab, setActiveTab] = useState('policies');
  const [policies, setPolicies] = useState([]);
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);

  // Modals
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [showRuleModal, setShowRuleModal] = useState(false);

  // Policy form
  const [policyForm, setPolicyForm] = useState({
    name: '',
    target_role: '*',
    action: 'REDACT',
    priority_order: 20,
    max_risk_threshold: 0.75,
    is_active: true,
    description: '',
  });

  // Rule form
  const [ruleForm, setRuleForm] = useState({
    name: '',
    rule_type: 'KEYWORD_FILTER',
    pattern_payload: '',
    action: 'ASK_USER',
    severity: 'MEDIUM',
    priority_order: 10,
    is_active: true,
  });

  // Sandbox testing
  const [testText, setTestText] = useState('Testing wire transfer to unverified external routing number.');
  const [testRole, setTestRole] = useState('user');
  const [testResult, setTestResult] = useState(null);
  const [evaluating, setEvaluating] = useState(false);

  const { activeTenantId } = useAuth();
  const { addToast } = useAlerts();

  const loadData = async () => {
    setLoading(true);
    try {
      const [policiesData, rulesData] = await Promise.all([
        policyApi.getPolicies({ limit: 100 }).catch(() => ({ policies: [] })),
        policyApi.getRules(activeTenantId).catch(() => ({ rules: [] })),
      ]);
      setPolicies(policiesData.policies || []);
      setRules(rulesData.rules || []);
    } catch (err) {
      console.error('Failed to load policies/rules', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeTenantId]);

  const handleCreatePolicy = async (e) => {
    e.preventDefault();
    try {
      await policyApi.createPolicy({
        ...policyForm,
        tenant_id: activeTenantId,
      });
      addToast({ type: 'success', title: 'Policy Created', message: `Security policy '${policyForm.name}' saved.` });
      setShowPolicyModal(false);
      setPolicyForm({
        name: '',
        target_role: '*',
        action: 'REDACT',
        priority_order: 20,
        max_risk_threshold: 0.75,
        is_active: true,
        description: '',
      });
      loadData();
    } catch (err) {
      addToast({ type: 'error', title: 'Error Creating Policy', message: err.response?.data?.detail || err.message });
    }
  };

  const handleCreateRule = async (e) => {
    e.preventDefault();
    try {
      await policyApi.createRule({
        ...ruleForm,
        tenant_id: activeTenantId,
      });
      addToast({ type: 'success', title: 'Firewall Rule Created', message: `Rule '${ruleForm.name}' saved.` });
      setShowRuleModal(false);
      setRuleForm({
        name: '',
        rule_type: 'KEYWORD_FILTER',
        pattern_payload: '',
        action: 'ASK_USER',
        severity: 'MEDIUM',
        priority_order: 10,
        is_active: true,
      });
      loadData();
    } catch (err) {
      addToast({ type: 'error', title: 'Error Creating Rule', message: err.response?.data?.detail || err.message });
    }
  };

  const handleEvaluateSandbox = async () => {
    if (!testText.trim()) return;
    setEvaluating(true);
    try {
      const res = await policyApi.evaluatePolicy({
        user_role: testRole,
        memory_text: testText,
        risk_score: 0.65,
        detected_entities: ['WIRE_TRANSFER'],
      });
      setTestResult(res);
      addToast({ type: 'info', title: 'Sandbox Evaluated', message: `Resulting Action: ${res.decision}` });
    } catch (err) {
      addToast({ type: 'error', title: 'Evaluation Failed', message: err.message });
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div className="page-body">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', display: 'flex', alignItems: 'center', gap: 10 }}>
            <Sliders color="var(--cyan)" size={28} /> Policy & Firewall Rules Manager
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Configure Role-Based Access Controls (RBAC), risk thresholds, keyword filters, and ASK_USER confirmation gates.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button onClick={loadData} className="btn btn-secondary btn-sm" title="Refresh">
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
          {activeTab === 'policies' && (
            <button onClick={() => setShowPolicyModal(true)} className="btn btn-primary btn-sm">
              <Plus size={14} /> New Security Policy
            </button>
          )}
          {activeTab === 'rules' && (
            <button onClick={() => setShowRuleModal(true)} className="btn btn-primary btn-sm">
              <Plus size={14} /> New Firewall Rule
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="tab-list">
        <button
          className={`tab-btn ${activeTab === 'policies' ? 'active' : ''}`}
          onClick={() => setActiveTab('policies')}
        >
          <Shield size={16} /> Security Policies ({policies.length})
        </button>
        <button
          className={`tab-btn ${activeTab === 'rules' ? 'active' : ''}`}
          onClick={() => setActiveTab('rules')}
        >
          <Sliders size={16} /> Firewall Rules ({rules.length})
        </button>
        <button
          className={`tab-btn ${activeTab === 'sandbox' ? 'active' : ''}`}
          onClick={() => setActiveTab('sandbox')}
        >
          <Play size={16} /> Policy Engine Sandbox
        </button>
      </div>

      {/* TAB 1: Policies */}
      {activeTab === 'policies' && (
        <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>Policy Name</th>
                  <th>Target Role</th>
                  <th>Action</th>
                  <th>Max Risk Threshold</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {policies.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '36px' }}>
                      No active security policies found. Click 'New Security Policy' to create one.
                    </td>
                  </tr>
                ) : (
                  policies.map((p) => (
                    <tr key={p.id}>
                      <td className="mono" style={{ color: 'var(--cyan)', fontWeight: 700 }}>
                        #{p.priority_order}
                      </td>
                      <td style={{ fontWeight: 600 }}>{p.name}</td>
                      <td>
                        <span className="badge badge-audit">
                          {p.target_role === '*' ? 'ALL ROLES (*)' : p.target_role}
                        </span>
                      </td>
                      <td>
                        <DecisionBadge decision={p.action} />
                      </td>
                      <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                        &le; {(p.max_risk_threshold * 100).toFixed(0)}%
                      </td>
                      <td>
                        <span style={{ color: p.is_active ? 'var(--emerald)' : 'var(--text-muted)', fontSize: '0.8125rem', fontWeight: 600 }}>
                          {p.is_active ? '● Active' : '○ Inactive'}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: Rules */}
      {activeTab === 'rules' && (
        <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>Rule Name</th>
                  <th>Rule Type</th>
                  <th>Pattern / Keywords</th>
                  <th>Prescribed Action</th>
                  <th>Severity</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rules.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '36px' }}>
                      No custom firewall rules configured for this tenant.
                    </td>
                  </tr>
                ) : (
                  rules.map((r) => (
                    <tr key={r.id}>
                      <td className="mono" style={{ color: 'var(--cyan)', fontWeight: 700 }}>
                        #{r.priority_order}
                      </td>
                      <td style={{ fontWeight: 600 }}>{r.name}</td>
                      <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>{r.rule_type}</td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--amber)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.pattern_payload}
                      </td>
                      <td>
                        <DecisionBadge decision={r.action} />
                      </td>
                      <td>
                        <SeverityBadge severity={r.severity} />
                      </td>
                      <td>
                        <span style={{ color: r.is_active ? 'var(--emerald)' : 'var(--text-muted)', fontSize: '0.8125rem', fontWeight: 600 }}>
                          {r.is_active ? '● Active' : '○ Inactive'}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Sandbox */}
      {activeTab === 'sandbox' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
          <div className="glass-card" style={{ padding: '24px' }}>
            <h2 style={{ fontSize: '1.125rem', marginBottom: 16 }}>Test Policy Engine Direct Evaluation</h2>

            <div className="form-group">
              <label className="form-label">Sample Memory / Prompt Stream</label>
              <textarea
                rows={4}
                className="textarea"
                value={testText}
                onChange={(e) => setTestText(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Subject User Role</label>
              <select className="select" value={testRole} onChange={(e) => setTestRole(e.target.value)}>
                <option value="user">user</option>
                <option value="admin">admin</option>
                <option value="agent">agent</option>
              </select>
            </div>

            <button
              onClick={handleEvaluateSandbox}
              className="btn btn-primary"
              style={{ width: '100%', marginTop: 8 }}
              disabled={evaluating}
            >
              {evaluating ? 'Evaluating Policies...' : 'Evaluate Against Active Policies'}
            </button>
          </div>

          <div className="glass-card" style={{ padding: '24px' }}>
            <h2 style={{ fontSize: '1.125rem', marginBottom: 16 }}>Policy Engine Evaluation Result</h2>
            {testResult ? (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                  <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Decision:</span>
                  <DecisionBadge decision={testResult.decision} />
                  <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                    ({testResult.latency_ms} ms)
                  </span>
                </div>
                <CodeViewer code={testResult} title="Policy Evaluation JSON" />
              </div>
            ) : (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px 0' }}>
                Run an evaluation to inspect matched driving policies and rule violation details.
              </div>
            )}
          </div>
        </div>
      )}

      {/* New Policy Modal */}
      {showPolicyModal && (
        <div className="modal-overlay" onClick={() => setShowPolicyModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '580px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: '1.25rem' }}>Create Security Policy</h2>
              <button onClick={() => setShowPolicyModal(false)} className="btn btn-ghost" style={{ padding: 4 }}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreatePolicy}>
              <div className="form-group">
                <label className="form-label">Policy Name</label>
                <input
                  type="text"
                  required
                  className="input"
                  placeholder="e.g. Strict PII Exfiltration Guard"
                  value={policyForm.name}
                  onChange={(e) => setPolicyForm({ ...policyForm, name: e.target.value })}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">Target Role</label>
                  <select
                    className="select"
                    value={policyForm.target_role}
                    onChange={(e) => setPolicyForm({ ...policyForm, target_role: e.target.value })}
                  >
                    <option value="*">All Roles (*)</option>
                    <option value="user">user</option>
                    <option value="agent">agent</option>
                    <option value="admin">admin</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Action</label>
                  <select
                    className="select"
                    value={policyForm.action}
                    onChange={(e) => setPolicyForm({ ...policyForm, action: e.target.value })}
                  >
                    <option value="REDACT">REDACT</option>
                    <option value="BLOCK">BLOCK</option>
                    <option value="QUARANTINE">QUARANTINE</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">Priority Order (Lower = First)</label>
                  <input
                    type="number"
                    className="input"
                    value={policyForm.priority_order}
                    onChange={(e) => setPolicyForm({ ...policyForm, priority_order: parseInt(e.target.value) })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Max Risk Threshold (0.0 to 1.0)</label>
                  <input
                    type="number"
                    step="0.05"
                    className="input"
                    value={policyForm.max_risk_threshold}
                    onChange={(e) => setPolicyForm({ ...policyForm, max_risk_threshold: parseFloat(e.target.value) })}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 20 }}>
                <button type="button" onClick={() => setShowPolicyModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Save Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New Firewall Rule Modal */}
      {showRuleModal && (
        <div className="modal-overlay" onClick={() => setShowRuleModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '580px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: '1.25rem' }}>Create Custom Firewall Rule</h2>
              <button onClick={() => setShowRuleModal(false)} className="btn btn-ghost" style={{ padding: 4 }}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreateRule}>
              <div className="form-group">
                <label className="form-label">Rule Name</label>
                <input
                  type="text"
                  required
                  className="input"
                  placeholder="e.g. Confirm Wire Transfers"
                  value={ruleForm.name}
                  onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">Rule Type</label>
                  <select
                    className="select"
                    value={ruleForm.rule_type}
                    onChange={(e) => setRuleForm({ ...ruleForm, rule_type: e.target.value })}
                  >
                    <option value="KEYWORD_FILTER">KEYWORD_FILTER</option>
                    <option value="REGEX_PATTERN">REGEX_PATTERN</option>
                    <option value="PII_DETECTION">PII_DETECTION</option>
                    <option value="PROMPT_INJECTION">PROMPT_INJECTION</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Action</label>
                  <select
                    className="select"
                    value={ruleForm.action}
                    onChange={(e) => setRuleForm({ ...ruleForm, action: e.target.value })}
                  >
                    <option value="ASK_USER">ASK_USER (Human Confirmation)</option>
                    <option value="REDACT">REDACT</option>
                    <option value="BLOCK">BLOCK</option>
                    <option value="QUARANTINE">QUARANTINE</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Pattern Payload (Comma-separated keywords or Regex)</label>
                <input
                  type="text"
                  required
                  className="input mono"
                  placeholder="wire transfer, account balance, routing number"
                  value={ruleForm.pattern_payload}
                  onChange={(e) => setRuleForm({ ...ruleForm, pattern_payload: e.target.value })}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">Severity</label>
                  <select
                    className="select"
                    value={ruleForm.severity}
                    onChange={(e) => setRuleForm({ ...ruleForm, severity: e.target.value })}
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Priority Order</label>
                  <input
                    type="number"
                    className="input"
                    value={ruleForm.priority_order}
                    onChange={(e) => setRuleForm({ ...ruleForm, priority_order: parseInt(e.target.value) })}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 20 }}>
                <button type="button" onClick={() => setShowRuleModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Save Firewall Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
