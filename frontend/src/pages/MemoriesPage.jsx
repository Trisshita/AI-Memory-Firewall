import React, { useState, useEffect } from 'react';
import {
  Brain,
  Search,
  Filter,
  Lock,
  Eye,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Clock,
  X,
  Plus,
} from 'lucide-react';
import { memoryApi } from '../services/api';
import { TierBadge } from '../components/Badge';
import { CodeViewer } from '../components/CodeViewer';
import { useAlerts } from '../context/AlertContext';
import { useAuth } from '../context/AuthContext';

export const MemoriesPage = () => {
  const [memories, setMemories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState('');
  const [quarantineFilter, setQuarantineFilter] = useState('');
  const [selectedMemory, setSelectedMemory] = useState(null);
  const [showStoreModal, setShowStoreModal] = useState(false);

  // Store modal form
  const [storeText, setStoreText] = useState('');
  const [storeTier, setStoreTier] = useState('INTERNAL');
  const [storeType, setStoreType] = useState('SHORT_TERM');
  const [storeSessionId, setStoreSessionId] = useState(() => 'sess-' + Math.random().toString(36).substring(2, 8));
  const [storing, setStoring] = useState(false);

  const { activeTenantId } = useAuth();
  const { addToast } = useAlerts();

  const fetchMemories = async () => {
    setLoading(true);
    try {
      const params = {
        limit: 50,
      };
      if (tierFilter) params.sensitivity_tier = tierFilter;
      if (quarantineFilter === 'quarantined') params.is_quarantined = true;
      if (quarantineFilter === 'safe') params.is_quarantined = false;
      if (search.trim()) params.search = search.trim();

      const data = await memoryApi.getMemories(params);
      setMemories(data.memories || []);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to Load Memories',
        message: err.response?.data?.detail || err.message,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMemories();
  }, [tierFilter, quarantineFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchMemories();
  };

  const handleStoreMemory = async (e) => {
    e.preventDefault();
    if (!storeText.trim()) return;
    setStoring(true);
    try {
      const res = await memoryApi.storeMemory({
        text: storeText,
        tenant_id: activeTenantId,
        session_id: storeSessionId,
        memory_type: storeType,
        sensitivity_tier: storeTier,
      });

      addToast({
        type: 'success',
        title: 'Memory Stored & Encrypted',
        message: `Decision: ${res.evaluation?.decision || 'STORED'}`,
      });

      setShowStoreModal(false);
      setStoreText('');
      fetchMemories();
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Storage Error',
        message: err.response?.data?.detail || err.message,
      });
    } finally {
      setStoring(false);
    }
  };

  return (
    <div className="page-body">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', display: 'flex', alignItems: 'center', gap: 10 }}>
            <Brain color="var(--cyan)" size={28} /> Memory Records & Encryption Inspector
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Inspect sanitized agent recall content and AES-256 Fernet ciphertext at rest.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button onClick={fetchMemories} className="btn btn-secondary btn-sm" title="Refresh">
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
          <button onClick={() => setShowStoreModal(true)} className="btn btn-primary btn-sm">
            <Plus size={14} /> Inject Memory Record
          </button>
        </div>
      </div>

      {/* Filters Bar */}
      <div
        className="glass-card"
        style={{
          padding: '16px 20px',
          marginBottom: 24,
          display: 'flex',
          flexWrap: 'wrap',
          gap: 16,
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: 10, flex: 1, minWidth: '280px' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <input
              type="text"
              className="input"
              placeholder="Search memory content, entities, or tokens..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-secondary">
            <Search size={16} /> Search
          </button>
        </form>

        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <select
            className="select"
            style={{ width: '160px' }}
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value)}
          >
            <option value="">All Tiers</option>
            <option value="PUBLIC">PUBLIC</option>
            <option value="INTERNAL">INTERNAL</option>
            <option value="CONFIDENTIAL">CONFIDENTIAL</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>

          <select
            className="select"
            style={{ width: '170px' }}
            value={quarantineFilter}
            onChange={(e) => setQuarantineFilter(e.target.value)}
          >
            <option value="">All Statuses</option>
            <option value="safe">Safe (Non-Quarantine)</option>
            <option value="quarantined">Quarantined Only</option>
          </select>
        </div>
      </div>

      {/* Memories Table */}
      <div className="glass-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="table-container">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Sensitivity Tier</th>
                <th>Memory Type</th>
                <th>Sanitized Content Preview</th>
                <th>Status</th>
                <th>Created At</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {memories.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '36px' }}>
                    {loading ? 'Fetching encrypted memory records...' : 'No memory records found matching criteria.'}
                  </td>
                </tr>
              ) : (
                memories.map((m) => (
                  <tr key={m.id}>
                    <td className="mono" style={{ color: 'var(--cyan)', fontSize: '0.8125rem' }}>
                      {String(m.session_id).slice(0, 12)}...
                    </td>
                    <td>
                      <TierBadge tier={m.sensitivity_tier} />
                    </td>
                    <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      {m.memory_type}
                    </td>
                    <td style={{ maxWidth: '340px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {m.sanitized_content}
                    </td>
                    <td>
                      {m.is_quarantined ? (
                        <span style={{ color: 'var(--crimson)', fontSize: '0.75rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <ShieldAlert size={14} /> QUARANTINED
                        </span>
                      ) : (
                        <span style={{ color: 'var(--emerald)', fontSize: '0.75rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <ShieldCheck size={14} /> ACTIVE RECALL
                        </span>
                      )}
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {m.created_at ? new Date(m.created_at).toLocaleTimeString() : 'N/A'}
                    </td>
                    <td>
                      <button
                        onClick={() => setSelectedMemory(m)}
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

      {/* Memory Details Modal: Sanitized vs AES-256 Ciphertext Side-by-Side */}
      {selectedMemory && (
        <div className="modal-overlay" onClick={() => setSelectedMemory(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '780px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Brain color="var(--cyan)" size={24} />
                <h2 style={{ fontSize: '1.25rem' }}>Memory Record Inspector</h2>
              </div>
              <button onClick={() => setSelectedMemory(null)} className="btn btn-ghost" style={{ padding: 4 }}>
                <X size={18} />
              </button>
            </div>

            {/* Metadata Badges */}
            <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
              <TierBadge tier={selectedMemory.sensitivity_tier} />
              <span className="badge badge-audit">{selectedMemory.memory_type}</span>
              {selectedMemory.is_quarantined && (
                <span className="badge badge-block">
                  Quarantined: {selectedMemory.quarantine_reason || 'Policy Violation'}
                </span>
              )}
            </div>

            {/* Side-by-Side Content Comparison */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
              <div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--emerald)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <ShieldCheck size={16} /> Sanitized Recall Content
                </div>
                <div
                  style={{
                    background: '#070b14',
                    border: '1px solid rgba(0, 230, 118, 0.2)',
                    borderRadius: 'var(--radius-md)',
                    padding: '14px',
                    fontSize: '0.875rem',
                    minHeight: '140px',
                    lineHeight: 1.5,
                  }}
                >
                  {selectedMemory.sanitized_content}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--cyan)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Lock size={16} /> AES-256 Fernet Ciphertext at Rest
                </div>
                <div
                  className="mono"
                  style={{
                    background: '#070b14',
                    border: '1px solid rgba(0, 229, 255, 0.2)',
                    borderRadius: 'var(--radius-md)',
                    padding: '14px',
                    fontSize: '0.75rem',
                    color: '#38bdf8',
                    minHeight: '140px',
                    wordBreak: 'break-all',
                    lineHeight: 1.4,
                  }}
                >
                  {selectedMemory.raw_content || 'gAAAAABn... [Encrypted with symmetric Fernet tenant key]'}
                </div>
              </div>
            </div>

            {/* Forensic Hashes & Schema */}
            <CodeViewer code={selectedMemory} title="Complete Database Record Metadata" />
          </div>
        </div>
      )}

      {/* Direct Memory Store Creation Modal */}
      {showStoreModal && (
        <div className="modal-overlay" onClick={() => setShowStoreModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '560px' }}>
            <h2 style={{ fontSize: '1.25rem', marginBottom: 16 }}>Inspect & Store Memory Record</h2>

            <form onSubmit={handleStoreMemory}>
              <div className="form-group">
                <label className="form-label">Raw Memory Text to Screen & Ingest</label>
                <textarea
                  rows={4}
                  required
                  className="textarea"
                  placeholder="Enter sensitive or standard conversational memory text..."
                  value={storeText}
                  onChange={(e) => setStoreText(e.target.value)}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">Sensitivity Classification</label>
                  <select className="select" value={storeTier} onChange={(e) => setStoreTier(e.target.value)}>
                    <option value="PUBLIC">PUBLIC</option>
                    <option value="INTERNAL">INTERNAL</option>
                    <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Memory Category</label>
                  <select className="select" value={storeType} onChange={(e) => setStoreType(e.target.value)}>
                    <option value="SHORT_TERM">SHORT_TERM</option>
                    <option value="LONG_TERM">LONG_TERM</option>
                    <option value="EPISODIC">EPISODIC</option>
                    <option value="SEMANTIC">SEMANTIC</option>
                    <option value="USER_CONTEXT">USER_CONTEXT</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 20 }}>
                <button type="button" onClick={() => setShowStoreModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={storing || !storeText.trim()}>
                  {storing ? 'Evaluating...' : 'Screen & Ingest Memory'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
