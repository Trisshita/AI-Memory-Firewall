import axios from 'axios';

// Create base Axios instance
const api = axios.create({
  baseURL: '',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: attach Bearer token if present
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('firewall_access_token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: auto-logout on 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Clear token if expired
      const isAuthEndpoint = error.config.url?.includes('/auth/login') || error.config.url?.includes('/auth/register');
      if (!isAuthEndpoint) {
        localStorage.removeItem('firewall_access_token');
        localStorage.removeItem('firewall_user');
      }
    }
    return Promise.reject(error);
  }
);

// ─── Auth Endpoints ───────────────────────────────────────────────────────────
export const authApi = {
  login: async (email, password) => {
    const res = await api.post('/auth/login', { email, password });
    return res.data;
  },
  register: async (email, password, role = 'user', tenantName = 'Default Org') => {
    const res = await api.post('/auth/register', { email, password, role, tenant_name: tenantName });
    return res.data;
  },
  getMe: async () => {
    const res = await api.get('/auth/me');
    return res.data;
  },
};

// ─── Firewall Gateway & Decisions (Weeks 7 & 8) ───────────────────────────────
export const gatewayApi = {
  sendMessage: async (payload) => {
    // payload: { message, session_id, tenant_id, model, mock_llm_response, system_prompt, skip_llm }
    const res = await api.post('/api/message', payload);
    return res.data;
  },
  submitDecision: async (decisionId, decision, scope = 'ONCE', mockLlmResponse = null) => {
    // decision: ALLOW | REDACT | BLOCK | REMEMBER_FOR_SESSION
    const res = await api.post('/api/message/decide', {
      decision_id: decisionId,
      decision,
      scope,
      mock_llm_response: mockLlmResponse,
    });
    return res.data;
  },
  getPendingDecisions: async (sessionId) => {
    const res = await api.get(`/api/message/pending/${sessionId}`);
    return res.data;
  },
  inspectText: async (text, tenantId = null) => {
    const res = await api.post('/api/v1/firewall/inspect', { text, tenant_id: tenantId });
    return res.data;
  },
};

// ─── Memories Explorer ────────────────────────────────────────────────────────
export const memoryApi = {
  getMemories: async (params = {}) => {
    // params: { session_id, sensitivity_tier, is_quarantined, search, limit, offset }
    const res = await api.get('/api/v1/memory', { params });
    return res.data;
  },
  getSessionMemories: async (sessionId, includeQuarantined = true) => {
    const res = await api.get(`/api/v1/memory/${sessionId}`, {
      params: { include_quarantined: includeQuarantined },
    });
    return res.data;
  },
  storeMemory: async (payload) => {
    const res = await api.post('/api/v1/memory/store', payload);
    return res.data;
  },
};

// ─── Audit & Hash Chain Ledger (Week 6) ───────────────────────────────────────
export const auditApi = {
  getSummary: async (tenantId = null) => {
    const res = await api.get('/api/v1/audit/summary', { params: { tenant_id: tenantId } });
    return res.data;
  },
  getAuditLogs: async (params = {}) => {
    // params: { tenant_id, event_type, severity, limit, offset }
    const res = await api.get('/api/v1/audit/logs', { params });
    return res.data;
  },
  getEvents: async (tenantId, minRiskScore = null) => {
    const res = await api.get('/api/v1/audit/events', {
      params: { tenant_id: tenantId, min_risk_score: minRiskScore },
    });
    return res.data;
  },
  verifyHashChain: async () => {
    const res = await api.get('/api/v1/audit/verify');
    return res.data;
  },
  getAlerts: async (isResolved = false, limit = 50) => {
    const res = await api.get('/api/v1/audit/alerts', {
      params: { is_resolved: isResolved, limit },
    });
    return res.data;
  },
  resolveAlert: async (alertId, resolutionNotes) => {
    const res = await api.put(`/api/v1/audit/alerts/${alertId}/resolve`, {
      resolution_notes: resolutionNotes,
    });
    return res.data;
  },
};

// ─── Policy & Rules Manager (Weeks 4 & 5) ─────────────────────────────────────
export const policyApi = {
  getPolicies: async (params = {}) => {
    const res = await api.get('/api/v1/admin/policies', { params });
    return res.data;
  },
  createPolicy: async (payload) => {
    const res = await api.post('/api/v1/admin/policies', payload);
    return res.data;
  },
  updatePolicy: async (policyId, payload) => {
    const res = await api.put(`/api/v1/admin/policies/${policyId}`, payload);
    return res.data;
  },
  deletePolicy: async (policyId) => {
    const res = await api.delete(`/api/v1/admin/policies/${policyId}`);
    return res.data;
  },
  evaluatePolicy: async (payload) => {
    const res = await api.post('/api/v1/admin/policies/evaluate', payload);
    return res.data;
  },
  getRules: async (tenantId) => {
    const res = await api.get(`/api/v1/rules/${tenantId}`);
    return res.data;
  },
  createRule: async (payload) => {
    const res = await api.post('/api/v1/rules', payload);
    return res.data;
  },
};

export default api;
