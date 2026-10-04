import React, { createContext, useContext, useState, useEffect } from 'react';
import { authApi } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('firewall_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem('firewall_access_token'));
  const [loading, setLoading] = useState(true);
  const [activeTenantId, setActiveTenantId] = useState(() => {
    const saved = localStorage.getItem('firewall_tenant_id');
    return saved || 'e8869819-cc43-4aae-8789-5f7c1228be4a';
  });

  useEffect(() => {
    const checkAuth = async () => {
      const storedToken = localStorage.getItem('firewall_access_token');
      if (storedToken) {
        try {
          const userData = await authApi.getMe();
          setUser(userData);
          if (userData.tenant_id) {
            setActiveTenantId(userData.tenant_id);
            localStorage.setItem('firewall_tenant_id', userData.tenant_id);
          }
          localStorage.setItem('firewall_user', JSON.stringify(userData));
        } catch (err) {
          console.warn('Session expired, clearing authentication', err);
          logout();
        }
      }
      setLoading(false);
    };
    checkAuth();
  }, []);

  const login = async (email, password) => {
    const data = await authApi.login(email, password);
    const accessToken = data.access_token;
    const userData = data.user || {
      email,
      role: email.includes('admin') ? 'admin' : 'user',
      tenant_id: activeTenantId,
    };

    localStorage.setItem('firewall_access_token', accessToken);
    localStorage.setItem('firewall_user', JSON.stringify(userData));
    if (userData.tenant_id) {
      localStorage.setItem('firewall_tenant_id', userData.tenant_id);
      setActiveTenantId(userData.tenant_id);
    }

    setToken(accessToken);
    setUser(userData);
    return userData;
  };

  const register = async (email, password, role = 'user', tenantName = 'Default Org') => {
    const data = await authApi.register(email, password, role, tenantName);
    return login(email, password);
  };

  const logout = () => {
    localStorage.removeItem('firewall_access_token');
    localStorage.removeItem('firewall_user');
    setToken(null);
    setUser(null);
  };

  // Helper for demo quick-fill
  const quickLogin = async (roleType = 'admin') => {
    if (roleType === 'admin') {
      return await login('admin@firewall.com', 'AdminSecure123!');
    } else {
      return await login('doctor@acme.com', 'SecurePass123!');
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        activeTenantId,
        setActiveTenantId,
        login,
        register,
        logout,
        quickLogin,
        isAuthenticated: !!user || !!token,
        isAdmin: user?.role === 'admin' || user?.role === 'ADMIN',
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
