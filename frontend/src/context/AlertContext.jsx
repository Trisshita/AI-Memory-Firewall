import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { auditApi } from '../services/api';

const AlertContext = createContext(null);

export const AlertProvider = ({ children }) => {
  const [alerts, setAlerts] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [toasts, setToasts] = useState([]);
  const [isChainValid, setIsChainValid] = useState(true);

  const addToast = useCallback((toast) => {
    // toast: { id, type: 'error' | 'warning' | 'info' | 'success', title, message, duration }
    const id = toast.id || Date.now() + Math.random().toString();
    const duration = toast.duration || 5000;

    setToasts((prev) => [...prev, { ...toast, id }]);

    if (duration > 0) {
      setTimeout(() => {
        removeToast(id);
      }, duration);
    }
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const data = await auditApi.getAlerts(false, 20);
      const items = data.alerts || data.items || [];
      setAlerts(items);
      setUnreadCount(items.length);
    } catch (err) {
      // Background poll failure is silent
    }
  }, []);

  const checkChainStatus = useCallback(async () => {
    try {
      const result = await auditApi.verifyHashChain();
      setIsChainValid(result.is_valid);
      if (!result.is_valid) {
        addToast({
          type: 'error',
          title: '🚨 Cryptographic Hash Chain Tampered!',
          message: `Chain sequence break detected at seq #${result.first_broken_sequence || result.broken_at_sequence || 1}. Investigate immediately!`,
          duration: 10000,
        });
      }
    } catch (err) {
      // Ignore initial connectivity errors
    }
  }, [addToast]);

  useEffect(() => {
    fetchAlerts();
    checkChainStatus();
    const interval = setInterval(() => {
      fetchAlerts();
    }, 6000);
    return () => clearInterval(interval);
  }, [fetchAlerts, checkChainStatus]);

  const resolveAlert = async (alertId, notes = 'Resolved via Security Dashboard') => {
    try {
      await auditApi.resolveAlert(alertId, notes);
      setAlerts((prev) => prev.filter((a) => a.id !== alertId));
      setUnreadCount((prev) => Math.max(0, prev - 1));
      addToast({
        type: 'success',
        title: 'Alert Resolved',
        message: 'Security incident marked as resolved in ledger.',
      });
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to Resolve Alert',
        message: err.response?.data?.detail || err.message,
      });
    }
  };

  return (
    <AlertContext.Provider
      value={{
        alerts,
        unreadCount,
        toasts,
        isChainValid,
        fetchAlerts,
        checkChainStatus,
        resolveAlert,
        addToast,
        removeToast,
      }}
    >
      {children}
    </AlertContext.Provider>
  );
};

export const useAlerts = () => useContext(AlertContext);
