import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AlertProvider } from './context/AlertContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { AlertToast } from './components/AlertToast';

import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { GatewayPlaygroundPage } from './pages/GatewayPlaygroundPage';
import { MemoriesPage } from './pages/MemoriesPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { PolicyManagerPage } from './pages/PolicyManagerPage';
import { AlertsPage } from './pages/AlertsPage';

// Protected Route Guard
const ProtectedLayout = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--cyan)',
          fontSize: '1.125rem',
          fontFamily: 'var(--font-heading)',
          gap: 12,
        }}
      >
        <span>Initializing Security Gateway...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <Navbar />
        {children}
      </div>
      <AlertToast />
    </div>
  );
};

export const App = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AlertProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            <Route
              path="/"
              element={
                <ProtectedLayout>
                  <DashboardPage />
                </ProtectedLayout>
              }
            />
            <Route
              path="/playground"
              element={
                <ProtectedLayout>
                  <GatewayPlaygroundPage />
                </ProtectedLayout>
              }
            />
            <Route
              path="/memories"
              element={
                <ProtectedLayout>
                  <MemoriesPage />
                </ProtectedLayout>
              }
            />
            <Route
              path="/audit"
              element={
                <ProtectedLayout>
                  <AuditLogsPage />
                </ProtectedLayout>
              }
            />
            <Route
              path="/policies"
              element={
                <ProtectedLayout>
                  <PolicyManagerPage />
                </ProtectedLayout>
              }
            />
            <Route
              path="/alerts"
              element={
                <ProtectedLayout>
                  <AlertsPage />
                </ProtectedLayout>
              }
            />

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AlertProvider>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
