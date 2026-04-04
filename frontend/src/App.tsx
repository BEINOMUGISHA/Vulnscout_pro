import React from 'react';
import { Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import MainLayout from './layouts/MainLayout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import ScansList from './pages/ScansList';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';
import Targets from './pages/Targets';
import NewTarget from './pages/NewTarget';
import Reports from './pages/Reports';
import ScanSchedule from './pages/ScanSchedule';
import Settings from './pages/Settings';
import Compliance from './pages/Compliance';
import ProxyHistory from './pages/ProxyHistory';
import Repeater from './pages/Repeater';
import Signup from './pages/Signup';
import { AlertToastProvider } from './components/WarRoom/AlertToastProvider';

const ProtectedRoute = () => {
  const { user, loading } = useAuth();
  if (loading) {
    return <div className="min-h-screen flex text-white items-center justify-center bg-background">Loading session...</div>;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
};

const AppRoutes = () => {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<MainLayout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/scans" element={<ScansList />} />
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/targets" element={<Targets />} />
          <Route path="/targets/new" element={<NewTarget />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/schedule" element={<ScanSchedule />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/proxy" element={<ProxyHistory />} />
          <Route path="/repeater" element={<Repeater />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
};

const App: React.FC = () => {
  return (
    <AuthProvider>
      <AlertToastProvider>
        <AppRoutes />
      </AlertToastProvider>
    </AuthProvider>
  );
};

export default App;
