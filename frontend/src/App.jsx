import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import Navbar from "./components/Navbar";
import ProtectedRoute from "./components/ProtectedRoute";
import SiteFooter from "./components/SiteFooter";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import SignupPage from "./pages/SignupPage";
import DashboardPage from "./pages/DashboardPage";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { ScanProvider } from "./context/ScanContext";
import { ToastProvider, ToastViewport } from "./context/ToastContext";

function GuestRoute({ children }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <Navigate to="/" replace /> : children;
}

function AppShell() {
  const location = useLocation();
  const showFooter = location.pathname !== "/dashboard";

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#050505] text-zinc-100">
      <BackgroundGlow />

      <div className="relative z-10 mx-auto flex w-full max-w-7xl flex-col px-6 pb-10 pt-7 lg:px-10">
        <Navbar />

        <main className="flex-1 py-8">
          <Routes>
            <Route path="/" element={<LandingPage />} />
            <Route
              path="/login"
              element={
                <GuestRoute>
                  <LoginPage />
                </GuestRoute>
              }
            />
            <Route
              path="/signup"
              element={
                <GuestRoute>
                  <SignupPage />
                </GuestRoute>
              }
            />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <DashboardPage />
                </ProtectedRoute>
              }
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>

        {showFooter ? <SiteFooter /> : null}
      </div>

      <ToastViewport />
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <ScanProvider>
            <AppShell />
          </ScanProvider>
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  );
}

function BackgroundGlow() {
  return (
    <>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_20%_0%,rgba(250,204,21,0.2),transparent_30%),radial-gradient(circle_at_95%_10%,rgba(234,179,8,0.14),transparent_28%),radial-gradient(circle_at_50%_100%,rgba(255,255,255,0.06),transparent_35%)]" />
      <div className="pointer-events-none absolute -top-56 left-1/2 h-[34rem] w-[34rem] -translate-x-1/2 rounded-full bg-yellow-500/10 blur-3xl" />
    </>
  );
}

export default App;
