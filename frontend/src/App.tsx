import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import NavBar from "./components/NavBar";
import DeviceDetailPage from "./pages/DeviceDetail";
import InventoryPage from "./pages/Inventory";
import LoginPage from "./pages/Login";
import LogoutPage from "./pages/Logout";
import OverviewPage from "./pages/Overview";
import ScanPolicyPage from "./pages/ScanPolicy";
import ScansPage from "./pages/Scans";
import { AUTH_CHANGED_EVENT, getSession } from "./lib/auth";
import { fetchSession } from "./lib/session";

type AuthState = "checking" | "authenticated" | "anonymous";

function RequireAuth({ children }: { children: JSX.Element }) {
  const [state, setState] = useState<AuthState>(() =>
    getSession() ? "authenticated" : "checking"
  );

  useEffect(() => {
    let active = true;
    // The cached flag is a hint; the backend is the authority. Probing a
    // real protected route also recovers a session that survived a reload.
    fetchSession()
      .then((session) => {
        if (active) setState(session ? "authenticated" : "anonymous");
      })
      .catch(() => {
        if (active) setState("anonymous");
      });

    const refreshAuth = () => {
      if (active && !getSession()) setState("anonymous");
    };
    window.addEventListener(AUTH_CHANGED_EVENT, refreshAuth);
    return () => {
      active = false;
      window.removeEventListener(AUTH_CHANGED_EVENT, refreshAuth);
    };
  }, []);

  // Render nothing protected until the backend has answered, so inventory
  // never flashes on screen for an unauthenticated visitor.
  if (state === "checking") {
    return (
      <main id="app" className="mx-auto max-w-6xl p-4">
        <p role="status">Checking your session…</p>
      </main>
    );
  }
  if (state === "anonymous") return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <BrowserRouter>
      <NavBar />
      <Routes>
        <Route
          path="/"
          element={
            <RequireAuth>
              <OverviewPage />
            </RequireAuth>
          }
        />
        <Route
          path="/scans"
          element={
            <RequireAuth>
              <ScansPage />
            </RequireAuth>
          }
        />
        <Route
          path="/inventory"
          element={
            <RequireAuth>
              <InventoryPage />
            </RequireAuth>
          }
        />
        <Route
          path="/inventory/:id"
          element={
            <RequireAuth>
              <DeviceDetailPage />
            </RequireAuth>
          }
        />
        <Route
          path="/settings/security/scan-policy"
          element={
            <RequireAuth>
              <ScanPolicyPage />
            </RequireAuth>
          }
        />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/logout" element={<LogoutPage />} />
      </Routes>
    </BrowserRouter>
  );
}
