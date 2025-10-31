import { useEffect } from "react";
import { clearAuth } from "../lib/auth";

export default function LogoutPage() {
  useEffect(() => {
    clearAuth();
    // quick visual hint then redirect:
    const t = setTimeout(() => (window.location.href = "/login"), 300);
    return () => clearTimeout(t);
  }, []);
  return (
    <main id="app" className="mx-auto max-w-lg p-4">
      <h1 className="text-2xl font-semibold mb-4">Logged out</h1>
      <p>Cleared saved credentials. Redirecting to Login…</p>
    </main>
  );
}
