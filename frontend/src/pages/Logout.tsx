import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { logout } from "../lib/session";

export default function LogoutPage() {
  const [done, setDone] = useState(false);

  useEffect(() => {
    let active = true;
    // Revokes the session server-side; clearing the local cache alone would
    // leave the cookie usable.
    // logout() clears the local cache even on failure; swallow the error so
    // an expired session (401) does not become an unhandled rejection.
    logout()
      .catch(() => undefined)
      .then(() => {
        if (active) setDone(true);
      });
    return () => {
      active = false;
    };
  }, []);

  if (done) return <Navigate to="/login" replace />;
  return (
    <main id="app" className="mx-auto max-w-lg p-4">
      <h1 className="text-2xl font-semibold mb-4">Signing out…</h1>
      <p>Revoking your session.</p>
    </main>
  );
}
