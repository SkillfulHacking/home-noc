import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { ApiError } from "../lib/api";
import { logout } from "../lib/session";

export default function LogoutPage() {
  const [done, setDone] = useState(false);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;

    // Do not claim that logout succeeded if the backend could not
    // confirm server-side revocation. An expired session (401) is
    // already invalid and can safely be treated as signed out.
    void logout().then(
      () => {
        if (active) setDone(true);
      },
      (reason: unknown) => {
        if (!active) return;

        if (reason instanceof ApiError && reason.status === 401) {
          setDone(true);
        } else {
          setError(true);
        }
      }
    );

    return () => {
      active = false;
    };
  }, [attempt]);

  if (done) return <Navigate to="/login" replace />;

  return (
    <main id="app" className="mx-auto max-w-lg p-4">
      <h1 className="text-2xl font-semibold mb-4">Signing out…</h1>
      {error ? (
        <>
          <p role="alert">
            Sign-out could not be verified. Your session may still be
            active on the server.
          </p>
          <button
            type="button"
            onClick={() => {
              setError(false);
              setAttempt((previous) => previous + 1);
            }}
          >
            Retry sign-out
          </button>
        </>
      ) : (
        <p>Revoking your session.</p>
      )}
    </main>
  );
}
