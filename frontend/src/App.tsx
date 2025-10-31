import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import NavBar from "./components/NavBar";
import IndexPage from "./pages/Index";
import LoginPage from "./pages/Login";
import LogoutPage from "./pages/Logout";
import { getAuth } from "./lib/auth";

function RequireAuth({ children }: { children: JSX.Element }) {
  const authed = !!getAuth();
  if (!authed) return <Navigate to="/login" replace />;
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
              <IndexPage />
            </RequireAuth>
          }
        />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/logout" element={<LogoutPage />} />
      </Routes>
    </BrowserRouter>
  );
}
