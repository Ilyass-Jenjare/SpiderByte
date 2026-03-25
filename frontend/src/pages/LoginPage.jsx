import { useLocation, useNavigate } from "react-router-dom";
import AuthForm from "../components/AuthForm";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";

export default function LoginPage() {
  const { login, isLoadingAuth } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const location = useLocation();

  async function handleLogin({ email, password }) {
    await login({ email, password });
    showToast("Login successful.", "success");

    const redirectTo = location.state?.from === "scan" ? "/" : "/";
    navigate(redirectTo, { replace: true });
  }

  return (
    <section className="flex min-h-[72vh] items-center justify-center">
      <AuthForm mode="login" onSubmit={handleLogin} isLoading={isLoadingAuth} />
    </section>
  );
}
