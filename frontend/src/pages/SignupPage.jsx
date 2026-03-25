import { useNavigate } from "react-router-dom";
import AuthForm from "../components/AuthForm";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";

export default function SignupPage() {
  const { signup, isLoadingAuth } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();

  async function handleSignup({ email, password }) {
    await signup({ email, password });
    showToast("Account created successfully.", "success");
    navigate("/", { replace: true });
  }

  return (
    <section className="flex min-h-[72vh] items-center justify-center">
      <AuthForm mode="signup" onSubmit={handleSignup} isLoading={isLoadingAuth} />
    </section>
  );
}
