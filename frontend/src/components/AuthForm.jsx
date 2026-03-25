import { useState } from "react";
import { Link } from "react-router-dom";

export default function AuthForm({ mode, onSubmit, isLoading }) {
  const isSignup = mode === "signup";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    if (!email.trim() || !password.trim()) {
      setError("Email and password are required.");
      return;
    }

    if (isSignup && password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      await onSubmit({ email, password, confirmPassword });
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Authentication failed.");
    }
  }

  return (
    <article className="glass-panel soft-ring mx-auto w-full max-w-md rounded-3xl p-6 sm:p-7">
      <h1 className="text-2xl font-semibold text-white">{isSignup ? "Create your account" : "Welcome back"}</h1>
      <p className="mt-2 text-sm text-zinc-400">
        {isSignup
          ? "Create an account to start scans and access your dashboard."
          : "Log in to launch scans and view vulnerability results."}
      </p>

      <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
        <div>
          <label htmlFor="auth-email" className="mb-2 block text-sm text-zinc-300">
            Email
          </label>
          <input
            id="auth-email"
            type="email"
            className="input-dark"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@company.com"
          />
        </div>

        <div>
          <label htmlFor="auth-password" className="mb-2 block text-sm text-zinc-300">
            Password
          </label>
          <input
            id="auth-password"
            type="password"
            className="input-dark"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="********"
          />
        </div>

        {isSignup ? (
          <div>
            <label htmlFor="auth-confirm" className="mb-2 block text-sm text-zinc-300">
              Confirm password
            </label>
            <input
              id="auth-confirm"
              type="password"
              className="input-dark"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              placeholder="********"
            />
          </div>
        ) : null}

        {error ? <p className="rounded-lg border border-red-400/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</p> : null}

        <button type="submit" className="accent-button w-full py-3" disabled={isLoading}>
          {isLoading ? "Please wait..." : isSignup ? "Register" : "Login"}
        </button>
      </form>

      <p className="mt-4 text-center text-sm text-zinc-400">
        {isSignup ? "Already have an account?" : "No account yet?"}{" "}
        <Link className="font-medium text-yellow-300 transition hover:text-yellow-200" to={isSignup ? "/login" : "/signup"}>
          {isSignup ? "Login" : "Sign up"}
        </Link>
      </p>
    </article>
  );
}
