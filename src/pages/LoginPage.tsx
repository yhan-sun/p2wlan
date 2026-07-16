import { useState } from "react";

interface LoginPageProps {
  onLogin: (token: string) => void;
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isRegister, setIsRegister] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      const endpoint = isRegister
        ? "http://localhost:8080/api/v1/register"
        : "http://localhost:8080/api/v1/login";

      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (data.success && data.token) {
        localStorage.setItem("token", data.token);
        onLogin(data.token);
      } else {
        setError(data.error || "Authentication failed");
      }
    } catch {
      setError("Cannot connect to server");
    }
  };

  return (
    <div className="login-page">
      <div className="card login-card">
        <h1 className="login-title">P2PNet</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              className="form-input"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@example.com"
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              className="form-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>
          {error && (
            <p style={{ color: "var(--danger)", fontSize: "0.875rem", marginBottom: "1rem" }}>
              {error}
            </p>
          )}
          <button className="btn btn-primary" type="submit" style={{ width: "100%" }}>
            {isRegister ? "Register" : "Login"}
          </button>
          <p style={{ textAlign: "center", marginTop: "1rem", fontSize: "0.875rem", color: "var(--text-secondary)" }}>
            {isRegister ? "Already have an account?" : "Don't have an account?"}{" "}
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => setIsRegister(!isRegister)}
              style={{ padding: 0, fontSize: "0.875rem" }}
            >
              {isRegister ? "Login" : "Register"}
            </button>
          </p>
        </form>
      </div>
    </div>
  );
}
