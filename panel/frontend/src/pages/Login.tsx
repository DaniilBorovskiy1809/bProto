import { useState, type FormEvent } from "react";
import { api, setToken } from "../api";
import { Button, ErrorBanner, Field, Input } from "../ui";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { token } = await api.login(username, password);
      setToken(token);
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-neutral-50 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-3xl font-semibold tracking-tight text-neutral-900">bUI</h1>
          <p className="mt-1 text-sm text-neutral-500">bProto control panel</p>
        </div>
        <form
          onSubmit={submit}
          className="space-y-3 rounded-lg border border-neutral-200 bg-white p-5"
        >
          <ErrorBanner error={error} onDismiss={() => setError(null)} />
          <Field label="Username">
            <Input
              value={username}
              autoComplete="username"
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
            />
          </Field>
          <Field label="Password">
            <Input
              type="password"
              value={password}
              autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </Field>
          <Button variant="primary" type="submit" className="w-full" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>
        <p className="mt-4 text-center text-xs text-neutral-500">
          Sessions live in memory and expire; put this panel behind HTTPS.
        </p>
      </div>
    </main>
  );
}
