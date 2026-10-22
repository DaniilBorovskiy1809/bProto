import { useEffect, useState } from "react";
import { api, hasToken, setToken, setUnauthorizedHandler, type Me } from "./api";
import Clients from "./pages/Clients";
import Dashboard from "./pages/Dashboard";
import Inbounds from "./pages/Inbounds";
import Login from "./pages/Login";
import Settings from "./pages/Settings";
import Subscriptions from "./pages/Subscriptions";

type Page = "dashboard" | "inbounds" | "clients" | "subscriptions" | "settings";

const NAV: { id: Page; label: string; hint: string }[] = [
  { id: "dashboard", label: "Dashboard", hint: "Traffic, clients, sessions" },
  { id: "inbounds", label: "Inbounds", hint: "Endpoints and their clients" },
  { id: "clients", label: "Clients", hint: "Users, devices, limits" },
  { id: "subscriptions", label: "Subscriptions", hint: "Sub links and remote sources" },
  { id: "settings", label: "Settings", hint: "Password, admins, audit" },
];

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState(hasToken());
  const [page, setPage] = useState<Page>("dashboard");

  // A rejected token (expired session, password change) drops us back to login.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setToken(null);
      setMe(null);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  useEffect(() => {
    if (!hasToken()) {
      setChecking(false);
      return;
    }
    api
      .me()
      .then(setMe)
      .catch(() => setToken(null))
      .finally(() => setChecking(false));
  }, []);

  useEffect(() => {
    document.title = me ? `bUI · ${page}` : "bUI";
  }, [me, page]);

  if (checking) {
    return <div className="p-8 text-sm text-neutral-500">Loading panel…</div>;
  }

  if (!me) {
    return (
      <Login
        onLogin={() => {
          void api.me().then(setMe);
        }}
      />
    );
  }

  return (
    <div className="flex min-h-screen flex-col bg-neutral-50 text-neutral-900 md:flex-row">
      <aside className="border-b border-neutral-200 bg-white md:w-60 md:shrink-0 md:border-b-0 md:border-r">
        <div className="flex items-center justify-between px-4 py-4">
          <div>
            <p className="text-xl font-semibold tracking-tight">bUI</p>
            <p className="text-xs text-neutral-500">bProto control panel</p>
          </div>
          <span className="text-xs text-neutral-400 md:hidden">{me.username}</span>
        </div>
        <nav aria-label="Sections" className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:px-2">
          {NAV.map((item) => {
            const active = item.id === page;
            return (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                aria-current={active ? "page" : undefined}
                className={`shrink-0 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                  active
                    ? "bg-neutral-900 text-white"
                    : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900"
                }`}
              >
                <span className="block font-medium">{item.label}</span>
                <span
                  className={`hidden text-xs md:block ${active ? "text-neutral-300" : "text-neutral-400"}`}
                >
                  {item.hint}
                </span>
              </button>
            );
          })}
        </nav>
        <div className="hidden items-center justify-between gap-2 border-t border-neutral-200 px-4 py-3 md:flex">
          <span className="truncate text-sm text-neutral-600" title={me.username}>
            {me.username}
          </span>
          <button
            className="text-xs text-neutral-500 hover:text-neutral-900"
            onClick={async () => {
              try {
                await api.logout();
              } finally {
                setToken(null);
                setMe(null);
              }
            }}
          >
            Sign out
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1 p-4 md:p-6">
        {page === "dashboard" && <Dashboard />}
        {page === "inbounds" && <Inbounds />}
        {page === "clients" && <Clients />}
        {page === "subscriptions" && <Subscriptions />}
        {page === "settings" && <Settings username={me.username} />}
        <footer className="mt-8 flex flex-wrap items-center justify-between gap-2 border-t border-neutral-200 pt-3 text-xs text-neutral-400 md:hidden">
          <span>{me.username}</span>
          <button
            className="hover:text-neutral-900"
            onClick={async () => {
              try {
                await api.logout();
              } finally {
                setToken(null);
                setMe(null);
              }
            }}
          >
            Sign out
          </button>
        </footer>
      </main>
    </div>
  );
}
