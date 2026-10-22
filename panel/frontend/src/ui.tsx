// Small shared UI kit: formatting helpers, primitives and the traffic chart.
// No component library — a panel this size does not need one.

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type { SeriesPoint } from "./api";

// --- formatting ------------------------------------------------------------

export function fmtBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB", "PiB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(2) : value.toFixed(1)} ${units[unit]}`;
}

/** Unlimited/never are stored as NULL and sent as 0. */
export function fmtLimit(bytes: number | null | undefined): string {
  return !bytes ? "∞" : fmtBytes(bytes);
}

export function fmtDate(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtDay(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export function fmtAgo(ts: number | null | undefined): string {
  if (!ts) return "—";
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

export function fmtUptime(secs: number | null | undefined): string {
  if (secs === null || secs === undefined) return "—";
  const days = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

/** Days until expiry, for the "expires" column. */
export function fmtExpiry(ts: number | null | undefined): string {
  if (!ts) return "never";
  const days = Math.ceil((ts - Date.now() / 1000) / 86400);
  if (days < 0) return `expired ${fmtDay(ts)}`;
  if (days === 0) return "today";
  return `${fmtDay(ts)} (${days}d)`;
}

export const GB = 1024 * 1024 * 1024;

/** GB input to bytes, where 0/empty means unlimited. */
export function gbToBytes(input: string): number {
  const value = Number.parseFloat(input);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.round(value * GB);
}

export function bytesToGbInput(bytes: number | null | undefined): string {
  if (!bytes) return "";
  return String(Math.round((bytes / GB) * 100) / 100);
}

/** `YYYY-MM-DD` to a unix timestamp, where empty means "never". */
export function dayToTs(input: string): number {
  if (!input) return 0;
  const parsed = Date.parse(`${input}T00:00:00`);
  return Number.isNaN(parsed) ? 0 : Math.floor(parsed / 1000);
}

export function tsToDayInput(ts: number | null | undefined): string {
  if (!ts) return "";
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

// --- primitives ------------------------------------------------------------

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md";
};

export function Button({ variant = "secondary", size = "md", className = "", ...rest }: ButtonProps) {
  const base =
    "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50";
  const sizes = { sm: "px-2.5 py-1 text-xs", md: "px-3 py-1.5 text-sm" };
  const variants = {
    primary: "bg-neutral-900 text-white hover:bg-neutral-700",
    secondary: "border border-neutral-300 bg-white text-neutral-800 hover:bg-neutral-100",
    danger: "border border-red-200 bg-white text-red-700 hover:bg-red-50",
    ghost: "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900",
  };
  return <button className={`${base} ${sizes[size]} ${variants[variant]} ${className}`} {...rest} />;
}

export function Field({
  label,
  hint,
  children,
  className = "",
}: {
  label: string;
  hint?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={`block ${className}`}>
      <span className="mb-1 block text-xs font-medium text-neutral-600">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-neutral-500">{hint}</span>}
    </label>
  );
}

const inputClass =
  "w-full rounded-md border border-neutral-300 bg-white px-2.5 py-1.5 text-sm text-neutral-900 placeholder:text-neutral-400 focus:border-neutral-500 focus:outline-none focus:ring-1 focus:ring-neutral-500";

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const { className = "", ...rest } = props;
  return <input className={`${inputClass} ${className}`} {...rest} />;
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  const { className = "", ...rest } = props;
  return <select className={`${inputClass} ${className}`} {...rest} />;
}

export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { className = "", ...rest } = props;
  return <textarea className={`${inputClass} ${className}`} {...rest} />;
}

export function Card({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lg border border-neutral-200 bg-white ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-neutral-200 px-4 py-3">
          <h2 className="text-sm font-semibold text-neutral-800">{title}</h2>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

type Tone = "ok" | "warn" | "bad" | "neutral" | "info";

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  const tones: Record<Tone, string> = {
    ok: "border-emerald-200 bg-emerald-50 text-emerald-700",
    warn: "border-amber-200 bg-amber-50 text-amber-700",
    bad: "border-red-200 bg-red-50 text-red-700",
    info: "border-sky-200 bg-sky-50 text-sky-700",
    neutral: "border-neutral-200 bg-neutral-50 text-neutral-600",
  };
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function statusTone(status: string): Tone {
  if (status === "active") return "ok";
  if (status === "disabled") return "warn";
  if (status === "revoked") return "bad";
  return "neutral";
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[32rem] border-collapse text-sm">{children}</table>
    </div>
  );
}

export function Th({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return (
    <th
      scope="col"
      className={`border-b border-neutral-200 px-3 py-2 text-left text-xs font-medium uppercase tracking-wide text-neutral-500 ${className}`}
    >
      {children}
    </th>
  );
}

export function Td({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return (
    <td className={`border-b border-neutral-100 px-3 py-2 align-middle text-neutral-700 ${className}`}>
      {children}
    </td>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="px-3 py-6 text-center text-sm text-neutral-500">{children}</p>;
}

export function ErrorBanner({ error, onDismiss }: { error: string | null; onDismiss?: () => void }) {
  if (!error) return null;
  return (
    <div
      role="alert"
      className="mb-4 flex items-start justify-between gap-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
    >
      <span className="break-words">{error}</span>
      {onDismiss && (
        <button className="text-red-700 hover:text-red-900" onClick={onDismiss} aria-label="Dismiss">
          ×
        </button>
      )}
    </div>
  );
}

export function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-md border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs leading-relaxed text-neutral-600">
      {children}
    </p>
  );
}

export function Modal({
  title,
  onClose,
  children,
  footer,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-neutral-900/40 p-4 sm:p-8">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`mt-8 w-full rounded-lg border border-neutral-200 bg-white shadow-lg ${wide ? "max-w-3xl" : "max-w-lg"}`}
      >
        <header className="flex items-center justify-between border-b border-neutral-200 px-4 py-3">
          <h2 className="text-sm font-semibold text-neutral-800">{title}</h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded px-2 text-lg leading-none text-neutral-500 hover:bg-neutral-100 hover:text-neutral-900"
          >
            ×
          </button>
        </header>
        <div className="space-y-3 px-4 py-4">{children}</div>
        {footer && (
          <footer className="flex justify-end gap-2 border-t border-neutral-200 px-4 py-3">{footer}</footer>
        )}
      </div>
    </div>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? "Copied" : label}
    </Button>
  );
}

export function QrCode({ svg }: { svg: string }) {
  return (
    <div
      className="w-fit rounded border border-neutral-200 bg-white p-2"
      // The only HTML we inject is the QR SVG the panel itself generated.
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}

// --- data loading ----------------------------------------------------------

/** Load something, with loading/error state and a manual reload. */
export function useLoader<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const loadRef = useRef(load);
  loadRef.current = load;

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await loadRef.current());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, setError };
}

/** Run an action, surfacing its error and reloading on success. */
export function useAction(reload?: () => void | Promise<void>) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(
    async (fn: () => Promise<unknown>) => {
      setBusy(true);
      setError(null);
      try {
        const result = await fn();
        await reload?.();
        return result;
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [reload],
  );

  return { run, busy, error, setError };
}

// --- chart -----------------------------------------------------------------

/** Hourly rx/tx bars for the last 24 hours, drawn as plain SVG. */
export function TrafficChart({ series }: { series: SeriesPoint[] }) {
  const max = Math.max(1, ...series.map((p) => Math.max(p.rx, p.tx)));
  const total = series.reduce((acc, p) => acc + p.rx + p.tx, 0);

  if (total === 0) {
    return (
      <p className="py-10 text-center text-sm text-neutral-500">
        No traffic in the last 24 hours. Servers add to it by posting to{" "}
        <code>/internal/v1/sessions/report</code>.
      </p>
    );
  }

  return (
    <figure className="space-y-2">
      <div
        role="img"
        aria-label={`Traffic per hour for the last 24 hours, ${fmtBytes(total)} in total`}
        className="flex h-40 items-end gap-1"
      >
        {series.map((point) => {
          const rx = (point.rx / max) * 100;
          const tx = (point.tx / max) * 100;
          const hour = new Date(point.ts * 1000).getHours().toString().padStart(2, "0");
          return (
            <div
              key={point.ts}
              className="group flex h-full flex-1 flex-col items-center justify-end gap-px"
              title={`${hour}:00 — ↑ ${fmtBytes(point.rx)} / ↓ ${fmtBytes(point.tx)}`}
            >
              <div className="flex h-full w-full items-end gap-px">
                <div
                  className="flex-1 rounded-t bg-neutral-900/80 group-hover:bg-neutral-900"
                  style={{ height: `${Math.max(rx, point.rx > 0 ? 2 : 0)}%` }}
                />
                <div
                  className="flex-1 rounded-t bg-neutral-300 group-hover:bg-neutral-400"
                  style={{ height: `${Math.max(tx, point.tx > 0 ? 2 : 0)}%` }}
                />
              </div>
              <span className="hidden text-[10px] text-neutral-400 sm:block">{hour}</span>
            </div>
          );
        })}
      </div>
      <figcaption className="flex items-center gap-4 text-xs text-neutral-500">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm bg-neutral-900/80" /> up (client → server)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm bg-neutral-300" /> down (server → client)
        </span>
        <span className="ml-auto">peak {fmtBytes(max)}/h</span>
      </figcaption>
      <details>
        <summary className="cursor-pointer text-xs text-neutral-500">Numbers</summary>
        <table className="mt-2 w-full text-xs text-neutral-600">
          <thead>
            <tr>
              <th className="text-left font-medium">hour</th>
              <th className="text-right font-medium">up</th>
              <th className="text-right font-medium">down</th>
            </tr>
          </thead>
          <tbody>
            {series.map((point) => (
              <tr key={point.ts}>
                <td>{new Date(point.ts * 1000).toLocaleString([], { hour: "2-digit", day: "2-digit", month: "2-digit" })}</td>
                <td className="text-right">{fmtBytes(point.rx)}</td>
                <td className="text-right">{fmtBytes(point.tx)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

export function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-neutral-200 bg-white px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">{label}</p>
      <p className="mt-1 text-xl font-semibold text-neutral-900">{value}</p>
      {hint && <p className="mt-0.5 text-xs text-neutral-500">{hint}</p>}
    </div>
  );
}
