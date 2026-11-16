import { useState } from "react";
import { api, type RoutingPolicy } from "./api";
import { Button, Card, ErrorBanner, Field, Notice, useAction, useLoader } from "./ui";

const defaults: RoutingPolicy = { routes: ["0.0.0.0/0"], dns: ["1.1.1.1"], bypass_apps: [] };
const lines = (value: string) => value.split(/\r?\n/).map(v => v.trim()).filter(Boolean);

export default function RoutingEditor() {
  const settings = useLoader(() => api.subSettings());
  const [draft, setDraft] = useState<RoutingPolicy | null>(null);
  const [saved, setSaved] = useState(false);
  const action = useAction(async () => { await settings.reload(); setDraft(null); setSaved(true); });
  const policy = draft ?? settings.data?.routing ?? defaults;
  const fields = [
    ["routes", "Tunnel IPv4 routes", "One network CIDR per line. Default: all IPv4 traffic."],
    ["dns", "DNS resolvers", "One IPv4 address per line."],
    ["bypass_apps", "Android apps outside VPN", "One package name per line. These apps use the ordinary connection."],
  ] as const;
  return <Card title="Subscription routing">
    <Notice>Rules are included in JSON subscriptions. Base64 and URI lists carry server keys only. Domain routing and transport disguise are not supported by these rules.</Notice>
    <ErrorBanner error={settings.error ?? action.error} />
    <form className="mt-4 grid gap-4" onSubmit={event => { event.preventDefault(); void action.run(() => api.updateSubSettings({ routing: policy })); }}>
      {fields.map(([key, label, hint]) => <Field key={key} label={label} hint={hint}>
        <textarea className="w-full rounded-lg border border-neutral-200 bg-white p-3 font-mono text-sm" rows={4}
          value={policy[key].join("\n")} disabled={!settings.data || action.busy}
          onChange={event => { setSaved(false); setDraft({ ...policy, [key]: lines(event.target.value) }); }} />
      </Field>)}
      <div className="flex items-center gap-3"><Button type="submit" variant="primary" disabled={!settings.data || action.busy}>{action.busy ? "Saving…" : "Save routing"}</Button>
        {saved && <span role="status" className="text-sm text-emerald-700">Saved. Refresh the subscription in your client.</span>}</div>
    </form>
  </Card>;
}
