import { api } from "./api";
import { useState } from "react";
import { Button, Card, Field, Input, Notice } from "./ui";

export default function TlsBridgeEditor() {
  const [transport, setTransport] = useState<"tls" | "wss" | "quic">("tls");
  const [hostname, setHostname] = useState("");
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("443");
  const [cert, setCert] = useState("/etc/bproto/tls/fullchain.pem");
  const [key, setKey] = useState("/etc/bproto/tls/privkey.pem");
  const [fallback, setFallback] = useState("/var/www/bproto/index.html");
  const [token, setToken] = useState("");
  const [ca, setCa] = useState("");
  const [nativeUri, setNativeUri] = useState("");
  const [exportError, setExportError] = useState("");
  const [agentStatus, setAgentStatus] = useState("");
  const [agentBusy, setAgentBusy] = useState(false);
  async function agent(action: "apply" | "health" | "rollback") {
    setAgentBusy(true);
    try {
      const config = {hostname, token, listen_host: "0.0.0.0", listen_port: Number(port),
        cert, key, fallback_file: fallback, upstream_host: "127.0.0.1", upstream_port: 4443};
      const result = await api.configAgent(action, action === "apply" ? config : undefined);
      setAgentStatus(result.status);
    } catch (error) { setAgentStatus(error instanceof Error ? error.message : "Agent failed"); }
    finally { setAgentBusy(false); }
  }
  function download(mode: "server" | "client") {
    const shared = { hostname, token };
    const tlsConfig = mode === "server"
      ? { ...shared, listen_host: "0.0.0.0", listen_port: Number(port), cert, key,
          fallback_file: fallback, upstream_host: "127.0.0.1", upstream_port: 4443 }
      : { ...shared, server_host: address || hostname, server_port: Number(port),
          local_port: 14443, ...(ca ? { ca } : {}) };
    const config = transport === "tls" ? tlsConfig : mode === "server"
      ? {listen_host: "0.0.0.0", listen_port: Number(port), cert, key, path: "/bproto",
          fallback_file: fallback, upstream_host: "127.0.0.1", upstream_port: 4443, token_env: "BPROTO_BRIDGE_TOKEN"}
      : {url: `wss://${hostname}:${port}/bproto`, local_port: 14443,
          token_env: "BPROTO_BRIDGE_TOKEN", ...(ca ? {ca} : {})};
    const output = transport !== "quic" ? config : mode === "server"
      ? {listen_host: "0.0.0.0", listen_port: Number(port), hostname, cert, key,
          fallback_file: fallback, upstream_host: "127.0.0.1", upstream_port: 4443, token_env: "BPROTO_BRIDGE_TOKEN"}
      : {server_host: address || hostname, server_port: Number(port), hostname,
          local_port: 14443, token_env: "BPROTO_BRIDGE_TOKEN", ...(ca ? {ca} : {})};
    const url = URL.createObjectURL(new Blob([JSON.stringify(output, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = transport + "-" + mode + ".json"; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function androidExport() {
    try {
      if (!nativeUri.startsWith("bproto://import/")) throw new Error("Expected bproto import URI");
      const encoded = nativeUri.slice("bproto://import/".length).replace(/-/g, "+").replace(/_/g, "/");
      const config = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded), c => c.charCodeAt(0))));
      if (config.v !== 1 || !/^[a-fA-F0-9]{64}$/.test(config.psk) || !/^[a-fA-F0-9]{64}$/.test(config.tag_key)) throw new Error("Invalid native profile");
      delete config.tls;
      delete config.wss;
      delete config.quic;
      if (transport === "tls") config.tls = { hostname, server_host: address || hostname, server_port: Number(port), token };
      else if (transport === "quic") config.quic = {hostname, server_host: address || hostname, server_port: Number(port), token};
      else config.wss = {url: `wss://${hostname}:${port}/bproto`, token};
      const bytes = new TextEncoder().encode(JSON.stringify(config));
      const uri = "bproto://import/" + btoa(Array.from(bytes, x => String.fromCharCode(x)).join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const url = URL.createObjectURL(new Blob([uri], { type: "text/plain" }));
      const link = document.createElement("a");
      link.href = url; link.download = "bproto-android-" + transport + ".txt"; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setExportError("");
    } catch { setExportError("Invalid bProto import key / Некорректный ключ"); }
  }
  const valid = /^[a-zA-Z0-9.-]+$/.test(hostname) && Number.isInteger(Number(port))
    && Number(port) > 0 && Number(port) <= 65535 && /^[a-f0-9]{64}$/.test(token)
    && !!cert && !!key && !!fallback;
  return <Card title="TLS 1.3 · экспериментальный транспорт / Experimental transport">
    <div className="space-y-3">
      <Notice>Конструктор конфигурации: экспорт не применяет настройки на сервере.
        TLS/WSS проверяют сертификат. Android QUIC экспериментальный; ECH пока отсутствует. Обход белых списков не гарантируется.
        Используйте собственный домен и сертификат. / Use an owned domain and certificate.</Notice>
      <Field label="Transport"><select value={transport} onChange={e => setTransport(e.target.value as "tls" | "wss" | "quic")}>
        <option value="tls">TLS 1.3</option><option value="wss">WebSocket over TLS</option><option value="quic">QUIC / HTTP3</option>
      </select></Field>
      <Field label="Домен сертификата / Certificate hostname"><Input value={hostname} onChange={e => setHostname(e.target.value)} placeholder="vpn.example.com" /></Field>
      <Field label="Адрес сервера / Server address"><Input disabled={transport === "wss"} value={address} onChange={e => setAddress(e.target.value)} placeholder="Default: hostname" /></Field>
      <Field label={transport === "quic" ? "UDP port" : "TCP port"}><Input type="number" min={1} max={65535} value={port} onChange={e => setPort(e.target.value)} /></Field>
      <Field label="Certificate chain path"><Input value={cert} onChange={e => setCert(e.target.value)} /></Field>
      <Field label="Private key path"><Input value={key} onChange={e => setKey(e.target.value)} /></Field>
      <Field label="Fallback HTML path"><Input value={fallback} onChange={e => setFallback(e.target.value)} /></Field>
      <Field label="Client CA path (optional; empty = system trust)"><Input value={ca} onChange={e => setCa(e.target.value)} /></Field>
      <Field label="Bridge token (64 hex characters)"><Input type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /></Field>
      <Button onClick={() => setToken(Array.from(crypto.getRandomValues(new Uint8Array(32)), x => x.toString(16).padStart(2, "0")).join(""))}>Создать токен / Generate token</Button>
      <p className="text-sm">Android-ключ и TLS JSON содержат токен. Для WSS/QUIC JSON задайте этот токен в BPROTO_BRIDGE_TOKEN на клиенте и сервере. Храните секреты с правами 600.</p>
      <Field label="Existing bProto import key / Ключ bProto для Android"><Input type="password" autoComplete="off" value={nativeUri} onChange={e => setNativeUri(e.target.value)} /></Field>
      <Button disabled={!valid || !nativeUri || !!ca} onClick={androidExport}>Android {transport.toUpperCase()} import key</Button>
      <p className="text-sm">Android TLS/WSS используют системные CA; QUIC — встроенные Mozilla roots. Импорт частного CA для Android здесь не поддерживается.</p>
      {exportError && <p role="alert">{exportError}</p>}
      <p className="text-sm">Применение перезапускает настроенный TLS-сервис и прерывает его подключения. Агент и mTLS настраиваются оператором заранее. Эта кнопка применяет только TLS-конфигурацию; WSS/QUIC экспортируются отдельно.</p>
      <Button disabled={!valid || agentBusy || transport !== "tls"} onClick={() => void agent("apply")}>Применить на сервере / Apply</Button>{" "}
      <Button disabled={agentBusy} onClick={() => void agent("health")}>Health</Button>{" "}
      <Button disabled={agentBusy} onClick={() => void agent("rollback")}>Rollback</Button>
      <p role="status">{agentStatus}</p>
      <Button disabled={!valid} onClick={() => download("server")}>Server JSON</Button>{" "}
      <Button disabled={!valid} onClick={() => download("client")}>Client JSON</Button>
    </div>
  </Card>;
}
