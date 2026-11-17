import { useState } from "react";
import { Button, Card, Field, Input, Notice } from "./ui";

export default function TlsBridgeEditor() {
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
  function download(mode: "server" | "client") {
    const shared = { hostname, token };
    const config = mode === "server"
      ? { ...shared, listen_host: "0.0.0.0", listen_port: Number(port), cert, key,
          fallback_file: fallback, upstream_host: "127.0.0.1", upstream_port: 4443 }
      : { ...shared, server_host: address || hostname, server_port: Number(port),
          local_port: 14443, ...(ca ? { ca } : {}) };
    const url = URL.createObjectURL(new Blob([JSON.stringify(config, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = "tls-" + mode + ".json"; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function androidExport() {
    try {
      if (!nativeUri.startsWith("bproto://import/")) throw new Error("Expected bproto import URI");
      const encoded = nativeUri.slice("bproto://import/".length).replace(/-/g, "+").replace(/_/g, "/");
      const config = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded), c => c.charCodeAt(0))));
      if (config.v !== 1 || !/^[a-fA-F0-9]{64}$/.test(config.psk) || !/^[a-fA-F0-9]{64}$/.test(config.tag_key)) throw new Error("Invalid native profile");
      config.tls = { hostname, server_host: address || hostname, server_port: Number(port), token };
      const bytes = new TextEncoder().encode(JSON.stringify(config));
      const uri = "bproto://import/" + btoa(Array.from(bytes, x => String.fromCharCode(x)).join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const url = URL.createObjectURL(new Blob([uri], { type: "text/plain" }));
      const link = document.createElement("a");
      link.href = url; link.download = "bproto-android-tls.txt"; link.click();
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
        Android TLS требует Android 10+. QUIC, CDN fronting и обход белых списков пока не поддерживаются.
        Используйте собственный домен и сертификат. / Export only; no automatic deployment.</Notice>
      <Field label="Домен сертификата / Certificate hostname"><Input value={hostname} onChange={e => setHostname(e.target.value)} placeholder="vpn.example.com" /></Field>
      <Field label="Адрес сервера / Server address"><Input value={address} onChange={e => setAddress(e.target.value)} placeholder="Default: hostname" /></Field>
      <Field label="TCP port"><Input type="number" min={1} max={65535} value={port} onChange={e => setPort(e.target.value)} /></Field>
      <Field label="Certificate chain path"><Input value={cert} onChange={e => setCert(e.target.value)} /></Field>
      <Field label="Private key path"><Input value={key} onChange={e => setKey(e.target.value)} /></Field>
      <Field label="Fallback HTML path"><Input value={fallback} onChange={e => setFallback(e.target.value)} /></Field>
      <Field label="Client CA path (optional; empty = system trust)"><Input value={ca} onChange={e => setCa(e.target.value)} /></Field>
      <Field label="Bridge token (64 hex characters)"><Input type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /></Field>
      <Button onClick={() => setToken(Array.from(crypto.getRandomValues(new Uint8Array(32)), x => x.toString(16).padStart(2, "0")).join(""))}>Создать токен / Generate token</Button>
      <p className="text-sm">Токен попадёт в оба файла. Храните их с правами 600. Форма не сохраняет секрет в браузере.</p>
      <Field label="Existing bProto import key / Ключ bProto для Android"><Input type="password" autoComplete="off" value={nativeUri} onChange={e => setNativeUri(e.target.value)} /></Field>
      <Button disabled={!valid || !nativeUri || !!ca} onClick={androidExport}>Android TLS import key</Button>
      <p className="text-sm">Android использует системные CA; нестандартный CA здесь не поддерживается. / Android uses system trust.</p>
      {exportError && <p role="alert">{exportError}</p>}
      <Button disabled={!valid} onClick={() => download("server")}>Server JSON</Button>{" "}
      <Button disabled={!valid} onClick={() => download("client")}>Client JSON</Button>
    </div>
  </Card>;
}
