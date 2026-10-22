# bProto — инженерный план реализации

Версия документа: 0.1 (MVP-планирование)

> **Прочитайте это перед остальным документом.**
>
> Этот план писался до реализации. Он по-прежнему описывает *замысел* и
> очерёдность работ, но три решения в нём устарели — код пошёл другим путём:
>
> 1. **Маскировка («режим B») реализована.** Не «этап 2», а рабочий код с
>    тестами: `crates/vpn-core/src/hello.rs` собирает `ClientHello`,
>    `crates/vpn-server/src/relay.rs` отправляет чужих на донора. Два варианта
>    рукопожатия кодируются из одного `ServerReply`, так что разойтись они не
>    могут.
> 2. **`craftls` не нужен и выброшен.** План предполагал форк `rustls` с патчем
>    `session_id`; вместо этого `ClientHello` собирается руками, отпечаток — это
>    данные (`HelloProfile`), а не зависимость. Никакого форка, никакого
>    отставания от security-патчей. Все упоминания `craftls` ниже — история.
> 3. **Разделение на крейты другое.** Вместо «ядра, в котором есть и протокол, и
>    транспорт»: `vpn-core` (чистый протокол, без I/O) → `vpn-rt` (один общий
>    асинхронный путь данных) → `vpn-client` и `vpn-server`. Сессия стала одним
>    типом `Endpoint` вместо клиентского и серверного вариантов.
>
> Актуальное описание того, что построено: `README.md` и `docs/PROTOCOL.md`.
> Что из этого плана ещё не сделано: FEC, живой rekey/key-update,
> пост-квантовый rekey, десктопные клиенты.

---

## Статус реализации (обновлено)

Что уже работает и покрыто тестами (см. `docs/INSTALL.md` — как это поставить):

| Слой | Состояние |
|---|---|
| Формат датаграммы, inner framing, AEAD ChaCha20-Poly1305, replay-окно | реализовано, тесты |
| Рукопожатие: `HELLO`/`HELLO_ACK`, X25519, HKDF, label-MAC с окном ±5 мин | реализовано, тесты |
| Сервер: TUN, пул адресов `10.66.0.0/24`, маршрутизация, NAT (`nft`) | реализовано |
| Клиент Linux: TUN, перехват default route с откатом | реализовано (нужен root/CAP_NET_ADMIN) |
| CUBIC, ACK-диапазоны, RTT/PTO, keepalive | реализовано, тесты |
| Панель: логин, inbounds, ключи, QR, подписки, статистика | реализовано, 37 тестов |
| `bproto import 'bproto://import/...'` (мост панель → клиент) | реализовано |
| Мобильные клиенты: C-ABI + JNI-мост, `VpnService` (Android), `NEPacketTunnelProvider` (iOS) | Android-приложение запущено end-to-end на эмуляторе (API 35): рукопожатие, аренда `tun0`, трафик через туннель; на телефоне не проверялось. iOS — только каркас, Xcode не запускался |

Осознанные отличия от плана на этапе 1:

1. **Маскировка перенесена на этап 2.** В MVP транспорт — собственная датаграмма
   с 12-байтовым заголовком, без донора. Причина: сначала рабочая и проверяемая
   крипто-сессия, потом «режим B» (QUIC-подмена + `craftls`). Конструкция метки
   уже сейчас упакована ровно в 32 байта — те самые, что пойдут в TLS
   `session_id`, поэтому переход на режим B не ломает протокол (см. §3.3 и
   `docs/PROTOCOL.md` §6).
2. **Пул адресов.** Сервер выдаёт клиенту адрес из пула (`10.66.0.2`, `.3`, …),
   а не просто маршрутизирует по тегу; при простое >45 c адрес освобождается.
3. **Идентификатор `session_tag`** выводится из обоих случайных значений
   (`cr‖sr`) через HKDF и меняется на каждой сессии.

Ещё не реализовано (явные `Error::Unimplemented`, без тихих заглушек): режим B
(донор + `craftls` ClientHello), FEC, живой rekey/key-update, пост-квантовый
rekey, а также рабочие клиенты под Windows/macOS. Android-приложение
(`apps/android`) проверено на реальном `VpnService` в эмуляторе — рукопожатие,
`tun0` с арендованным адресом и ping через туннель (3/3, на сервере
`sessions=1 unknown=0`); на телефоне оно не запускалось. iOS-провайдер
(`apps/ios`) не собирался с Xcode. Как собрать — `docs/BUILD-CLIENTS.md`.
Панель пока не пушит ключи в сервер — это один ручной шаг, описан в
`docs/INSTALL.md` §5.5.

Тот же прогон нашёл и закрыл баг уровня датапата: новая сессия создавалась с
`last_rx_us = 0`, поэтому `tick` считал её простой равным всему аптайму сервера —
любой клиент, подключившийся позже `idle_timeout` (45 c) после старта сервера,
терял сессию на ближайшем тике, и все его пакеты падали в `unknown` (туннель
поднимается и не везёт ничего). Исправлено, есть регресс-тест
(`a_fresh_session_is_not_expired_by_a_long_uptime`).

---

## 0. Резюме и два противоречия, которые нужно снять до старта

План ниже реализует зафиксированные решения. Но два из них взаимно противоречивы в текущей
формулировке — их надо снять на первом же совещании, иначе мы построим систему, у которой
маскировка и транспорт живут в разных сетевых мирах.

**Противоречие A: «UDP-транспорт» + «пересылка ClientHello на целевой сайт по TLS».**
Целевой сайт (donor) на :443 говорит либо TCP+TLS, либо UDP+QUIC. Если наш транспорт — UDP,
то «переслать рукопожатие на сайт» означает переслать его по **QUIC/HTTP-3**, а не по
TCP/TLS-record. `craftls` — это форк rustls, он умеет и то и другое, но `quinn` (наш транспортный
слой, откуда взяты CUBIC/BBR) работает только поверх QUIC.

Рекомендация: **donor обязан поддерживать HTTP/3, маскировка — под QUIC/HTTP-3.** Тогда всё
сходится: UDP end-to-end, `quinn` как транспорт, `craftls` снизу как поставщик отпечатка
ClientHello (он drop-in замена rustls, а `quinn` использует rustls). Фолбэк на TCP/TLS
(ShadowTLS-подобный) оставить как «режим B» для доноров без h3 — но не в MVP.

**Противоречие B: «минимальная надёжность = счётчик + NACK» + «CUBIC из quinn».**
CUBIC считается по ACK: он обязан знать, что пакет дошёл, чтобы расти на окне; NACK сообщает
только о потерях. На чистом NACK+CUBIC получится контроллер, который не разгоняется и
схлопывает окно по таймауту. Реально надёжность и congestion control — это одна подсистема.

Рекомендация: **реализовать QUIC-подобный ACK (диапазоны + ACK-delay), NACK оставить как
быстрый сигнал о потере вне очереди.** Это не «TCP-over-TCP»: мы не ретранслируем TCP-сегменты,
мы ACK-аем свои UDP-датаграммы. Формулировку «минимальный уровень надёжности» читаю как
«без отдельной надёжной очереди и без head-of-line blocking», а не «без ACK».

Если оба противоречия не снять — MVP будет нетранспортабельным. Дальше в плане приняты
рекомендованные варианты.

---

## 1. Общая архитектура

```
                        ┌──────────────────────────────────────────────┐
                        │                КЛИЕНТСКОЕ УСТРОЙСТВО          │
                        │                                              │
   ┌─────────────┐      │  ┌────────────┐   ┌────────────────────────┐   │
   │ ОС / apps   │◄────►│  │  TUN       │◄─►│   vpn-core (Rust)      │   │
   │ (весь трафик)│     │  │  iface     │   │  ┌──────────────────┐  │   │
   └─────────────┘      │  └────────────┘   │  │ packet  (12B hdr)│  │   │
                        │        ▲          │  │ crypto  (X25519, │  │   │
   ┌─────────────┐      │        │          │  │        ChaCha20) │  │   │
   │  GUI/Tauri  │      │  ┌─────┴───────┐  │  │ masq   (craftls) │  │   │
   │  Android UI │      │  │ FFI-обвязка │  │  │ transport (quinn)│  │   │
   └─────────────┘      │  │ JNI / C-FFI │  │  │ session (state)  │  │   │
                        │  └─────────────┘  │  └──────────────────┘  │   │
                        │        ▲          └───────────┬────────────┘   │
                        │  VpnService / NE / tun crate   │                │
                        └───────────────────────────────┼────────────────┘
                                                        │
                                    UDP:443 (QUIC-shaped)│
                                                        ▼
   ┌──────────────────────────────┐        ┌──────────────────────────────────┐
   │        ПАНЕЛЬ УПРАВЛЕНИЯ      │        │            VPS / vpn-server       │
   │  panel-backend (axum)        │  admin │  ┌────────────────────────────┐   │
   │  panel-frontend (React)      │◄──────►│  │ vpn-server (Rust)          │   │
   │  SSOT: SQLite                │  API   │  │  - QUIC listener (quinn)   │   │
   └──────────────────────────────┘  loop  │  │  - ClientHello interceptor │   │
                                          │  │  - session_id verifier     │   │
                                          │  │  - TUN + NAT (nftables)    │   │
                                          │  │  - NewSessionTicket relay  │   │
                                          │  └───────────┬────────────────┘   │
                                          └──────────────┼────────────────────┘
                                                         │ исходящее ТСP/UDP :443
                                                         ▼
                                          ┌──────────────────────────────────┐
                                          │  DONOR SITE (реальный сайт, h3)   │
                                          │  выдаёт настоящий сертификат      │
                                          └──────────────────────────────────┘
```

Где живёт `vpn-core`:

| Потребитель | Способ линковки | Артефакт |
|---|---|---|
| `vpn-server` | прямой Rust-крейт | rlib |
| Desktop (Tauri) | Rust-крейт внутри Tauri-процесса | rlib |
| Android | JNI | `libvpn_core.so` (cdylib) |
| iOS | C-FFI + Swift | `libvpn_core.a` (staticlib) |
| CLI/тесты | крейт + пример | rlib |

Ядро **не знает** про TUN и про UI. Оно умеет: `connect`, гонять буферы IP-пакетов в обе
стороны, реагировать на смену сетевого пути. Всё остальное — задача платформенной обвязки.
Такое разделение даёт возможность тестировать протокол headless в интеграционном харнессе
без TUN-устройства.

---

## 2. Структура репозитория (monorepo)

```
bProto/
├── Cargo.toml                     # workspace: members = crates/*
├── Cargo.lock                     # коммитим (бинарники сервера/клиента)
├── rust-toolchain.toml            # пин toolchain (stable, edition 2024)
├── justfile                       # единая точка входа: just build/test/lint/release
├── deny.toml                      # cargo-deny: лицензии, CVE, дубликаты
├── rustfmt.toml / clippy.toml
├── .cargo/config.toml             # RUSTFLAGS, линковка Android/iOS
│
├── crates/
│   ├── vpn-core/                  # ★ протокол (rlib + cdylib + staticlib)
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs             # публичный API + реэкспорты
│   │   │   ├── config.rs          # TunnelConfig, TunnelParams
│   │   │   ├── error.rs           # Error / Result
│   │   │   ├── packet.rs          # 12-байтовый заголовок, (де)сериализация
│   │   │   ├── crypto.rs          # X25519, ChaCha20-Poly1305, HKDF, nonce
│   │   │   ├── auth.rs            # метка в session_id (derive/verify)
│   │   │   ├── replay.rs          # anti-replay скользящее окно
│   │   │   ├── session.rs         # состояние сессии, key update
│   │   │   ├── transport/
│   │   │   │   ├── mod.rs         # Transport trait
│   │   │   │   ├── quic.rs        # quinn-обвязка (feature = "quic")
│   │   │   │   └── ack.rs         # ACK-диапазоны, RTT, loss detection
│   │   │   ├── masquerade/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── hello.rs       # сборка ClientHello (craftls)
│   │   │   │   ├── relay.rs       # пересылка на donor, NST-хендлинг
│   │   │   │   └── shape.rs       # QUIC-carrier шейпинг (паттерны размеров)
│   │   │   └── netstack.rs        # (feature="user-stack") lwIP-подобный стек — этап 2
│   │   ├── tests/
│   │   │   ├── packet_roundtrip.rs
│   │   │   ├── auth_label.rs
│   │   │   ├── replay_window.rs
│   │   │   └── censor_gets_real_site.rs   # ★ приёмка маскировки
│   │   └── benches/crypto.rs
│   │
│   ├── vpn-server/                # ★ бинарник сервера
│   │   ├── src/{main.rs,cli.rs,listener.rs,interceptor.rs,tun.rs,nat.rs,nst.rs,admin.rs}
│   │   ├── config/server.toml     # пример конфига
│   │   └── deploy/{bproto-server.service,install.sh,nftables.conf}
│   │
│   ├── vpn-ffi/                   # C ABI + JNI поверх vpn-core
│   │   ├── include/bproto.h       # C-заголовок
│   │   └── src/{lib.rs,jni.rs,ios.rs}
│   │
│   ├── vpn-cli/                   # отладочный клиент (connect + ping через туннель)
│   └── craftls/                   # git submodule: форк rustls с патчем session_id
│
├── apps/
│   ├── android/                   # Gradle + Kotlin + AAR
│   │   └── app/src/main/{java/...,cpp/...,AndroidManifest.xml}
│   ├── ios/                       # Xcode проект + PacketTunnelProvider
│   └── desktop/                   # Tauri: src (Vue) + src-tauri (Rust)
│
├── panel/
│   ├── backend/                   # axum + sqlx(SQLite)
│   │   ├── src/{main.rs,routes/,db/,auth.rs,ratelimit.rs,models.rs}
│   │   └── migrations/            # sqlx migrate
│   ├── frontend/                  # Vite + React + Tailwind
│   └── docker-compose.yml         # caddy(HTTPS) + panel
│
├── proto/                         # bproto.proto — admin API сервер↔панель
├── docs/
│   ├── PLAN.md                    # этот файл
│   ├── PROTOCOL.md                # спецификация кадра/рукопожатия
│   ├── THREAT-MODEL.md            # что от чего защищаем
│   └── DEPLOY.md
└── xtask/                         # cargo xtask: сборка AAR, .xcframework, релиз
```

Сборка одной командой (`justfile`):

```make
default: check
check:     ; cargo fmt --all --check && cargo clippy --all-targets -- -D warnings
test:      ; cargo nextest run --workspace
build:     ; cargo build --release -p vpn-server -p vpn-cli
android:   ; cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 build -p vpn-ffi --release && cargo xtask android-aar
ios:       ; cargo xtask ios-xcframework
panel:     ; cd panel/backend && sqlx migrate run && cargo run --release
frontend:  ; cd panel/frontend && pnpm i && pnpm build
release:   build android ios frontend
```

`cargo-make` не нужен — `just` + `xtask` покрывают всё и не тянут второй таск-раннер.

---

## 3. Ядро протокола: модули и зависимости

### 3.1 Формат кадра (фиксируем сразу, это контракт)

```
bProto datagram, 12-байтовый открытый заголовок (он же AAD для AEAD):

 offset  size  поле
 0       1     flags:  ver[7:4] | flags[3:0]
                 ver = 0x1
                 flag bit0 FEC_RESERVED (в MVP всегда 0, зарезервировано)
                 flag bit1 KEY_PHASE    (0/1, для key update)
                 flag bit2 SPIN         (шум, маскировка под QUIC spin bit)
                 flag bit3 CONTROL      (управляющий кадр, не IP)
 1       4     session_tag  u32 BE   (ротирующийся, усечённый conn_id)
 5       5     packet_number u40 BE  (монотонный, окно антиреплея)
 10      2     reserved      u16 BE  (MUST be 0; под FEC-параметры на этапе 2)
 ----------------------------------------------------------------------
 12      var   ChaCha20-Poly1305(key, nonce, aad=header, plaintext)
 plaintext:
   0    1      inner_type (0x00 IP, 0x01 control, 0x02 keepalive/padding)
   1    var    IP-пакет || нулевой padding до bucket-размера
```

* nonce (12 B) = `nonce_prefix[4] || packet_number_padded_to_8`; `nonce_prefix` — из HKDF
  по направлению (`client→server` / `server→client`), поэтому PN может повторяться между
  направлениями без коллизии.
* AAD = весь 12-байтовый заголовок → заголовок нельзя подменить, но он читаем для роутинга.
* MTU туннеля = `1280 − 12 − 16(tag) − 1(inner) = 1251`; TUN поднимаем с MTU 1280 и режем.
* `session_tag` ротируется по таймеру (например, раз в 30 c) вместе с key update, чтобы
  пассивный наблюдатель не мог линковать длинные потоки по одному ID.

### 3.2 Таблица модулей

| Модуль (файл) | Ответственность | Крейты (версия) |
|---|---|---|
| `packet.rs` | (де)сериализация 12B заголовка, inner-тип, паддинг до bucket | `bytes 1.10`, `zerocopy 0.8` (или ручное описание — рекомендую ручное: меньше сюрпризов) |
| `crypto.rs` | AEAD seal/open, X25519, HKDF-деривация ключей/nonce | `chacha20poly1305 0.10`, `x25519-dalek 2.0` (feature `static_secrets`, `zeroize`), `hkdf 0.12`, `sha2 0.10`, `zeroize 1.8`, `subtle 2.6` |
| `auth.rs` | метка в `session_id`: derive (клиент) / verify (сервер) | `hmac 0.12`, `sha2 0.10`, `blake2 0.10` (для tag-таблицы) |
| `replay.rs` | антиреплей: скользящее окно 4096 бит | собственный (`bitvec 1.0`) или `sliding-window` — рекомендую свой, ~80 строк, легко аудируется |
| `session.rs` | состояние: keys, PN-счётчики, key update (RFC 9001 §6), таймеры | `tokio 1.44` (time), внутренние |
| `transport/mod.rs` | `Transport` trait: `send`/`poll_recv`/`on_loss` | — |
| `transport/quic.rs` | обвязка `quinn` (UDP, CID, CUBIC/BBR) | `quinn 0.11`, `quinn-proto 0.11`, `tokio 1.44` |
| `transport/ack.rs` | ACK-диапазоны, RTT (RFC 9002), loss detection, NACK как fast-loss | собственный по RFC 9002 |
| `masquerade/hello.rs` | сборка ClientHello с отпечатком и меткой | `craftls` (git-форк rustls), `rustls 0.23`-совместимый API |
| `masquerade/relay.rs` | пересылка рукопожатия на donor, релей/синтез NST | `tokio`, `rustls`/`craftls`, `webpki-roots 0.26` |
| `masquerade/shape.rs` | шейпинг размеров/таймингов под трафик донора | собственный |
| `netstack.rs` (этап 2) | userspace TCP для релея, если понадобится | `smoltcp 0.11` или `lwip` биндинги |
| `config.rs` | `TunnelConfig`, сериализация | `serde 1.0`, `humantime-serde 1.1` |
| `error.rs` | единый `Error` | `thiserror 2.0` |

Правило: **крипто-крейты — только RustCrypto/AWS-LC-совместимые, никаких самописных
примитивов.** `ring` не берём (сложнее с кросс-компиляцией на Android/iOS); `aws-lc-rs`
не берём в MVP (тяжёлый C-билд), `chacha20poly1305` + `x25519-dalek` покрывают всё.

### 3.3 Как именно патчится `craftls` под `session_id`

Факт: `craftls` (github.com/3andne/craftls) — это форк `rustls`, подключаемый через

```toml
[patch.crates-io]
rustls = { git = "https://github.com/3andne/craftls", rev = "<pinned>" }
```

Он даёт `ClientConfig::builder()...with_fingerprint(CHROME_112)` — отпечаток ClientHello
(набор и порядок extensions, GREASE, padding). Метки `session_id` он не умеет.

Патч состоит из двух частей.

**(1) Новое поле конфига — `src/client/client_conn.rs`.** Добавляем опциональный
`session_id` и билдер:

```rust
// ClientConfig
pub(crate) session_id_override: Option<[u8; 32]>,

pub fn with_session_id(mut self, sid: [u8; 32]) -> Self {
    self.session_id_override = Some(sid);
    self
}
```

**(2) Точка сборки ClientHello — `src/client/hs.rs`, функция
`emit_client_hello_for_retry`.** Именно здесь формируется `ClientHelloPayload`;
заменяем сгенерированный rustls session id (random или пустой для TLS1.3 middlebox-compat)
на наш:

```diff
             cipher_suites: cipher_suites.clone(),
             compression_methods: CompressionMethods::from_vec(vec![CompressionMethod::Null]),
-            session_id: SessionId::new(session_id_or_empty),
+            session_id: SessionId::new(
+                self.config.session_id_override
+                    .map(|s| s.to_vec())
+                    .unwrap_or_else(|| session_id_or_empty.to_vec()),
+            ),
```

Всё. Никакого форка с нуля, ~6 строк в двух файлах. Важно: длина `session_id` остаётся
**ровно 32 байта**, как у настоящего Chrome/Safari в middlebox-compat режиме, поэтому
длина ClientHello не меняется — это и есть отличие от ShadowTLS, у которого размер
рукопожатия «поехал».

Метка (содержимое 32 байт) описывается в `auth.rs`:

```
session_id[0..8]  = HMAC-SHA256(K_tag, user_id)[0..8]                   // тег роутинга
session_id[8..32] = HMAC-SHA256(psk, client_random ‖ x25519_pub ‖ T)[0..24]
T = floor(unix_time / 300)                                              // окно 5 мин
```

Сервер: берёт тег → по таблице `tag → user` (предвычислена панелью) находит пользователя →
проверяет MAC в окнах `T−1, T, T+1` (constant-time через `subtle`). Совпадение → перехват,
иначе → **прозрачная пересылка** на donor (клиент получит настоящий сайт).

Почему так, а не «HMAC поверх записей» (как ShadowTLS):

| Свойство | ShadowTLS v3 | bProto |
|---|---|---|
| Аутентификация | HMAC-PSK поверх кадров рукопожатия (+4 байта к каждому) | метка внутри `session_id` (0 байт overhead) |
| Длина ServerFinished | +4 байта → детектируется Aparecium | не меняется → не детектируется |
| NewSessionTicket | не релеится → отсутствует | релеится/синтезируется → присутствует |
| Атака Aparecium | успешна (два вектора) | оба вектора закрыты конструктивно |

---

## 4. Сервер: порядок реализации

Шаги 1–3 параллелятся между двумя инженерами; 4–5 зависят от 2; 6+ — от всего.

| # | Шаг | Критерий готовности (DoD) | Можно параллелить с |
|---|---|---|---|
| 1 | Скелет `vpn-server`, парсинг TOML, CLI, логирование (tracing), systemd unit | `vpn-server --check-config` валидирует конфиг и падает на неверном; сервис стартует и логирует listen_addr | 2, 3 |
| 2 | TUN + NAT: `tun` crate, поднятие `bproto0`, nftables masquerade, MTU 1280 | `ping 8.8.8.8` с сервера через NAT идёт; `ip -s link show bproto0` показывает счётчики | 1, 3 |
| 3 | Приёмная площадка маскировки: QUIC/HTTP-3 клиент к donor, релей ClientHello → вывод сертификата donor без TLS-ошибки | `openssl s_client`/`curl --http3` к нашему порту получает **валидный сертификат donor** | 1, 2 |
| 4 | Проверка `session_id` (тег→user, MAC, ±1 окно), маршрутизация «свой/чужой» | unit-тесты на 3 окна + таблица тегов; чужой ClientHello уходит на donor побайтово | 2 |
| 5 | Подключение `vpn-core`: вызов `Session::accept`, деривация ключей, AEAD round-trip с тестовым клиентом | `vpn-cli` поднимает сессию, `send_ip_packet`/`recv_ip_packet` работают внутри одного хоста | 2 |
| 6 | Обработка IP-пакетов: чтение из TUN → `send_ip_packet`; из сессии → запись в TUN; маршрутизация по внутренним адресам | `ping` через `vpn-cli` на другой хост даёт ответ | 5 |
| 7 | NST-митигация: релей/синтез `NewSessionTicket` после ClientFinished | против Aparecium-подобного скрипта нет различий по NST и длине ServerFinished | 3 |
| 8 | Admin API (`proto/bproto.proto`) на loopback: add/remove user, revoke, stats | панель по gRPC добавляет юзера, сервер сразу его принимает без рестарта | 1 |
| 9 | Метрики/rate-limit/anti-replay-очистка, hardening (drop caps, chroot, seccomp) | `systemd-analyze security` score, лимит `nofile`, тест на absence of caps | 6 |
| 10 | Деплой-скрипт на VPS + DEPLOY.md | Чистый Ubuntu 24.04 → рабочий сервер одной командой, перезагрузка не ломает | 9 |

Ключевой риск шага 3: не все доноры одинаковы. Нужен health-check доноров и список с
автопереключением (donor pool), потому что TLS-версии/набор extensions у сайтов меняются.

---

## 5. Клиенты: особенности каждой платформы

### 5.1 Android

| Проблема | Решение | Риски |
|---|---|---|
| TUN | `VpnService` + `ParcelFileDescriptor`; `Builder.addAddress/addRoute(0.0.0.0/0, ::/0)`; `addDnsServer` | Два DNS-сервера и split-tunnel легко сломать; тестировать на API 24+ и 34+ |
| Рандомизация адресов TUN | Генерировать локальный /32 и внутритуннельный адрес из `getrandom` на каждом старте; не переиспользовать | Приложение-клиент запоминает 10.0.0.2 → детект по стабильности; ротация обязательна |
| Нейтральное имя сессии | `Builder.setSession("System Service")` + не показывать иконку-ключ в статус-баре; `setBlocking(false)` | Актуально только для API < 29; на 29+ систему это не обманет |
| Банковские приложения падают | Не мешает: они проверяют `NetworkCapabilities.TRANSPORT_VPN`, а не имя | **Полностью решается только на стороне приложения**; снижаем эвристики (см. ниже) |
| `onRevoke` | Обработчик: корректно закрыть сессию, не оставлять висящий TUN | На некоторых прошивках вызывается без предупреждения |
| Обход детекта VPN | **Этап 2**: точки расширения — `bproto_jni_set_stealth(level)`, переключаемые стратегии (per-app bypass через `addDisallowedApplication`, разделение маршрутов, вынос DNS) | Не обещаем невидимость: VPN-детект многослойный |

### 5.2 iOS

| Проблема | Решение | Риски |
|---|---|---|
| Пакетный туннель | `NEPacketTunnelProvider` + `NEPacketTunnelNetworkSettings` (IPv4/IPv6, MTU 1280, DNS) | Нужен entitlement `packet-tunnel-provider` и платный Apple Developer аккаунт |
| Нет динамической загрузки кода | Вся логика — в статически скомпонованном `libvpn_core.a` (C-FFI), Swift только оркестрирует | Нельзя подменять протокол на лету — только switch по скомпилированным стратегиям |
| Проверка расширения | Подпись + provisioning profile; обновлять профиль до истечения | Просроченный профиль = туннель не поднимается у всех |
| App Store | VPN-приложения допускаются, но требуют реального сервиса и privacy-манифеста; в ряде регионов приложение изымается | Планировать TestFlight/Enterprise как запасной канал |
| Фон | `NEPacketTunnelProvider` живёт как системный процесс; ограничения по памяти | Watchdog убивает при утечках; держать память ядра в узде |

### 5.3 Desktop (Windows / macOS / Linux)

| ОС | TUN | Права администратора |
|---|---|---|
| Linux | `tun` crate, `/dev/net/tun` | Не root, а `setcap cap_net_admin+ep` на бинарник **или** systemd-сервис с `AmbientCapabilities=CAP_NET_ADMIN`; GUI работает без прав, только helper-демон привилегирован |
| macOS | `utun` (тот же `tun` crate) | Требуется NetworkExtension-расширение (system extension) → пользователь один раз одобряет в Privacy → не «без прав», а «одноразовое одобрение»; для dev — root |
| Windows | Wintun (`wintun.dll`) через `tun` crate | Установка Wintun-драйвера требует admin **один раз**; либо ставить Windows-сервис при установке MSI, GUI общается с ним по named pipe |

Честно: **«обойти требование прав администратора» нельзя** — можно только сделать так, чтобы
GUI никогда не работал с правами, а привилегированный компонент был минимальным и
устанавливался один раз. Формулировка «обойти» ведёт к неправильной архитектуре (попытка
делать NAT из userspace без прав не сработает).

### Что почти наверняка съест больше времени, чем кажется

1. **Смена сетевого пути** (`on_path_change`): Wi-Fi↔LTE, NAT-rebinding, смена белого IP.
   Это самая болезненная часть в мобильных VPN. Нужен отдельный тест-стенд с ротацией сети.
2. **iOS на реальном устройстве**, не в симуляторе: симулятор не даёт `NEPacketTunnelProvider`
   в полноте, отладка через `log stream` и `Console`.
3. **Фрагментация и MTU**: путь с 1400 → PMTU discovery, ретрансляция ICMP. Классический
   источник «у одних работает, у других нет».
4. **Android OEM-прошивки**: MIUI/HyperOS агрессивно убивают фоновые VPN-VPN; Doze и
   battery optimization надо обходить через foreground service.
5. **QUIC-CID лимиты при маскировке**: если шейпить под QUIC, надо тянуть совместимость с
   изменением форматов QUIC у разных браузеров.

---

## 6. Панель управления: API и модель данных

### 6.1 Схема БД (SQLite, WAL, `sqlx`)

```
users
  id            INTEGER PK
  username      TEXT UNIQUE NOT NULL
  password_hash TEXT          -- argon2id
  is_admin      INTEGER       -- 0/1
  traffic_limit_bytes INTEGER NULL   -- NULL = без лимита
  traffic_used_bytes  INTEGER DEFAULT 0
  expires_at    INTEGER NULL
  status        TEXT          -- active | disabled | revoked
  created_at    INTEGER

keys                                 -- одна запись на устройство/сессию
  id            INTEGER PK
  user_id       INTEGER FK users(id) ON DELETE CASCADE
  label         TEXT                 -- "Pixel 8", "MacBook"
  psk           BLOB(32)             -- pre-shared key (для session_id MAC)
  tag           BLOB(8)              -- HMAC(K_tag, user_id)[0..8]
  pubkey        BLOB(32) NULL        -- X25519 клиента (pin, этап 2)
  config_qr     TEXT                 -- сериализованный bproto://... (не секрет, PSK внутри)
  status        TEXT                 -- active | revoked
  created_at    INTEGER
  revoked_at    INTEGER NULL
  last_seen_ip  TEXT NULL

sessions                              -- runtime, пишется сервером
  id            INTEGER PK
  key_id        INTEGER FK keys(id)
  server_id     TEXT                 -- идентификатор VPS
  started_at    INTEGER
  ended_at      INTEGER NULL
  bytes_rx      INTEGER
  bytes_tx      INTEGER
  peer_ip       TEXT

servers                               -- пул VPS-серверов
  id            TEXT PK
  name          TEXT
  host          TEXT
  donor_url     TEXT
  status        TEXT

admin_audit
  id            INTEGER PK
  admin_id      INTEGER
  action        TEXT
  target        TEXT
  at            INTEGER
  ip            TEXT

rate_limit                            -- опционально: last request per ip/key
  bucket        TEXT PK
  tokens        REAL
  updated_at    INTEGER
```

### 6.2 Эндпоинты MVP

```
POST   /api/auth/login              -> {token}          (argon2id + rate limit)
POST   /api/auth/logout
GET    /api/me

GET    /api/users                   -> список + статус/трафик
POST   /api/users                   -> создать (username, лимит, срок)
PATCH  /api/users/{id}              -> лимит/срок/status
DELETE /api/users/{id}              -> revoke

GET    /api/users/{id}/keys
POST   /api/users/{id}/keys         -> {key_id, config_uri, qr_png_base64}
POST   /api/keys/{id}/revoke
GET    /api/keys/{id}/config        -> повторная выдача config_uri

GET    /api/servers                 -> пул + доноры + статус
GET    /api/stats/overview          -> онлайн, rx/tx, топ юзеров
GET    /api/stats/users/{id}        -> история сессий
GET    /api/health

# служебный (loopback, mTLS/static token)
POST   /internal/v1/keys/sync       -> панель → сервер: полный снапшот tag→(user,psk)
POST   /internal/v1/sessions/report -> сервер → панель: батч статистики
```

### 6.3 Как панель взаимодействует с сервером — выбор

| Вариант | Плюсы | Минусы | Вердикт |
|---|---|---|---|
| Файлы конфигов + reload по SIGHUP | просто, нет API | отзыв ключа не мгновенный, гонки при записи, плохо масштабируется на пул | ✗ |
| Сервер сам ходит в БД панели | нет дубля данных | сервер зависит от схемы панели, SQLite через сеть = боль | ✗ |
| **Панель → admin-API сервера (gRPC), SSOT в SQLite панели** | мгновенный отзыв, явный контракт (`.proto`), пул VPS единообразно, сервер не знает про SQL | чуть больше кода | **✓ рекомендую** |
| Панель → файлы (генерируемый снапшот, атомарный rename) | просто | не мгновенно | ✗ |

Конкретно: SSOT — SQLite панели. Панель при изменении ключей рассылает **инкрементальный
снапшот** `tag→psk` по gRPC на каждый сервер; сервер держит его в памяти и на диск не
пишет (после рестарта берёт заново). Статистику сервер **батчит и шлёт** панели раз в 30 c
(не по пакету). Транспорт — loopback + WireGuard/приватная сеть между панелью и VPS;
никогда не выставлять `/internal` в интернет.

### 6.4 Безопасность панели

* argon2id (`argon2 0.5`), параметры `m=19MiB, t=2, p=1` минимум.
* HTTPS обязателен: Caddy с автоматическим Let's Encrypt перед axum, HSTS, редирект 80→443.
* Rate limiting: `tower-governor` на `/api/auth/*` (5/мин/IP, 20/мин/аккаунт) + общий лимит.
* Сессии админа — короткоживущий JWT (15 мин) + refresh в HttpOnly/Secure/SameSite=Strict cookie.
* CSRF-токен на мутирующие запросы; CSP на фронте; `sqlx` с параметризацией (никакой конкатенации SQL).
* Аудит всех админ-действий в `admin_audit`; PSK никогда не логируется и не отдаётся повторно
  после первого показа (кроме явного «перевыпустить»).

---

## 7. План по этапам

### Этап 1 — MVP (цель: рабочий туннель + маскировка без известных дыр)

Входит:
* `vpn-core`: packet/crypto/auth/replay/session, транспорт на `quinn` (CUBIC), без FEC.
* `vpn-server`: TUN+NAT, перехват ClientHello, verify метки, релей на donor, NST-митигация.
* Клиент Desktop (Linux/macOS CLI+Tauri-минимум) как референс; `vpn-cli`.
* Панель: пользователи, ключи, выдача конфига (QR), статус, отзыв.
* `craftls` с патчем `session_id`, донор-пул из 3–5 h3-сайтов.

Критерий готовности:
* Трафик всего устройства клиента идёт через сервер; `curl https://ifconfig.me` показывает IP VPS.
* Пассивный DPI по сигнатурам (nDPI/`tls_fingerprint`) не отличает поток от QUIC-трафика донора.
* Активное зондирование: чужой/пустой/повторный ClientHello → **настоящий сайт**.

Способ проверки:
```
# 1) настоящий сайт для чужого
openssl s_client -connect <vps>:443 -servername <donor> -alpn h3
python3 tools/aparecium_like.py --host <vps> --donor <donor>   # !!! ожидаем 0 findings
# 2) туннель
vpn-cli connect --config cfg.toml && vpn-cli ping 1.1.1.1
# 3) реплей метки в пределах окна — должен быть отвергнут (nonce-cache)
python3 tools/replay_label.py
```

Тест «цензор с неверным паролем получает настоящий сайт» (обязательный интеграционный,
`crates/vpn-core/tests/censor_gets_real_site.rs`):
1. Поднять donor-заглушку (локальный TLS-сервер с самоподписанным cert).
2. Поднять `vpn-server` против неё.
3. Послать ClientHello с ПРАВИЛЬНОЙ меткой → ожидаем перехват (сессионный ответ bProto).
4. Послать ClientHello со случайным `session_id` → ожидаем **побайтово валидный TLS-хендшейк
   донора** и его сертификат.
5. Послать ClientHello с правильным тегом, но неверным MAC → снова донор.

### Этап 2 — усиление

Входит:
* Панель: лимиты трафика-энфорсмент, статистика, пул серверов, аудит, 2FA.
* Android (VpnService + JNI) и iOS (NEPacketTunnelProvider + C-FFI), рандомизация TUN-адресов,
  нейтральное имя сессии, точки `set_stealth`.
* `on_path_change` (migration), key update, ротация `session_tag`.
* PQ: **ML-KEM-768 как rekey после рукопожатия** (см. критику ниже) — гибридный
  X25519+ML-KEM-768 при key update.
* donor-пул с health-check и автопереключением; шейпинг размеров/таймингов (`shape.rs`).

Критерий готовности:
* Android: устройство выдерживает Wi-Fi↔LTE без разрыва туннеля; банковское приложение
  запускается (мы не роняем его, но и не гарантируем незаметность).
* iOS: туннель в App Store-сборке; PQ rekey успешен; `ml-kem` в трейсе подтверждён.
* Детект-тест Android: `VpnDetector`-подобная проверка (`NetworkCapabilities`), фиксируем
  честно: `TRANSPORT_VPN` = true всегда, снижаем только вторичные эвристики.

Способ проверки: `tools/detect_vpn.kt` (проверка `TRANSPORT_VPN`, `/proc/net/route`, DNS),
скрипт network-migration (переключение интерфейсов под нагрузкой, `iperf3` без обрыва > 2 c).

### Этап 3 — продукт

Входит:
* FEC (Reed–Solomon, сначала AEAD затем RS — как зафиксировано), только для lossy-путей.
* Windows/macOS GUI-полнота, установщики, апдейтер, минимальный привилегированный сервис.
* Мульти-серверная маршрутизация, лимиты по устройствам, биллинг-хуки, self-service.
* Внешний аудит криптографии и протокола.

Критерий готовности: внешний пентест ciphertext-in/ciphertext-out, fuzz-корпус без паник,
деградация при 20% loss не хуже заявленной, FEC включается динамически без пересборки.

---

## 8. Честная критика

### Что реально сломано или переусложнено

1. **«NACK + CUBIC» — нерабочая комбинация** (см. Противоречие B). Либо ACK+NACK (рекомендую),
   либо собственный loss-based контроллер по таймаутам — но это уже изобретение CC.
2. **«UDP + пересылка TLS ClientHello на сайт»** не сходится, если donor не умеет h3
   (см. Противоречие A). Если брать TCP-маскировку — то и транспорт станет TCP/TLS, а
   «UDP-only» потеряет смысл. Нужно определиться: **QUIC-маскировка (мой рекомендованный
   вариант)** либо честно TCP/TLS.
3. **12 байт заголовка + AAD = открытые метаданные.** `session_tag` в открытом виде даёт
   линковку сессий, если не ротировать. Ротация `session_tag` и API-вызов key update —
   обязательны в MVP, а не «этап 2», иначе деанонимизация тривиальна.
4. **ML-KEM-768 «после рукопожатия» не защищает от harvest-now-decrypt-later** для первой
   сессии: если трафик записан, а долгий ключ Compromised — первая сессия читается.
   Честный вариант: гибрид X25519+ML-KEM-768 **в рукопожатии** (но 1184 B pubkey + 1088 B
   ciphertext раздувают ClientHello → конфликт с маскировкой под Chrome). Компромисс:
   делать гибрид только в **QUIC CRYPTO** после Initial (там уже большой легитимный паддинг),
   а не «после полного рукопожатия». Иначе PQ-обещание — маркетинг.
5. **Ed25519-only без ML-DSA — согласен**, но надо понимать: сертификат мы не подписываем
   своим ключом вообще — мы **занимаем** сертификат донора. То есть подпись в системе не
   защищает аутентификацию сервера так, как ожидается; аутентификация держится на PSK-метке.
   Ed25519 в конфиге остаётся только для подписи конфигов/обновлений. Это надо явно
   записать в THREAT-MODEL, чтобы никто не думал, что «есть сертификат → есть защита от MITM».
6. **«Заимствование сертификата» = активный MITM на пути к донору.** Юридически и с точки
   зрения abuse — риск (наш сервер исходяще коннектится к донору от имени множества клиентов).
   Нужны: donor-pool, соблюдение их ToS, отсутствие кэширования приватного трафика.
7. **Обещание «обход обнаружения VPN» на Android недостижимо полностью.** Банк видит
   `TRANSPORT_VPN` на уровне ОС. Максимум — per-app bypass и снижение вторичных эвристик.
   Не закладывать эту функцию как «гарантируемую» в продукт-оффер.
8. **iOS «без прав администратора» — миф.** Одноразовое одобрение system extension требуется.
   Так же и Windows-драйвер Wintun. Позиционировать как «минимум привилегий», не «без прав».
9. **craftls = форк rustls, привязанный к версии.** Пока мы на форке, мы отстаём от
   security-патчей rustls. Риск. Митигация: держать ревью-дифф с апстримом, обновлять
   минимум раз в квартал, CI-тест на апстрим-совместимость API.
10. **SQLite в панели** при нескольких инстансах = проблема. MVP — один инстанс, WAL.
    Как только инстансов >1 — постгрес. Не тянуть переезд.

### Что стоит урезать в MVP

* Убрать Windows/iOS целиком (этап 2). MVP — Linux/macOS сервер + Linux-клиент + панель.
* Убрать ML-KEM и FEC (уже убраны, подтверждаю — правильно).
* Убрать GUI Tauri: хватит `vpn-cli` + конфиг. GUI не проверяет протокол.
* Убрать «драйверы» и установщики: один бинарник + systemd.

### Решения из «Зафиксированных», которые я бы оспорил

| Решение | Позиция | Аргумент |
|---|---|---|
| NACK вместо ACK | **оспорено** | ломает CUBIC; нужен ACK+NACK |
| UDP-транспорт + TCP/TLS-маскировка на donor | **оспорено** | несовместимо; либо QUIC-маскировка, либо TCP-транспорт |
| ML-KEM-768 «после рукопожатия» | **оспорено** | не даёт HNDL-устойчивости для первой сессии; делать гибрид в CRYPTO |
| Подписи Ed25519 как защита от MITM | **уточнено** | защиту даёт PSK-метка; Ed25519 — только для конфигов/обновлений |
| «Обход обнаружения VPN» в Android | **уточнено** | недостижимо полностью; снижаем эвристики, не обещаем невидимость |
| ML-DSA-65 не использовать | **согласен** | 3293 B ломает маскировку, смысла нет |
| FEC отложен | **согласен** | правильно для MVP |
| Реализация через `craftls` + патч | **согласен** | минимальный диф, 32-байтовый session_id без изменения длины |

### Итоговая рекомендация по критическим развилкам

| Вопрос | Выбор |
|---|---|
| Маскировка | **QUIC/HTTP-3 к donor** (fallback: TCP/TLS-режим как отдельный режим, не в MVP) |
| Надёжность | **ACK-диапазоны + NACK как fast-loss** (RFC 9002), никакой чистой NACK-схемы |
| Congestion | **CUBIC (MVP)**, BBR — после телеметрии; BBRv3 — не трогать |
| PQ | **гибрид в QUIC CRYPTO на key update**, не «после рукопожатия» |
| Панель↔сервер | **gRPC admin-API + SSOT в SQLite панели** |
| Десктоп-права | **минимальный привилегированный сервис/драйвер + непривилегированный GUI** |

---

## Приложение A: Публичный API `vpn-core`

```rust
// crates/vpn-core/src/lib.rs
pub struct TunnelConfig {
    pub server: SocketAddr,
    pub donor: DonorSpec,          // sni, alpn, ip override
    pub psk: [u8; 32],
    pub user_id: u64,
    pub tag_key: [u8; 32],         // K_tag из панели
    pub mtu: u16,                  // 1280
    pub fingerprint: Fingerprint,  // Chrome112 | Safari17_1 | ...
    pub stealth: StealthLevel,     // MVP: Off
}

pub struct Tunnel { /* ... */ }

impl Tunnel {
    pub async fn connect(cfg: TunnelConfig) -> Result<Self, Error>;

    /// Отправить один сырой IP-пакет (из TUN). Не блокирует, ставит в очередь.
    pub async fn send_ip_packet(&self, pkt: &[u8]) -> Result<(), Error>;

    /// Принять один IP-пакет в buf. Возвращает длину.
    pub async fn recv_ip_packet(&self, buf: &mut [u8]) -> Result<usize, Error>;

    /// Уведомить о смене локального адреса/интерфейса (Wi-Fi↔LTE, NAT rebind).
    pub fn on_path_change(&self, new_local: SocketAddr, mtu: u16);

    /// Метрики: rtt, cwnd, rx/tx, loss, rekey age.
    pub fn stats(&self) -> TunnelStats;

    /// Инициировать key update / ротацию session_tag.
    pub async fn rekey(&self) -> Result<(), Error>;

    pub async fn close(self) -> Result<(), Error>;
}
```

## Приложение B: C-FFI / JNI (для мобильных)

```c
// vpn-ffi/include/bproto.h
typedef struct BprotoTunnel BprotoTunnel;
typedef void (*bproto_packet_cb)(const uint8_t *pkt, size_t len, void *user);

BprotoTunnel* bproto_connect(const char *config_json, char **err);
int  bproto_send(BprotoTunnel*, const uint8_t *pkt, size_t len);
void bproto_set_recv_cb(BprotoTunnel*, bproto_packet_cb, void *user);
void bproto_on_path_change(BprotoTunnel*, const char *local_addr, uint16_t mtu);
void bproto_free(BprotoTunnel*);
```

Android оборачивает это в `object VpnBridge { external fun ... }`; iOS — в Swift
`final class BProtoCore`. Один и тот же `libbproto` (`crates/vpn-ffi`, cdylib для
Android / staticlib для iOS) — одна реализация протокола на всех платформах;
