# bProto — VPN, сервер, Android и панель / VPN, server, Android and panel

[![Build and test](https://github.com/dr-lexus-dr/bProto/actions/workflows/build.yml/badge.svg)](https://github.com/dr-lexus-dr/bProto/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/dr-lexus-dr/bProto)](https://github.com/dr-lexus-dr/bProto/releases)

**Русский.** bProto — проект VPN на Rust: протокол поверх UDP, Linux-сервер,
Linux CLI, Android-клиент с глобусом и веб-панель bUI. Этот README предназначен
для владельца VPS, пользователя клиента и разработчика. Здесь есть установка
одной командой, объяснение сетевых настроек, обслуживание и проверяемые ограничения.

**English.** bProto is a Rust VPN project with a UDP protocol, Linux server,
Linux CLI, an Android globe client and the bUI web panel. This README is for VPS
operators, client users and developers. It covers one-command installation,
network configuration, maintenance and the limits of the current implementation.

**Текущий релиз / Current release:** [v1.0.0](https://github.com/dr-lexus-dr/bProto/releases/tag/v1.0.0).
[Загрузки / Downloads](https://github.com/dr-lexus-dr/bProto/releases) ·
[Сборки / Builds](https://github.com/dr-lexus-dr/bProto/actions) ·
[Задачи / Issues](https://github.com/dr-lexus-dr/bProto/issues)

> **RU:** шифрование работает; гарантированный обход блокировок или белых списков
> не заявляется. Android APK релиза 1.0.0 имеет debug-подпись. Сначала прочитайте
> требования и ограничения, особенно перед переносом реального трафика.
>
> **EN:** encryption is implemented; guaranteed censorship or allowlist bypass
> is not claimed. The 1.0.0 Android APK is debug-signed. Read the requirements
> and limitations before depending on the tunnel for real traffic.

## Содержание / Contents

Каждый раздел содержит русский и английский текст; команды общие, если не указано иное.
Each section includes Russian and English explanations; commands are shared unless stated otherwise.

| Начало / Getting started | Эксплуатация / Operations | Устройство / Internals |
| --- | --- | --- |
| [Быстрая установка / Quick install](#quick-install) | [Служба / Service](#service) | [Архитектура / Architecture](#architecture) |
| [Доверие скрипту / Script trust](#script-trust) | [NAT и адрес / NAT and endpoint](#nat) | [Протокол / Protocol](#protocol) |
| [Требования / Requirements](#requirements) | [Firewall](#firewall) | [Возможности / Capabilities](#capabilities) |
| [Параметры / Options](#bootstrap-options) | [Конфигурация / Configuration](#server-config) | [Безопасность / Security](#security) |
| [Скачивание / Download only](#download-only) | [Ключи / Keys](#keys) | [Разработка / Development](#development) |
| [Файлы / Files](#files) | [Обновление / Upgrade](#upgrade) | [Участие / Contributing](#contributing) |

**Клиенты / Clients:** [Linux](#linux-client) · [Android](#android) ·
[Профили / Profiles](#profiles) · [Автовыбор / Automatic selection](#automatic).

**Панель / Panel:** [Установка / Installation](#panel-install) · [HTTPS](#https) ·
[Первый вход / First login](#panel-first-login) · [Синхронизация ключей / Key sync](#key-sync) ·
[Подписки / Subscriptions](#subscriptions).

**Маршрутизация / Routing:** [Правила / Rules](#routing) · [Split tunnel](#split-tunnel) ·
[DNS и IPv6](#dns-ipv6) · [Приватность / Privacy](#privacy).

**Обслуживание / Maintenance:** [Резервные копии / Backups](#backups) · [Откат / Rollback](#rollback) ·
[Удаление / Removal](#uninstall) · [Диагностика / Troubleshooting](#troubleshooting) ·
[FAQ](#faq) · [Поддержка / Support](#support) · [Релизы / Releases](#releases).

<a id="quick-install"></a>
## Быстрая установка на VPS / Quick VPS installation

**RU.** Для готового пакета нужен x86_64 VPS с Ubuntu 24.04+ или Debian 13+,
systemd и доступным TUN. Откройте root-оболочку: `sudo -i`. Затем выполните:

**EN.** The prebuilt package requires an x86_64 VPS running Ubuntu 24.04+ or
Debian 13+, with systemd and TUN available. Enter a root shell using `sudo -i`, then run:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/dr-lexus-dr/bProto/main/bootstrap.sh)
```

**RU.** Команда скачивает бинарники **v1.0.0**, проверяет контрольную сумму,
размещает текущие скрипты проекта в `/opt/bproto`, устанавливает сервер и CLI,
создаёт ключи и службу. Rust не нужен. Порты firewall скрипт не открывает:
после завершения проверьте UDP 443, `nat_interface` и публичный адрес клиента.
Служба должна перейти в `active`; ошибка запуска возвращает ненулевой код.

**EN.** The command downloads **v1.0.0** binaries, verifies their checksum,
places current project scripts in `/opt/bproto`, installs the server and CLI,
and creates keys and a service. Rust is not required. The script does not open
firewall ports: check UDP 443, `nat_interface` and the client’s public endpoint
after installation. The service should become `active`; startup failure returns
an error status.

```bash
systemctl status bproto-server --no-pager
journalctl -u bproto-server -n 50 --no-pager
```

<a id="script-trust"></a>
## Что выполняет curl-команда / Understanding the curl command

**RU.** `bash <(...)` — синтаксис Bash, не обычного `sh`. `curl -f` возвращает
ошибку при HTTP 404/500, `-sS` скрывает прогресс, но показывает ошибки, `-L`
следует перенаправлениям. Не используйте `curl -k`: проверка HTTPS должна оставаться
включённой. Загружаемый скрипт с ветки `main` может меняться. Проверка SHA256
архива защищает от повреждения скачивания, но не является независимой подписью
издателя: сам манифест приходит из того же GitHub-релиза.

**EN.** `bash <(...)` is Bash syntax, not portable `sh` syntax. `curl -f` fails
on HTTP 404/500, `-sS` hides progress while keeping errors visible, and `-L`
follows redirects. Do not use `curl -k`; retain HTTPS verification. The script
on `main` can change. Archive SHA256 verification detects download corruption,
but is not an independent publisher signature: the manifest comes from the same release.

**RU.** Для просмотра до запуска скачайте файл отдельно. Это также удобнее,
если `sudo bash /dev/fd/...` не видит файловый дескриптор process substitution.
**EN.** Download first if you want to inspect the script, or if `sudo bash
/dev/fd/...` cannot access a process-substitution descriptor.

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/dr-lexus-dr/bProto/main/bootstrap.sh \
  -o bootstrap.sh
less bootstrap.sh
bash -n bootstrap.sh
bash bootstrap.sh --dry-run
sudo bash bootstrap.sh
```

<a id="requirements"></a>
## Требования / Requirements

| Компонент / Component | Требования / Requirements |
| --- | --- |
| Готовый Linux-пакет / Prebuilt Linux package | x86_64, glibc ≥ 2.39; Ubuntu 24.04+ / Debian 13+ |
| Сервер / Server | Linux TUN, systemd для установщика / for installer; `ip`, `nft`, root during installation |
| Сборка Rust / Rust build | Rust ≥ 1.88, C compiler/linker, Cargo lockfiles |
| Панель / Panel | Docker Engine + Compose v2; DNS hostname; TCP 80/443 |
| Панель из исходников / Panel from source | Rust + Node 20+; pnpm 9.15.9 |
| Android | Android 8 / API 26 or newer; arm64-v8a, armeabi-v7a, x86_64 |
| Сборка Android / Android build | JDK 17, Gradle 8.11.1, SDK 35, NDK 27.2.12479018, cargo-ndk 3.5.4 |

**RU.** Виртуальный сервер должен разрешать `/dev/net/tun` и сетевые capabilities.
Обычный контейнер без этих прав не подходит для серверного datapath. Ubuntu 22.04
может использоваться для самостоятельной совместимой сборки, но bootstrap
откажется устанавливать на него бинарник, собранный с более новой glibc.
Alpine/musl и готовый Linux ARM64-пакет текущим bootstrap не поддерживаются.

**EN.** Your VPS must expose `/dev/net/tun` and permit network capabilities.
An ordinary container without them cannot run the server datapath. Ubuntu 22.04
can be used for a compatible source build, but bootstrap rejects the prebuilt
binary on its older glibc. Alpine/musl and prebuilt Linux ARM64 installation
are not supported by the current bootstrap.

```bash
uname -m
getconf GNU_LIBC_VERSION
test -c /dev/net/tun && echo 'TUN available'
```

<a id="bootstrap-options"></a>
## Параметры bootstrap / Bootstrap options

| Флаг / Flag | Значение по умолчанию / Default | Назначение / Purpose |
| --- | --- | --- |
| `--release TAG` | `v1.0.0` | Версия бинарников / Binary release tag |
| `--directory PATH` | `/opt/bproto` | Постоянный checkout / Persistent checkout |
| `--target TARGET` | `all` | `server`, `client`, `all` |
| `--port PORT` | `443` | UDP-порт **нового** конфига / UDP port for a **new** config |
| `--no-start` | off | Не запускать службу / Do not start service |
| `--skip-deps` | off | Не выполнять apt-get / Do not run apt-get |
| `--download-only DIR` | off | Только проверенное скачивание / Verified download only |
| `--dry-run` | off | План без сети и изменений / Plan without network or host changes |
| `--help` | — | Справка / Help |

```bash
bash bootstrap.sh --dry-run --target server --port 8443
sudo bash bootstrap.sh --target all --port 8443 --no-start
sudo bash bootstrap.sh --skip-deps --directory /opt/bproto
```

**RU.** `all` означает сервер + Linux CLI, не панель. Панель устанавливается
отдельно после Docker и DNS. `--port` не меняет уже существующий `server.toml`:
измените конфигурацию вручную и перезапустите службу. `--release` выбирает
бинарники опубликованного релиза; установочные скрипты берутся из `main`.

**EN.** `all` means server + Linux CLI, not the panel. Install the panel
separately after setting up Docker and DNS. `--port` does not rewrite an existing
`server.toml`; edit it and restart the service. `--release` selects published
binaries, while installation scripts come from `main`.

<a id="download-only"></a>
## Только скачивание и ручная установка / Download-only and manual installation

**RU.** Этот режим не требует root, не запускает apt, не создаёт службу и не
меняет маршруты. Укажите ещё не существующий каталог. Он скачивает Linux-архив,
проверяет SHA256 по манифесту релиза и проверяет наличие серверного и клиентского
бинарников в архиве.

**EN.** This mode needs no root, does not run apt, and does not create services
or change routes. Choose a directory that does not exist yet. It downloads the
Linux archive, checks its release-manifest SHA256 and confirms that server and
client binaries are present.

```bash
bash bootstrap.sh --download-only "$PWD/bproto-download"
cd bproto-download
sha256sum --check bproto-linux-x86_64.tar.gz.sha256
tar -tzf bproto-linux-x86_64.tar.gz
```

**RU.** Для ручного развёртывания разместите `dist/` из архива в checkout проекта
и вызовите `sudo ./install.sh all --no-build`. Один архив бинарников не содержит
полного окружения установки: нужны скрипт и systemd unit из исходников. Для
офлайн-сервера заранее перенесите исходники, бинарники и системные зависимости.

**EN.** For manual deployment, extract `dist/` into the source checkout and run
`sudo ./install.sh all --no-build`. A binary archive alone is not the complete
installation environment: use the installer and systemd unit from the source
checkout. For an offline host, transfer sources, binaries and OS dependencies
in advance.

<a id="files"></a>
## Что появляется на сервере / Installed files

| Путь / Path | Содержимое / Contents |
| --- | --- |
| `/opt/bproto` | Checkout текущих скриптов / Current installation source checkout |
| `/opt/bproto/dist/bin` | Проверенные скачанные бинарники / Verified downloaded binaries |
| `/usr/local/bin/vpn-server` | Исполняемый файл сервера / Server executable |
| `/usr/local/bin/bproto` | Linux CLI |
| `/etc/bproto/server.toml` | Ключи и настройки сервера / Server settings and keys |
| `/etc/bproto/user1.client.toml` | Начальный клиент / Initial client configuration |
| `/etc/systemd/system/bproto-server.service` | Служба / Service unit |
| `/etc/sysctl.d/99-bproto.conf` | IPv4 forwarding |
| `/opt/bproto/panel/.env` | Домен и секреты панели / Panel domain and secrets |

**RU.** Каталог `/etc/bproto` имеет `0750`, владелец `root`, группа `bproto`.
Конфиг сервера — `root:bproto`, `0640`: сервис может его прочитать, обычные
пользователи — нет. Клиентский файл остаётся `0600`. Не выдавайте группе `bproto`
чужие учётные записи. Данные Docker-панели находятся в named volumes; они не
исчезают при обычном `docker compose down`, но удаляются с `down -v`.

**EN.** `/etc/bproto` is `0750`, owned by `root:bproto`. The server configuration
is `0640`, owned by `root:bproto`, so the service can read it but ordinary users
cannot. The client file remains `0600`. Do not add unrelated accounts to the
`bproto` group. Docker panel data lives in named volumes: ordinary
`docker compose down` preserves them; `down -v` removes them.

<a id="service"></a>
## Служба systemd / systemd service

```bash
sudo systemctl status bproto-server --no-pager
sudo systemctl restart bproto-server
sudo systemctl stop bproto-server
sudo systemctl start bproto-server
sudo systemctl enable bproto-server
sudo journalctl -u bproto-server -n 100 --no-pager
```

**RU.** Сервер запускается от системного пользователя `bproto`. `CAP_NET_ADMIN`
нужен для TUN/NAT, `CAP_NET_BIND_SERVICE` — для портов ниже 1024, включая UDP 443.
Служба не запускается целиком от root. Установщик добавляет `--datapath`: без него
сервер отвечает на рукопожатия, но не пересылает IP-пакеты. `active` доказывает
только работу процесса; интернет через VPN проверяйте отдельно с клиента.

**EN.** The service runs as the system account `bproto`. `CAP_NET_ADMIN` permits
TUN/NAT; `CAP_NET_BIND_SERVICE` permits low ports including UDP 443. The process
does not run entirely as root. The installer sets `--datapath`: without it the
server answers handshakes but drops IP packets. An `active` service proves only
that the process is running; test Internet forwarding from a client separately.

**RU.** Проверка файла до перезапуска / **EN.** Validate before restarting:

```bash
sudo /usr/local/bin/vpn-server --check-config --config /etc/bproto/server.toml
sudo systemctl cat bproto-server
```

<a id="nat"></a>
## Публичный адрес, NAT и forwarding / Public endpoint, NAT and forwarding

**RU.** Автоматическое определение IP часто возвращает **локальный** адрес VPS
за NAT. В клиентской конфигурации должен стоять адрес, доступный пользователю
из интернета: публичный IP и внешний UDP-порт. Проверьте его в панели провайдера.
Если VPS находится за NAT, настройте перенаправление UDP снаружи на порт сервера.
Имя интерфейса для исходящего трафика не всегда `eth0` — встречаются `ens3`, `enp1s0`.

**EN.** Automatic address detection can return a **private** address on a
NAT-backed VPS. The client needs an endpoint reachable from its network:
public IP and external UDP port. Check your provider’s console. If the VPS is
behind NAT, forward the external UDP port to the server. The outbound interface
is not always `eth0`; `ens3` and `enp1s0` are common.

```bash
ip route get 1.1.1.1
sysctl net.ipv4.ip_forward
sudo nft list ruleset
sudoedit /etc/bproto/server.toml
```

**RU.** `nat_interface` должен совпадать с `dev` из маршрута наружу.
`net.ipv4.ip_forward` должен быть `1`. Не заменяйте весь действующий ruleset
командами из случайной инструкции: это может оборвать SSH или другие сервисы.
**EN.** Set `nat_interface` to the outbound route’s `dev` value. IPv4 forwarding
must be `1`. Do not replace the whole firewall ruleset with unrelated examples;
you could disconnect SSH or other services.
