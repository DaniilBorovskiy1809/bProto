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

<a id="firewall"></a>
## Порты и firewall / Ports and firewall

| Порт / Port | Для чего / Purpose | Доступ / Exposure |
| --- | --- | --- |
| UDP 443, либо выбранный / or selected port | VPN transport | Клиентам / Client networks |
| TCP 80 | Caddy HTTP / ACME | Интернет при установке панели / Internet for panel setup |
| TCP 443 | HTTPS панели / Panel HTTPS | Пользователям панели / Panel users |
| TCP 8080 | Backend панели / Panel backend | Только Compose network / Compose network only |
| TCP 9100 | Административный endpoint сервера / Server administration | Loopback only |
| TCP 22, либо SSH-порт / or SSH port | SSH | По вашей политике / Your access policy |

**RU.** UDP 443 и TCP 443 — разные сокеты: VPN и HTTPS-панель могут использовать
один номер порта на одном VPS. Однако HTTP/3 Caddy или другой UDP-сервис может
занять UDP 443; проверяйте `ss`. Кроме firewall ОС часто есть отдельный security
group у провайдера. Разрешите SSH **до** включения нового firewall.

**EN.** UDP 443 and TCP 443 are different sockets: the tunnel and HTTPS panel
can share the port number. Caddy HTTP/3 or another UDP service can still occupy
UDP 443, so inspect listeners. Cloud-provider security groups are separate
from the host firewall. Allow SSH **before** enabling a new firewall.

```bash
sudo ss -lntup
# If UFW is already your chosen firewall:
sudo ufw allow 443/udp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw status verbose
```

<a id="server-config"></a>
## Конфигурация сервера / Server configuration

**RU.** Редактируйте существующий файл через `sudoedit`, сохраняя ключи.
Ниже — схема, не готовый секретный конфиг: замените placeholders реальными
значениями. Для рабочего первого конфига используйте генерацию установщика.

**EN.** Edit the existing file with `sudoedit`, preserving keys. This is a
schema example, not a usable secret configuration. Replace placeholders with
real values, or let the installer generate the initial configuration.

```toml
listen_addr = "0.0.0.0:443"
tag_key = "<64 hex characters shared with the panel>"

[donor]
sni = "www.cloudflare.com"

[tun]
name = "bproto0"
address = "10.66.0.1"
netmask = "255.255.255.0"
mtu = 1280
nat_interface = "ens3"

[admin]
listen_addr = "127.0.0.1:9100"
token = "<64 hex characters>"

[[users]]
id = 1
psk = "<64 hex characters for this user>"
```

**RU.** `tag_key` общий для развёртывания, `psk` индивидуален. SNI в текущей
версии не делает UDP-трафик похожим на настоящий HTTPS. Смена ключей без
обновления клиентов разрывает совместимость. После изменений выполните
`--check-config`, затем перезапустите службу.

**EN.** `tag_key` is shared across the deployment; PSKs are individual. The SNI
field does not make current UDP traffic indistinguishable from HTTPS. Changing
keys without updating clients breaks compatibility. Run `--check-config`
after changes, then restart the service.

<a id="keys"></a>
## Ключи и первый клиент / Keys and the first client

**RU.** Начальный файл `/etc/bproto/user1.client.toml` уже содержит PSK и tag key.
Скопируйте его на Linux-клиент защищённым способом и исправьте публичный endpoint.
Не публикуйте файл в issue. Для Android обычно удобнее URI из панели. Если панель
ещё не установлена, URI для начального клиента можно создать из TOML:

**EN.** `/etc/bproto/user1.client.toml` already contains a PSK and tag key.
Transfer it securely to a Linux client and correct its public endpoint. Never
attach it to an issue. Android normally imports a URI from the panel. Before
installing a panel, you can convert the initial TOML file into a URI:

```bash
# Python 3.11+. Output is SECRET: do not record or publish it.
sudo python3 - <<'PYCODE'
import base64, json, tomllib
with open('/etc/bproto/user1.client.toml', 'rb') as file:
    config = tomllib.load(file)
body = dict(v=1, server=config['server'], uid=config['user_id'],
            sni=config['donor']['sni'], psk=config['psk'],
            tag_key=config['tag_key'], fp=config.get('fingerprint', 'chrome112'))
encoded = base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip('=')
print('bproto://import/' + encoded)
PYCODE
```

**RU.** До конвертации исправьте `server` на публичный IP:port. URI эквивалентен
секретному конфигу, а QR-код — визуальное представление этого же секрета.
**EN.** Correct `server` to the public IP:port before converting. The URI is
secret configuration material; its QR code contains the same secret.

<a id="linux-client"></a>
## Linux CLI / Linux client

**RU.** Серверный bootstrap с `--target all` ставит CLI на VPS для обслуживания;
для использования VPN установите CLI на отдельное Linux-устройство. Режим
`connect` проверяет рукопожатие, но не меняет маршруты. `up` создаёт TUN и
меняет default route, поэтому требует root. При удалённой проверке полный
туннель может изменить маршрут вашего SSH-соединения.

**EN.** Server bootstrap with `--target all` installs the CLI for maintenance;
install it on a separate Linux device to use the VPN. `connect` tests the
handshake without changing routes. `up` creates TUN and changes the default
route, requiring root. A full tunnel on a remote machine can change the route
used by your SSH session.

```bash
bproto --version
bproto import 'bproto://import/REPLACE_WITH_YOUR_KEY' --out client.toml
chmod 600 client.toml
bproto --config client.toml check
bproto --config client.toml connect --seconds 5
sudo bproto --config client.toml up
# Configure TUN without moving the default route:
sudo bproto --config client.toml up --no-default-route
```

**RU.** CLI не предоставляет Android package exclusions и не импортирует JSON
подписку как список серверов. DNS в Linux настраивает оператор. Подробности
отката маршрутов и DNS находятся в [INSTALL.md](docs/INSTALL.md).
**EN.** The CLI does not implement Android package exclusions or import a JSON
subscription as a server list. Linux DNS remains operator-managed. See
[INSTALL.md](docs/INSTALL.md) for route rollback and DNS details.

<a id="android"></a>
## Android: установка и глобус / Android installation and globe

**RU.** Скачайте APK только из [релиза проекта](https://github.com/dr-lexus-dr/bProto/releases).
Устройство должно разрешать установку из выбранного источника. В релизе 1.0.0
APK подписан debug-ключом. Если Android сообщает о несовместимой подписи при
обновлении, потребуется удаление старого приложения; сначала сохраните свою
подписку, поскольку профили устройства будут удалены.

**EN.** Download the APK from the [project release](https://github.com/dr-lexus-dr/bProto/releases).
Allow installation from your selected source. Release 1.0.0 is debug-signed.
If an update fails because the signatures differ, uninstalling the old app may
be necessary. Keep your subscription before doing so; device profiles are removed.

1. **RU:** вставьте `bproto://import/...` или HTTPS-подписку. **EN:** paste a key URI or HTTPS subscription.
2. **RU:** импортируйте подписку и выберите сервер. **EN:** import the subscription and choose a server.
3. **RU:** нажмите глобус и разрешите создание VPN. **EN:** tap the globe and grant VPN consent.
4. **RU:** дождитесь подтверждения соединения. **EN:** wait for connected status.
5. **RU:** повторное нажатие отключает VPN. **EN:** tap again to disconnect.

**RU.** Рисунок глобуса — кнопка подключения, не карта реальных координат серверов.
Проверки сборки не заменяют испытания на вашем физическом устройстве.
**EN.** The globe is a connection control, not a map of verified server locations.
Build validation does not replace testing on your physical device.

<a id="profiles"></a>
## Профили Android / Android profiles

**RU.** Импортированные серверы сохраняются зашифрованными AES-GCM с ключом
Android Keystore. Секреты не записываются в обычные preferences и исключены из
backup storage. Выбор сервера и режим Automatic запоминаются отдельно без
сохранения URI в открытом виде. Кнопка сервера повторно открывает список.

**EN.** Imported servers are stored using AES-GCM with an Android Keystore key.
Secrets are not stored in ordinary preferences and are excluded from backup
storage. Selected server and Automatic mode are remembered separately without
storing a plaintext URI. The server button reopens the imported list.

**RU.** `Routing settings` меняет маршрутизацию выбранного профиля. `Reset to
full tunnel` возвращает маршрут по умолчанию. `Forget profiles` удаляет список
после подтверждения. Повторный импорт заменяет профили и локальные overrides:
сохраните нужные правила в панели, если они должны переживать обновление подписки.

**EN.** `Routing settings` changes the selected profile’s routing policy.
`Reset to full tunnel` restores defaults. `Forget profiles` removes the list
after confirmation. Reimporting replaces profiles and local overrides; store
rules in the panel if they must survive subscription refreshes.

**RU.** Скопировать файл профилей на другой телефон недостаточно: ключ Keystore
не переносится вместе с файлом. При сбросе/потере ключа импортируйте подписку заново.
**EN.** Copying the encrypted file to another phone is insufficient: its Keystore
key does not move with it. Reimport after a reset or loss of the local key.
