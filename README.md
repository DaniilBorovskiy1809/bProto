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
