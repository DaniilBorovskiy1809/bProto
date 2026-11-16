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
