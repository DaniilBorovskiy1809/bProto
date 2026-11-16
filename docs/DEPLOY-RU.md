# Сборка и установка

## GitHub Actions

`.github/workflows/build.yml` запускается на push, pull request и вручную
через Actions → Build and test → Run workflow. Изменения workflow должны
сначала попасть в GitHub. Успешный запуск предоставляет два артефакта:

* `linux-x86_64-panel`: tar.gz с CLI, сервером, библиотекой и панелью;
* `android-debug-apk`: APK с arm64-v8a, armeabi-v7a, x86_64 и SHA256SUMS.

APK подписан отладочным ключом конкретной сборки. Это тестовый пакет;
для распространения нужна отдельная release-подпись с постоянным ключом.
Между сборками может потребоваться удаление старого приложения, что удалит
его данные. Linux-бинарники собираются на Ubuntu 24.04; совместимость с более
старой glibc не гарантируется. Автоматическая публикация GitHub Release
и установка на сервер этим workflow не выполняются.

## Сервер

Используйте Linux VPS с публичным IPv4, TUN, systemd и правами root.
Установите Rust 1.88+ по официальной инструкции rustup, затем:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config ca-certificates iproute2 nftables openssl git
git clone https://github.com/dr-lexus-dr/bProto.git
cd bProto
./build_app.sh --no-panel
sudo ./install.sh server --port 443
```

Установщик создаёт `/etc/bproto/server.toml` и клиентскую конфигурацию.
Существующую конфигурацию сохраняет, если не указан `--force-config`.
Проверьте `nat_interface` в server.toml по `ip route get 1.1.1.1`,
откройте UDP 443 в firewall VPS и у провайдера. Административный порт
9100 оставьте доступным только на loopback.

```sh
sudo /usr/local/bin/vpn-server --check-config --config /etc/bproto/server.toml
sudo systemctl status bproto-server
sudo journalctl -u bproto-server -n 100 --no-pager
```

Точное имя установленного unit и команды управления также выводит установщик.
Ключи и клиентские файлы не публикуйте в issues, логах или артефактах CI.
Для подключения и проверки маршрутизации следуйте разделу 4 `INSTALL.md`.

## Панель

Установите Docker Engine с Compose plugin, направьте DNS домена на VPS,
откройте TCP 80/443 для Caddy и выполните из checkout:

```sh
sudo ./install.sh panel --domain panel.example.com
```

Замените домен своим. Сохраните выданные реквизиты безопасно. Проверьте
`docker compose -f panel/docker-compose.yml ps` и HTTPS-вход в панель.
`BPROTO_TAG_KEY` должен совпадать с `tag_key` сервера. Панель пока не
передаёт ключи серверу автоматически: выполните ручной шаг из
`docs/INSTALL.md`, раздел 5.5. Подробности переменных — в `panel/README.md`.

## Ограничения обнаружения и блокировки

Нельзя гарантировать, что РКН или другой оператор не обнаружит и не
заблокирует VPN: возможны DPI, блокировка IP, UDP и активное зондирование.
В текущей версии есть шифрование и аутентификация, но режим маскировки
под донорский TLS, FEC и live rekey ещё не реализованы. Порт UDP 443
не превращает этот протокол в HTTP/3. Поля donor_sni/fingerprint в панели
не доказывают наличие маскировки в транспортном коде.

Перед использованием проверьте DNS, IPv6 и поведение при обрыве связи.
На Android включите системный Always-on VPN и блокировку соединений без
VPN, если устройство это поддерживает. IPv6 fallback и отсутствие
встроенного kill switch описаны в `apps/android/README.md`.
