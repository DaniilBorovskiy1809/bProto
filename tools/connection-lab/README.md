# Стенд подключения bProto / Connection lab

Ветка: `test/connection-lab`. Стенд не устанавливает production-службу,
не использует рабочие ключи панели и не меняет маршруты хоста в обычном режиме.
Python 3.11+ и Rust/Cargo нужны для локальной сборки. Созданные ключи находятся
в `.connection-lab/` (`0700`, файлы `0600`), каталог исключён из Git.

## 1. Автоматическая проверка без root

Из корня репозитория:

```bash
git switch test/connection-lab
python3 tools/connection_lab.py doctor
python3 tools/connection_lab.py build
python3 tools/connection_lab.py smoke
cargo test --locked -p vpn-core --test tunnel_e2e
```

`smoke` поднимает настоящий UDP-сервер на свободном loopback-порту, валидирует
конфиги, выполняет настоящее рукопожатие, проверяет выдачу `10.66.0.2`, затем
проверяет отказ клиента с неверным PSK. Чужие процессы не останавливает; свой
сервер и временные ключи убирает после проверки. Вывод — JSON с результатами,
без секретов. Ненулевой exit code означает ошибку, а не пропуск теста.

Пять существующих `tunnel_e2e`-тестов дополнительно проверяют передачу пакетов
в обе стороны через реальные UDP-сокеты, неправильный ключ, разных пользователей
и тихую сессию. Их TUN-сторона — канал в памяти, **не устройство ядра**.

## 2. Ручной сервер и Linux-клиент

```bash
python3 tools/connection_lab.py init
# Терминал 1: сервер работает, пока вы не нажмёте Ctrl+C.
python3 tools/connection_lab.py server
# Терминал 2:
python3 tools/connection_lab.py check --seconds 10
```

По умолчанию сервер слушает `127.0.0.1:4443`, клиент берёт `.connection-lab/client.toml`.
Повторный `init` отказывается перезаписывать существующий каталог: ключи случайно
не меняются. Для второго стенда используйте новый каталог:

```bash
python3 tools/connection_lab.py --directory /tmp/my-second-lab init \
  --listen 127.0.0.1:5443 --endpoint 127.0.0.1:5443
python3 tools/connection_lab.py --directory /tmp/my-second-lab server
```

Без `--datapath` это **проверка установления соединения**, не интернет через VPN:
сервер отвечает на рукопожатие, но IP-пакеты не пересылает. Android может показать
подключение после рукопожатия, а сайты не откроются — в этом режиме это ожидаемо.

## 3. Android: получить ключ

В приватном терминале:

```bash
# СЕКРЕТНЫЙ вывод: не публикуйте URI и QR.
python3 tools/connection_lab.py uri
```

URI содержит те же PSK/tag key, что и сервер. Вставьте его в Android → «Добавить
профиль или подписку». `127.0.0.1` на телефоне означает **сам телефон** и не
ведёт к серверу на компьютере.

Для стандартного Android Emulator, запущенного на той же машине, где сервер:

```bash
python3 tools/connection_lab.py uri --endpoint 10.0.2.2:4443
```

Для физического телефона сервер должен иметь доступный LAN/public IP и UDP-порт.
Используйте отдельную тестовую VM/VPS или подходящий LAN-хост. Текущий cloud
loopback-стенд не является публичным адресом телефона. `uri --endpoint` меняет
только импортируемый адрес, а не привязку сокета или firewall.

```bash
# Новый приватный каталог; замените 192.0.2.10 реальным IP сервера.
python3 tools/connection_lab.py --directory /tmp/phone-lab init \
  --listen 0.0.0.0:4443 --endpoint 192.0.2.10:4443
python3 tools/connection_lab.py --directory /tmp/phone-lab server
python3 tools/connection_lab.py --directory /tmp/phone-lab uri
```

Этот пример по-прежнему проверяет только рукопожатие. Разрешайте UDP 4443
только из нужной тестовой сети; не публикуйте ключи и не отключайте рабочий firewall.

## 4. Настоящий TUN: изолированный Docker-сценарий

Требования: Linux Docker host с `/dev/net/tun`, Docker Compose v2, разрешённые
`NET_ADMIN` в контейнерах и возможность namespaced IPv4 forwarding.
`DAC_READ_SEARCH` позволяет контейнерному root прочитать readonly fixtures с
правами `0600`, не ослабляя права ключей на хосте. Проверку
выполняйте на отдельной тестовой VM. `network_mode: host` и `privileged: true`
не используются. Маршрут клиента меняется **только внутри контейнера**.

Сборка использует системный CA bundle через BuildKit secret для проверки TLS
Cargo, не отключая проверку сертификатов и checksum. При другом расположении
trust store задайте `BPROTO_LAB_CA_FILE=/path/to/trusted-ca-bundle.pem`. Сертификат
не встраивается в image и не попадает в Git.

Сначала создайте ключи командой `init` (если их ещё нет), затем:
Если native-сервер уже занимает UDP 4443, остановите его или задайте
`BPROTO_LAB_PORT=5444` перед Compose-командой.

```bash
docker compose -f tools/connection-lab/compose.yaml config --quiet
docker compose -f tools/connection-lab/compose.yaml up --build \
  --abort-on-container-exit --exit-code-from probe
# Завершение и уборка контейнеров/сети; ключи сохраняются:
docker compose -f tools/connection-lab/compose.yaml down
```

Сервер и клиент находятся в разных network namespaces. Probe выполняет реальное
рукопожатие, создаёт клиентский TUN и требует **3/3** ответов `ping -I bplabc0
10.66.0.1`. Это доказывает двусторонний проход пакетов через TUN/шифрование;
проверка не выдаёт результат успешного ping за доказательство доступа в Интернет.
NAT настроен на серверный `eth0`, но внешний Интернет в автоматическом probe
не проверяется. Сервис `probe` после проверки выходит; Compose возвращает его exit code.

Для ручного подключения телефона к Docker-серверу на тестовой VM:

```bash
BPROTO_LAB_BIND=0.0.0.0 docker compose -f tools/connection-lab/compose.yaml \
  up -d --build server
python3 tools/connection_lab.py uri --endpoint 192.0.2.10:4443
# Логи и остановка:
docker compose -f tools/connection-lab/compose.yaml logs --tail 100 server
docker compose -f tools/connection-lab/compose.yaml down
```

Публичный IP замените своим, откройте только тестовый UDP 4443 и проверьте NAT
провайдера. Это явное открытие тестового listener, не настройка production.
Ключи подключаются readonly из `.connection-lab`; для другого каталога задайте
`BPROTO_LAB_STATE=/absolute/path/to/lab`. Внутренний порт Docker всегда 4443;
`BPROTO_LAB_PORT` меняет опубликованный порт хоста.

## 5. Диагностика и сохранение результатов

- `doctor` показывает наличие TUN и `CAP_NET_ADMIN`, но не утверждает, что весь datapath работает.
- Ошибка bind: остановите только свой прежний сервер или выберите другой порт.
- Timeout: проверьте IP/порт, UDP firewall, совпадение ключей и часы.
- Android подключился, сайты не работают: убедитесь, что сервер запущен с datapath,
  затем проверьте forwarding, NAT и DNS; обычный `server` intentionally handshake-only.
- Ошибка `/dev/net/tun`: включите TUN у провайдера/на тестовой VM. Не обходите её
  подменой успешного результата теста.
- Локальные client/server TOML и URI — секреты. Не коммитьте их в тестовую ветку.

В CI native smoke выполняется после сборки бинарников, а тесты генератора —
без root. Результаты проверки текущей ветки — в `VALIDATION.md` рядом с этой инструкцией.

## English quick reference

`python3 tools/connection_lab.py build`, then `smoke` verifies a real loopback UDP
handshake, address lease and wrong-PSK failure without root or host route changes.
`init` creates fresh private configs; `server` stays in the foreground; `check`
connects using the generated client. `uri` explicitly prints secret Android
credentials; `uri --endpoint IP:PORT` changes the imported address only.

Default loopback cannot be reached from a physical phone. Use a LAN/VPS endpoint
or `10.0.2.2` for an Android emulator on the server's host. Handshake-only mode
cannot forward Internet traffic. The optional Compose probe requires a real
TUN-capable Docker host, uses separate server/client network namespaces and
asserts three ICMP replies through the tunnel. Neither native smoke nor tunnel
ping claims Internet forwarding, Android device validation or censorship bypass.

## 6. Захват собственного тестового трафика

Compose теперь поднимает также внутренний HTTP-сервис и capture-sidecar в
сетевом namespace сервера. Probe требует не только 3/3 ping, но и HTTP 200 от
`10.66.0.1:8088/probe` с известным синтетическим маркером `BPROTO_LAB_PROBE`.
Никакие PSK или пользовательские данные в HTTP-запрос не добавляются.

Capture использует `NET_RAW` и `SETGID` (для инициализации групп tcpdump), без
`privileged` и без доступа к fixtures с ключами. `--immediate-mode` и `-U`
уменьшают буферизацию, а probe оставляет время на обработку последних пакетов.
Захват ограничен тестовыми UDP 4443, ICMP и TCP 8088. HTTP-порт не публикуется
на хосте. PCAP и таблица интерфейсов пишутся в отдельный named volume.

Пример сохранения результата после завершения теста, **до** `down`:

```bash
# После up --abort-on-container-exit --exit-code-from probe для этого проекта:
install -d -m0700 .connection-lab/captures
capture_id="$(docker compose -p bproto-capture-check -f tools/connection-lab/compose.yaml ps -a -q capture)"
docker cp "$capture_id:/captures/server.pcap" .connection-lab/captures/server.pcap
docker cp "$capture_id:/captures/interfaces.json" .connection-lab/captures/interfaces.json
chmod 600 .connection-lab/captures/*
python3 tools/connection-lab/analyze_capture.py   .connection-lab/captures/server.pcap .connection-lab/captures/interfaces.json
# Только этот временный тестовый проект, после копирования артефактов:
docker compose -p bproto-capture-check -f tools/connection-lab/compose.yaml down -v
```

Запускайте up с тем же `-p bproto-capture-check`; при занятом порте задайте
`BPROTO_LAB_PORT=5444`. Анализатор требует SLL2 capture, внешние UDP-пакеты,
HTTP-запрос и ответ на интерфейсе `bplab0`. Он выдаёт ошибку для пустого capture,
отсутствующих доказательств или открытого маркера во внешнем UDP.

Открытый HTTP/ICMP внутри TUN ожидаем: это пакеты после расшифрования/до
шифрования. Отсутствие известной строки во внешнем UDP — регрессионная проверка,
не доказательство отсутствия любых утечек и не криптографический аудит.
Это тест серверной части с автоматическим Linux probe, не проверка Android UI.
