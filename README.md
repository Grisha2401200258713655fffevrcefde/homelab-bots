# Homelab Bots

Два Telegram-бота под хомлаб, поднимаются одной командой через docker-compose.
Требуется всего два токена (BotFather). Распределены по принципу "кто что трогает":

- **content-scout** (`@homelab_scout_bot`) — всё, что работает через обычные
  HTTP-запросы, без спецправ и без SSH:
  - парсинг RSS (Reddit, Habr, ServeTheHome, YouTube и т.д.), фильтр по
    ключевым словам
  - `/waste` — простаивающие контейнеры (Prometheus)
  - `/certs` — истечение SSL-сертификатов (TLS-хендшейк)

- **sentry-ops** (`@lab_sentry_bot`) — всё, что требует повышенных прав:
  raw-сканы сети (`NET_RAW`/`NET_ADMIN`) и SSH-доступ к нодам кластера:
  - `/scan` — автоскан подсети (nmap) + Nuclei по найденным веб-сервисам,
    опционально с объяснением через локальную Ollama
  - `/backup` — реально скачивает случайный файл бэкапа (MinIO) и
    тестирует целостность архива, либо смотрит статус задач Duplicati
  - `/bloat` — по SSH обходит все ноды, считает reclaimable место в Docker
  - `/drift` — ловит ручные правки конфигов на серверах, забытые в git

## Установка одной командой

```bash
git clone https://github.com/Grisha2401200258713655fffevrcefde/homelab-bots.git
cd homelab-bots
chmod +x setup.sh
./setup.sh
```

## Ручной запуск

```bash
cp .env.example .env
nano .env   # впиши токены + опциональные секции
docker compose up -d --build
```

## Структура

```
homelab-bots/
├── docker-compose.yml
├── setup.sh
├── .env.example
├── content-scout/            # RSS + waste + certs (HTTP-only, без спецправ)
│   ├── bot.py
│   ├── feeds.yaml             # источники и ключевые слова — правится без пересборки
│   ├── Dockerfile
│   └── requirements.txt
└── sentry-ops/                # network scan + backup + bloat + drift (raw/SSH)
    ├── bot.py
    ├── Dockerfile
    └── requirements.txt
```

## SSH-доступ (для /bloat и /drift в sentry-ops)

Нужен приватный SSH-ключ с доступом ко всем нодам кластера (тот же, что уже
используется для passwordless-доступа с srv1). Путь на хосте — `.env` →
`SSH_KEY_HOST_PATH` (по умолчанию `/home/admin1/.ssh/id_rsa`), монтируется
в контейнер read-only.

## Обязательная настройка перед запуском

Часть функций без конфигурации просто ответит "не сконфигурировано":

- **/waste** — проверь `PROMETHEUS_URL` (по умолчанию srv1:9090)
- **/certs** — заполни `CERT_TARGETS`, например `jellyfin.lab:443,vaultwarden.lab:443`
- **/backup** — заполни `MINIO_*` или `DUPLICATI_URL`
- **/drift** — заполни `DRIFT_WATCH_PATHS`, например
  `srv1|/etc/nginx/nginx.conf,host-196|/home/admin1/docker-compose.yml`

`/scan` и `/bloat` заработают сразу с дефолтными адресами кластера.

## Заведение своего Telegram-бота

1. `@BotFather` → `/newbot` → получаешь токен
2. `@userinfobot` → узнаёшь свой `chat_id`

## Команды в Telegram

**content-scout**: `/check`, `/sources`, `/stats`, `/waste`, `/certs`

**sentry-ops**: `/scan`, `/status`, `/hosts`, `/findings`, `/backup`, `/bloat`, `/drift`, `/rebaseline`

## Данные

SQLite-базы обоих ботов лежат в `./data/` на хосте — переживают пересборку
и рестарт. Эта папка и `.env` в `.gitignore`, в git не попадают.
