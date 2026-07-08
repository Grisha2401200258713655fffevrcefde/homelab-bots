# Homelab Bots

Два Telegram-бота под хомлаб, поднимаются одной командой через docker-compose.
Требуется всего два токена (BotFather).

- **content-scout** (`@homelab_scout_bot`) — парсит RSS (Reddit, Habr,
  ServeTheHome, YouTube и т.д.), фильтрует по ключевым словам, шлёт новое
  в Telegram
- **sentry-ops** (`@lab_sentry_bot`) — комбайн из шести функций в одном
  процессе:
  - автоскан подсети (nmap) + Nuclei по найденным веб-сервисам,
    опционально с объяснением через локальную Ollama
  - проверка бэкапов — реально скачивает случайный файл (MinIO) и тестирует
    целостность архива, либо смотрит статус задач Duplicati
  - простаивающие ресурсы — Prometheus-анализ контейнеров с нулевым CPU,
    но занятым RAM
  - Docker bloat — по SSH обходит все ноды, считает reclaimable место
  - истечение SSL-сертификатов
  - дрейф конфигов — ловит ручные правки на серверах, забытые в git

## Установка одной командой

```bash
git clone https://github.com/Grisha2401200258713655fffevrcefde/homelab-bots.git
cd homelab-bots
chmod +x setup.sh
./setup.sh
```

Скрипт сам поставит Docker (если нет), создаст `.env` из шаблона и попросит
вписать токены — соберёт и запустит оба контейнера.

## Ручной запуск

```bash
cp .env.example .env
nano .env   # впиши SCOUT_BOT_TOKEN/CHAT_ID, SCANNER_BOT_TOKEN/CHAT_ID + опциональные секции
docker compose up -d --build
```

## Структура

```
homelab-bots/
├── docker-compose.yml       # 2 сервиса + nuclei-updater
├── setup.sh                 # установка одной командой
├── .env.example             # шаблон конфига
├── content-scout/           # бот-парсер (feedparser + aiogram)
│   ├── bot.py
│   ├── feeds.yaml           # источники и ключевые слова — правится без пересборки
│   ├── Dockerfile
│   └── requirements.txt
└── sentry-ops/               # бот-комбайн (nmap+nuclei+paramiko+minio+aiogram)
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

Часть функций sentry-ops без конфигурации просто ответит "не сконфигурировано":

- **/backup** — заполни `MINIO_*` или `DUPLICATI_URL`
- **/waste** — проверь `PROMETHEUS_URL` (по умолчанию srv1:9090)
- **/certs** — заполни `CERT_TARGETS`, например `jellyfin.lab:443,vaultwarden.lab:443`
- **/drift** — заполни `DRIFT_WATCH_PATHS`, например
  `srv1|/etc/nginx/nginx.conf,host-196|/home/admin1/docker-compose.yml`

## Заведение своего Telegram-бота

1. `@BotFather` → `/newbot` → получаешь токен
2. `@userinfobot` → узнаёшь свой `chat_id`

## Команды в Telegram

**content-scout**: `/check`, `/sources`, `/stats`

**sentry-ops**:
- `/scan`, `/status`, `/hosts`, `/findings` — сеть/безопасность
- `/backup` — проверка бэкапов
- `/waste` — простаивающие контейнеры
- `/bloat` — bloat Docker-образов
- `/certs` — истечение SSL
- `/drift`, `/rebaseline` — дрейф конфигов

## Данные

SQLite-базы обоих ботов лежат в `./data/` на хосте — переживают пересборку
и рестарт. Эта папка и `.env` в `.gitignore`, в git не попадают.
