# Homelab Bots

Семь Telegram-ботов под хомлаб, поднимаются одной командой через docker-compose.

- **content-scout** — парсит RSS (Reddit, Habr, ServeTheHome, YouTube и т.д.),
  фильтрует по ключевым словам, шлёт новое в Telegram
- **security-scanner** — автоматически сканирует твою подсеть (nmap),
  находит сервисы, прогоняет веб-сервисы через Nuclei, шлёт алерты
  (опционально с объяснением через локальную Ollama)
- **backup-verify** — реально скачивает случайный файл из последнего бэкапа
  (MinIO) и проверяет целостность архива; либо смотрит статус задач Duplicati
- **resource-waste** — анализирует Prometheus за 30 дней, находит контейнеры
  с почти нулевым CPU, но заметным RAM — конкретный список "можно снести"
- **docker-bloat** — по SSH обходит все ноды, считает висящие образы и
  reclaimable место через `docker system df`
- **cert-monitor** — проверяет SSL-сертификаты твоих сервисов, шлёт алерт
  за N дней до истечения
- **config-drift** — по SSH снимает конфиги с нод, сравнивает с baseline —
  ловит ручные правки на сервере, которые забыли закоммитить

## Установка одной командой

```bash
git clone <URL-твоего-репозитория> homelab-bots
cd homelab-bots
chmod +x setup.sh
./setup.sh
```

Скрипт сам:
1. поставит Docker, если его нет
2. создаст `.env` из шаблона и попросит вписать токены ботов
3. соберёт и запустит оба контейнера

## Ручной запуск (если не нужен setup.sh)

```bash
cp .env.example .env
nano .env   # впиши SCOUT_BOT_TOKEN, SCOUT_CHAT_ID, SCANNER_BOT_TOKEN, SCANNER_CHAT_ID
docker compose up -d --build
```

## Структура

```
homelab-bots/
├── docker-compose.yml       # все 7 сервисов + nuclei-updater
├── setup.sh                 # установка одной командой
├── .env.example             # шаблон конфига (токены всех ботов, интервалы, ноды)
├── content-scout/           # бот-парсер (feedparser + aiogram)
├── security-scanner/        # бот-сканер сети (nmap + nuclei + aiogram)
├── backup-verify/           # проверка бэкапов (MinIO / Duplicati)
├── resource-waste/          # простаивающие ресурсы (Prometheus)
├── docker-bloat/            # bloat образов по SSH
├── cert-monitor/            # истечение SSL
└── config-drift/            # дрейф конфигов по SSH
```

Каждая папка — свой `bot.py` + `Dockerfile` + `requirements.txt`.

## SSH-доступ (для docker-bloat и config-drift)

Этим двум ботам нужен приватный SSH-ключ с доступом ко всем нодам кластера
(тот же, что уже используется для passwordless-доступа с srv1). Путь к нему
на хосте указывается в `.env` как `SSH_KEY_HOST_PATH` — по умолчанию
`/home/admin1/.ssh/id_rsa`, docker-compose примонтирует его в контейнеры
read-only.

## Обязательная настройка перед запуском

Некоторые боты без минимальной конфигурации просто ничего не найдут:

- **backup-verify** — заполни `MINIO_*` или `DUPLICATI_URL` в `.env`
- **resource-waste** — проверь `PROMETHEUS_URL` (по умолчанию srv1:9090)
- **cert-monitor** — заполни `CERT_TARGETS` (например `jellyfin.lab:443,vaultwarden.lab:443`)
- **config-drift** — заполни `DRIFT_WATCH_PATHS` (например `srv1|/etc/nginx/nginx.conf,host-196|/home/admin1/docker-compose.yml`)

Без этого боты просто ответят "не сконфигурировано" вместо ошибки.

## Заведение своего Telegram-бота

1. `@BotFather` в Telegram → `/newbot` → получаешь токен
2. `@userinfobot` → узнаёшь свой `chat_id`
3. Можно использовать одного бота для обоих сервисов (один токен, один chat_id)
   или двух разных — тогда сообщения не будут перемешиваться в одном чате

## Команды в Telegram

**content-scout**: `/check`, `/sources`, `/stats`
**security-scanner**: `/scan`, `/status`, `/hosts`, `/findings`
**backup-verify**: `/verify`, `/history`
**resource-waste**: `/scan`
**docker-bloat**: `/scan`, `/nodes`
**cert-monitor**: `/check`
**config-drift**: `/check`, `/rebaseline`

## Данные

Персистентные данные (SQLite базы) лежат в `./data/` на хосте —
переживают пересборку и рестарт контейнеров. Эта папка в `.gitignore`,
как и `.env` — токены и история сканов в git не попадут.

## Публикация в свой git

Репозиторий уже инициализирован локально. Чтобы залить на свой GitHub/Gitea:

```bash
git remote add origin <URL-твоего-пустого-репозитория>
git branch -M main
git push -u origin main
```
