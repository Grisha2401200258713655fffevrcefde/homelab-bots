# Homelab Bots

Два Telegram-бота под хомлаб, поднимаются одной командой через docker-compose.
Требуется всего два токена (BotFather). Распределены по принципу "кто что трогает".

## content-scout (`@homelab_scout_bot`)
Всё, что работает через обычные HTTP-запросы, без спецправ и без SSH:

- парсинг RSS (Reddit, Habr, ServeTheHome, YouTube и т.д.), фильтр по ключевым словам
- **перевод статей** — вытаскивает полный текст (не только RSS-сниппет) через
  экстрактор контента, переводит на русский через **deep-translator (без ИИ/LLM,
  обычный машинный перевод)**, шлёт сначала перевод (🇷🇺), потом оригинал (🇬🇧).
  Русскоязычные источники (Habr) не переводятся — определяется автоматически
  по доле кириллицы в тексте
- `/waste` — простаивающие контейнеры (Prometheus)
- `/certs` — истечение SSL-сертификатов (TLS-хендшейк)
- `/sla` — % аптайма по сервисам за месяц (Prometheus `up`)
- `/forecast` — **прогноз заполнения дисков через линейную регрессию** по тренду
  за последние N дней (не статичный порог "диск заполнен на 90%", а "по текущей
  скорости съедания места закончится через ~X дней")

## sentry-ops (`@lab_sentry_bot`)
Всё, что требует повышенных прав: raw-сканы сети (`NET_RAW`/`NET_ADMIN`) и SSH:

- `/scan` — автоскан подсети (nmap) + Nuclei по найденным веб-сервисам,
  опционально с объяснением через локальную Ollama
- `/backup` — реально скачивает случайный файл бэкапа (MinIO) и тестирует
  целостность архива, либо смотрит статус задач Duplicati
- `/bloat` — по SSH обходит все ноды, считает reclaimable место в Docker
- `/drift` — ловит ручные правки конфигов на серверах, забытые в git
- `/maintenance <нода> <минуты>` — заглушает алерты по ноде на время (не спамит,
  пока ты сам что-то чинишь руками)
- `/blast <сервис>` — граф зависимостей по `depends_on` из docker-compose файлов:
  что упадёт, если остановить/перезапустить сервис
- критичные алерты (nuclei critical/high, упавший бэкап) шлются с кнопкой
  "✅ Подтвердить" — если не подтверждено за `ESCALATION_MINUTES`, бот
  присылает повторно с пометкой "не подтверждено"
- `/audit` — последние выполненные команды (в каждом боте свой лог)

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
├── content-scout/            # RSS + waste + certs + SLA + forecast (HTTP-only)
│   ├── bot.py
│   ├── feeds.yaml             # источники и ключевые слова — правится без пересборки
│   ├── Dockerfile
│   └── requirements.txt
└── sentry-ops/                # scan + backup + bloat + drift + maintenance + blast (raw/SSH)
    ├── bot.py
    ├── Dockerfile
    └── requirements.txt
```

## SSH-доступ (для /bloat, /drift, /blast в sentry-ops)

Нужен приватный SSH-ключ с доступом ко всем нодам кластера (тот же, что уже
используется для passwordless-доступа с srv1). Путь на хосте — `.env` →
`SSH_KEY_HOST_PATH` (по умолчанию `/home/admin1/.ssh/id_rsa`), монтируется
в контейнер read-only.

## Обязательная настройка перед запуском

Часть функций без конфигурации просто ответит "не сконфигурировано":

- **/waste** — проверь `PROMETHEUS_URL` (по умолчанию srv1:9090)
- **перевод статей** — работает "из коробки" без дополнительной настройки
  (использует бесплатный веб-эндпоинт Google Translate через deep-translator,
  никакой ИИ/LLM не задействован). Если перевод не нужен — `TRANSLATE_ENABLED=false`
- **/certs** — заполни `CERT_TARGETS`, например `jellyfin.lab:443,vaultwarden.lab:443`
- **/sla** — тот же `PROMETHEUS_URL`, нужна метрика `up` (стандартная для Prometheus)
- **/forecast** — нужен `node_exporter` на нодах (метрика `node_filesystem_avail_bytes`)
- **/backup** — заполни `MINIO_*` или `DUPLICATI_URL`
- **/drift** — заполни `DRIFT_WATCH_PATHS`, например
  `srv1|/etc/nginx/nginx.conf,host-196|/home/admin1/docker-compose.yml`
- **/blast** — заполни `COMPOSE_PATHS`, например
  `srv1|/home/admin1/homelab-infra/homelab-bot/docker-compose.yml,host-196|/home/admin1/docker-compose.yml`

`/scan` и `/bloat` заработают сразу с дефолтными адресами кластера.

## Как работает прогноз заполнения дисков (/forecast)

Не "диск заполнен на N%" (статичный порог, срабатывает поздно), а тренд:
бот берёт историю `node_filesystem_avail_bytes` за `FORECAST_LOOKBACK_DAYS`
(по умолчанию 14) из Prometheus, считает наклон прямой методом наименьших
квадратов (линейная регрессия) отдельно для каждой файловой системы на каждой
ноде, и если диск устойчиво тает — экстраполирует, через сколько дней он
закончится. Алерт только если это меньше `FORECAST_WARN_DAYS` (по умолчанию 30).

## Как работает on-call эскалация

Критичные находки (`critical`/`high` от Nuclei) и упавшие бэкапы приходят
с inline-кнопкой "✅ Подтвердить". Если за `ESCALATION_MINUTES` (по умолчанию
30) никто не нажал — фоновая задача каждые `ESCALATION_CHECK_MINUTES`
(по умолчанию 10) проверяет неподтверждённые алерты и присылает их повторно
с пометкой "⚠️ ПОВТОРНО". Эскалация срабатывает один раз на алерт, чтобы не
спамить бесконечно.

## Заведение своего Telegram-бота

1. `@BotFather` → `/newbot` → получаешь токен
2. `@userinfobot` → узнаёшь свой `chat_id`

## Команды в Telegram

**content-scout**: `/check`, `/sources`, `/stats`, `/waste`, `/certs`, `/sla`, `/forecast`, `/audit`

**sentry-ops**: `/scan`, `/status`, `/hosts`, `/findings`, `/backup`, `/bloat`, `/drift`,
`/rebaseline`, `/maintenance`, `/maintenance_clear`, `/maintenance_list`, `/blast`, `/audit`

## Данные

SQLite-базы обоих ботов лежат в `./data/` на хосте — переживают пересборку
и рестарт. Эта папка и `.env` в `.gitignore`, в git не попадают.
