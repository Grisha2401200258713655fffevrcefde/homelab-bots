# Homelab Bots

Два Telegram-бота под хомлаб, поднимаются одной командой через docker-compose.

- **content-scout** — парсит RSS (Reddit, Habr, ServeTheHome, YouTube и т.д.),
  фильтрует по ключевым словам, шлёт новое в Telegram
- **security-scanner** — автоматически сканирует твою подсеть (nmap),
  находит сервисы, прогоняет веб-сервисы через Nuclei, шлёт алерты
  (опционально с объяснением через локальную Ollama)

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
├── docker-compose.yml       # оба сервиса + nuclei-updater
├── setup.sh                 # установка одной командой
├── .env.example             # шаблон конфига (токены, интервалы, подсеть)
├── content-scout/           # бот-парсер (feedparser + aiogram)
│   ├── bot.py
│   ├── feeds.yaml           # источники и ключевые слова — правится без пересборки
│   ├── Dockerfile
│   └── requirements.txt
└── security-scanner/        # бот-сканер (nmap + nuclei + aiogram)
    ├── bot.py
    ├── Dockerfile
    └── requirements.txt
```

## Заведение своего Telegram-бота

1. `@BotFather` в Telegram → `/newbot` → получаешь токен
2. `@userinfobot` → узнаёшь свой `chat_id`
3. Можно использовать одного бота для обоих сервисов (один токен, один chat_id)
   или двух разных — тогда сообщения не будут перемешиваться в одном чате

## Команды в Telegram

**content-scout**: `/check`, `/sources`, `/stats`
**security-scanner**: `/scan`, `/status`, `/hosts`, `/findings`

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
