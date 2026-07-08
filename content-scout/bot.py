import asyncio
import logging
import os
import sqlite3
from datetime import datetime

import feedparser
import yaml
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("content-scout")

# ---------- Config ----------
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
CHECK_INTERVAL_MINUTES = int(os.environ.get("CHECK_INTERVAL_MINUTES", "60"))
DB_PATH = "/app/data/scout.db"
FEEDS_PATH = "/app/feeds.yaml"

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
scheduler = AsyncIOScheduler()

# ---------- Config file ----------
def load_config():
    with open(FEEDS_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg.get("feeds", []), [k.lower() for k in cfg.get("keywords", [])]

# ---------- DB ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS seen (
            url TEXT PRIMARY KEY,
            source TEXT,
            title TEXT,
            found_at TEXT
        )
    """)
    return conn

def already_seen(conn, url: str) -> bool:
    return conn.execute("SELECT 1 FROM seen WHERE url=?", (url,)).fetchone() is not None

def mark_seen(conn, url: str, source: str, title: str):
    conn.execute(
        "INSERT OR IGNORE INTO seen (url, source, title, found_at) VALUES (?,?,?,?)",
        (url, source, title, datetime.utcnow().isoformat())
    )

# ---------- Core job ----------
def matches_keywords(text: str, keywords: list[str]) -> bool:
    if not keywords:
        return True
    text_low = text.lower()
    return any(k in text_low for k in keywords)

async def check_feeds_job(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    feeds, keywords = load_config()
    conn = db()
    new_count = 0

    loop = asyncio.get_event_loop()
    for feed in feeds:
        name, url = feed["name"], feed["url"]
        try:
            parsed = await loop.run_in_executor(None, feedparser.parse, url)
        except Exception as e:
            log.warning("Failed to fetch %s: %s", name, e)
            continue

        for entry in parsed.entries[:30]:
            link = entry.get("link", "")
            title = entry.get("title", "")
            if not link or already_seen(conn, link):
                continue

            summary = entry.get("summary", "")
            if not matches_keywords(f"{title} {summary}", keywords):
                mark_seen(conn, link, name, title)  # видели, но не по теме — не спамим повторно
                continue

            mark_seen(conn, link, name, title)
            new_count += 1
            text = f"📰 <b>{name}</b>\n{title}\n{link}"
            await bot.send_message(chat, text, parse_mode="HTML", disable_web_page_preview=False)
            await asyncio.sleep(1)  # не спамить телеграм лимитами

    conn.commit()
    conn.close()

    if manual_chat_id and new_count == 0:
        await bot.send_message(chat, "Новых материалов по теме не найдено.")
    log.info("Feed check done, %d new items sent", new_count)

# ---------- Handlers ----------
@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    feeds, keywords = load_config()
    await message.answer(
        "Content Scout Bot\n\n"
        "/check — проверить фиды прямо сейчас\n"
        "/sources — список источников\n"
        "/stats — сколько всего найдено материалов\n"
        f"Автопроверка каждые {CHECK_INTERVAL_MINUTES} мин.\n"
        f"Источников: {len(feeds)}, ключевых слов: {len(keywords)}"
    )

@dp.message(Command("check"))
async def cmd_check(message: Message):
    await message.answer("🔎 Проверяю фиды...")
    await check_feeds_job(manual_chat_id=message.chat.id)

@dp.message(Command("sources"))
async def cmd_sources(message: Message):
    feeds, _ = load_config()
    lines = ["Источники:"] + [f"• {f['name']}" for f in feeds]
    await message.answer("\n".join(lines))

@dp.message(Command("stats"))
async def cmd_stats(message: Message):
    conn = db()
    total = conn.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
    conn.close()
    await message.answer(f"Всего материалов в базе: {total}")

# ---------- Main ----------
async def main():
    os.makedirs("/app/data", exist_ok=True)
    db().close()

    scheduler.add_job(check_feeds_job, "interval", minutes=CHECK_INTERVAL_MINUTES)
    scheduler.start()

    log.info("Bot starting. interval=%s min", CHECK_INTERVAL_MINUTES)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
