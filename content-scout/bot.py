import asyncio
import logging
import os
import socket
import sqlite3
import ssl
from datetime import datetime

import aiohttp
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

# --- Resource waste (Prometheus, только чтение по HTTP) ---
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://192.168.5.100:9090")
WASTE_CHECK_INTERVAL_HOURS = int(os.environ.get("WASTE_CHECK_INTERVAL_HOURS", "168"))
WASTE_LOOKBACK = os.environ.get("WASTE_LOOKBACK", "30d")
WASTE_CPU_IDLE_THRESHOLD_PCT = float(os.environ.get("WASTE_CPU_IDLE_THRESHOLD_PCT", "2"))
WASTE_MIN_MEM_MB = float(os.environ.get("WASTE_MIN_MEM_MB", "100"))

# --- Cert monitor (TLS-хендшейк, без спецправ) ---
CERT_CHECK_INTERVAL_HOURS = int(os.environ.get("CERT_CHECK_INTERVAL_HOURS", "24"))
CERT_WARN_DAYS = int(os.environ.get("CERT_WARN_DAYS", "14"))
CERT_TARGETS = os.environ.get("CERT_TARGETS", "")

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

# ---------- Resource waste job ----------
async def prom_query(query: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": query},
                                timeout=aiohttp.ClientTimeout(total=30)) as resp:
            data = await resp.json()
            if data.get("status") != "success":
                raise RuntimeError(data)
            return data["data"]["result"]

async def job_resource_waste(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    cpu_query = f'avg by (name) (rate(container_cpu_usage_seconds_total{{name!=""}}[{WASTE_LOOKBACK}])) * 100'
    mem_query = 'avg by (name) (container_memory_usage_bytes{name!=""})'
    try:
        cpu_results = await prom_query(cpu_query)
        mem_results = await prom_query(mem_query)
    except Exception as e:
        await bot.send_message(chat, f"Не смог достучаться до Prometheus ({PROMETHEUS_URL}): {e}")
        return
    mem_by_name = {}
    for r in mem_results:
        name = r["metric"].get("name", "")
        try:
            mem_by_name[name] = float(r["value"][1]) / (1024 * 1024)
        except (ValueError, KeyError):
            continue
    wasted = []
    for r in cpu_results:
        name = r["metric"].get("name", "")
        if not name:
            continue
        try:
            cpu_pct = float(r["value"][1])
        except (ValueError, KeyError):
            continue
        mem_mb = mem_by_name.get(name, 0)
        if cpu_pct < WASTE_CPU_IDLE_THRESHOLD_PCT and mem_mb >= WASTE_MIN_MEM_MB:
            wasted.append((name, cpu_pct, mem_mb))
    wasted.sort(key=lambda x: -x[2])
    if not wasted:
        await bot.send_message(chat, f"✅ За {WASTE_LOOKBACK} простаивающих контейнеров не найдено.")
        return
    total_mem = sum(m for _, _, m in wasted)
    lines = [f"💸 Простаивающие контейнеры за {WASTE_LOOKBACK}:"]
    for name, cpu, mem in wasted[:20]:
        lines.append(f"  {name}: CPU {cpu:.2f}%, RAM {mem:.0f} МБ")
    lines.append(f"\nПотенциально освободится: ~{total_mem:.0f} МБ RAM")
    await bot.send_message(chat, "\n".join(lines))

# ---------- Cert monitor job ----------
def parse_cert_targets():
    result = []
    for entry in CERT_TARGETS.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            host, port = entry.split(":", 1)
            port = int(port)
        else:
            host, port = entry, 443
        result.append((host, port))
    return result

def check_cert(host: str, port: int) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days
        return {"ok": True, "days_left": days_left, "expires": expires.isoformat()}
    except Exception as e:
        return {"ok": False, "error": str(e)}

async def job_cert_check(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    targets = parse_cert_targets()
    if not targets:
        await bot.send_message(chat, "CERT_TARGETS не задан в .env")
        return
    loop = asyncio.get_event_loop()
    lines, problems = [], 0
    for host, port in targets:
        result = await loop.run_in_executor(None, check_cert, host, port)
        if not result["ok"]:
            problems += 1
            lines.append(f"❌ {host}:{port} — {result['error']}")
            continue
        days = result["days_left"]
        if days < 0:
            problems += 1
            lines.append(f"🔴 {host}:{port} — ПРОТУХ {abs(days)} дн. назад!")
        elif days <= CERT_WARN_DAYS:
            problems += 1
            lines.append(f"🟠 {host}:{port} — истекает через {days} дн.")
        else:
            lines.append(f"✅ {host}:{port} — ещё {days} дн.")
    header = f"🔐 Сертификаты ({len(targets)} целей" + (f", {problems} проблем)" if problems else ")")
    await bot.send_message(chat, header + "\n" + "\n".join(lines))

# ---------- Handlers ----------
@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    feeds, keywords = load_config()
    await message.answer(
        "Content Scout Bot\n\n"
        "Контент:\n"
        "  /check — проверить фиды прямо сейчас\n"
        "  /sources — список источников\n"
        "  /stats — сколько всего найдено материалов\n\n"
        "Наблюдение за кластером:\n"
        "  /waste — простаивающие контейнеры (Prometheus)\n"
        "  /certs — истечение SSL-сертификатов\n\n"
        f"Автопроверка фидов каждые {CHECK_INTERVAL_MINUTES} мин.\n"
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

@dp.message(Command("waste"))
async def cmd_waste(message: Message):
    await message.answer("🔎 Анализирую метрики...")
    await job_resource_waste(manual_chat_id=message.chat.id)

@dp.message(Command("certs"))
async def cmd_certs(message: Message):
    await job_cert_check(manual_chat_id=message.chat.id)

# ---------- Main ----------
async def main():
    os.makedirs("/app/data", exist_ok=True)
    db().close()

    scheduler.add_job(check_feeds_job, "interval", minutes=CHECK_INTERVAL_MINUTES)
    scheduler.add_job(job_resource_waste, "interval", hours=WASTE_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_cert_check, "interval", hours=CERT_CHECK_INTERVAL_HOURS)
    scheduler.start()

    log.info("Bot starting. interval=%s min", CHECK_INTERVAL_MINUTES)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
