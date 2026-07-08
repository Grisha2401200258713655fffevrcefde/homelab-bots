import asyncio
import logging
import os
import re
import socket
import sqlite3
import ssl
from datetime import datetime

import aiohttp
import feedparser
import trafilatura
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

# --- Перевод статей (deep-translator / Google Translate, без ИИ и LLM) ---
TRANSLATE_ENABLED = os.environ.get("TRANSLATE_ENABLED", "true").lower() == "true"
TRANSLATE_MAX_CHARS = int(os.environ.get("TRANSLATE_MAX_CHARS", "4000"))

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

# --- SLA / uptime tracker (Prometheus 'up' metric) ---
SLA_CHECK_INTERVAL_HOURS = int(os.environ.get("SLA_CHECK_INTERVAL_HOURS", "168"))
SLA_LOOKBACK = os.environ.get("SLA_LOOKBACK", "30d")
SLA_WARN_PCT = float(os.environ.get("SLA_WARN_PCT", "99.0"))

# --- Predictive disk-fill forecast (линейная регрессия по тренду) ---
FORECAST_CHECK_INTERVAL_HOURS = int(os.environ.get("FORECAST_CHECK_INTERVAL_HOURS", "24"))
FORECAST_LOOKBACK_DAYS = int(os.environ.get("FORECAST_LOOKBACK_DAYS", "14"))
FORECAST_WARN_DAYS = int(os.environ.get("FORECAST_WARN_DAYS", "30"))

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
            url TEXT PRIMARY KEY, source TEXT, title TEXT, found_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT, chat_id TEXT, ts TEXT
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

def log_audit(command: str, chat_id):
    conn = db()
    conn.execute("INSERT INTO audit (command, chat_id, ts) VALUES (?,?,?)",
                 (command, str(chat_id), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
# ---------- Извлечение полного текста статьи + перевод ----------
CYRILLIC_RE = re.compile(r"[а-яА-ЯёЁ]")

def is_mostly_russian(text: str) -> bool:
    if not text:
        return False
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    cyr = len(CYRILLIC_RE.findall(text))
    return cyr / len(letters) > 0.3

async def fetch_article_text(url: str) -> str:
    """Скачивает страницу и вытаскивает основной текст статьи (без меню/рекламы)."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20),
                                    headers={"User-Agent": "Mozilla/5.0 (homelab content-scout bot)"}) as resp:
                html = await resp.text(errors="replace")
    except Exception as e:
        log.warning("Не смог скачать %s: %s", url, e)
        return ""
    try:
        extracted = trafilatura.extract(html, include_comments=False, include_tables=False)
        return extracted or ""
    except Exception as e:
        log.warning("Не смог извлечь текст из %s: %s", url, e)
        return ""

async def translate_to_russian(text: str) -> str:
    """Переводит текст на русский через deep-translator (Google Translate веб-эндпоинт,
    обычный машинный перевод, без LLM). Возвращает '' при неудаче."""
    if not TRANSLATE_ENABLED or not text.strip():
        return ""

    def _translate_sync(t: str) -> str:
        from deep_translator import GoogleTranslator
        translator = GoogleTranslator(source="auto", target="ru")
        # у Google Translate лимит ~5000 символов на запрос — режем на чанки по абзацам
        chunk_size = 4500
        chunks = [t[i:i + chunk_size] for i in range(0, len(t), chunk_size)]
        translated = [translator.translate(c) for c in chunks]
        return "\n".join(translated)

    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _translate_sync, text)
    except Exception as e:
        log.warning("Translate failed: %s", e)
        return ""

def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"


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
                mark_seen(conn, link, name, title)
                continue
            mark_seen(conn, link, name, title)
            new_count += 1

            article_text = await fetch_article_text(link)
            body = article_text if article_text else summary

            if TRANSLATE_ENABLED and body and not is_mostly_russian(body):
                to_translate = truncate(body, TRANSLATE_MAX_CHARS)
                translation = await translate_to_russian(to_translate)
            else:
                translation = ""

            if translation:
                ru_text = (
                    f"📰 <b>{name}</b>\n<b>{title}</b>\n\n"
                    f"🇷🇺 <b>Перевод:</b>\n{truncate(translation, 3500)}\n\n{link}"
                )
                await bot.send_message(chat, ru_text, parse_mode="HTML", disable_web_page_preview=False)
                await asyncio.sleep(1)

                en_text = f"🇬🇧 <b>Оригинал ({name}):</b>\n{truncate(body, 3500)}"
                await bot.send_message(chat, en_text, parse_mode="HTML", disable_web_page_preview=True)
            else:
                # перевод недоступен/не нужен — как раньше, просто заголовок+ссылка
                text = f"📰 <b>{name}</b>\n{title}\n{link}"
                await bot.send_message(chat, text, parse_mode="HTML", disable_web_page_preview=False)

            await asyncio.sleep(1)

    conn.commit()
    conn.close()
    if manual_chat_id and new_count == 0:
        await bot.send_message(chat, "Новых материалов по теме не найдено.")
    log.info("Feed check done, %d new items sent", new_count)

# ---------- Prometheus helpers ----------
async def prom_query(query: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": query},
                                timeout=aiohttp.ClientTimeout(total=30)) as resp:
            data = await resp.json()
            if data.get("status") != "success":
                raise RuntimeError(data)
            return data["data"]["result"]

async def prom_query_range(query: str, start_ts: float, end_ts: float, step: str = "1h"):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{PROMETHEUS_URL}/api/v1/query_range",
                                params={"query": query, "start": start_ts, "end": end_ts, "step": step},
                                timeout=aiohttp.ClientTimeout(total=30)) as resp:
            data = await resp.json()
            if data.get("status") != "success":
                raise RuntimeError(data)
            return data["data"]["result"]

# ---------- Resource waste job ----------
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

# ---------- SLA / uptime tracker ----------
async def job_sla_check(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    query = f'avg_over_time(up[{SLA_LOOKBACK}]) * 100'
    try:
        results = await prom_query(query)
    except Exception as e:
        await bot.send_message(chat, f"Не смог достучаться до Prometheus: {e}")
        return
    if not results:
        await bot.send_message(chat, "Prometheus не вернул метрику 'up' — проверь, что там есть таргеты.")
        return
    rows = []
    for r in results:
        job = r["metric"].get("job", "") or r["metric"].get("instance", "unknown")
        try:
            pct = float(r["value"][1])
        except (ValueError, KeyError):
            continue
        rows.append((job, pct))
    rows.sort(key=lambda x: x[1])
    lines = [f"📊 SLA / аптайм за {SLA_LOOKBACK}:"]
    problems = 0
    for job, pct in rows:
        emoji = "✅"
        if pct < SLA_WARN_PCT:
            emoji = "🟠" if pct >= 95 else "🔴"
            problems += 1
        lines.append(f"{emoji} {job}: {pct:.2f}%")
    if problems:
        lines.append(f"\n{problems} сервис(ов) ниже порога {SLA_WARN_PCT}%")
    await bot.send_message(chat, "\n".join(lines))

# ---------- Predictive disk-fill forecast (линейная регрессия) ----------
def linear_regression(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Простой МНК: возвращает (slope, intercept) для y = slope*x + intercept."""
    n = len(xs)
    if n < 2:
        return 0.0, ys[0] if ys else 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den = sum((x - mean_x) ** 2 for x in xs)
    if den == 0:
        return 0.0, mean_y
    slope = num / den
    intercept = mean_y - slope * mean_x
    return slope, intercept

async def job_forecast(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    now = datetime.utcnow().timestamp()
    start = now - FORECAST_LOOKBACK_DAYS * 86400
    query = 'node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"}'
    try:
        series = await prom_query_range(query, start, now, step="6h")
    except Exception as e:
        await bot.send_message(chat, f"Не смог достучаться до Prometheus ({PROMETHEUS_URL}): {e}")
        return
    if not series:
        await bot.send_message(chat, "Метрика node_filesystem_avail_bytes не найдена — установлен ли node_exporter?")
        return

    predictions = []
    for s in series:
        instance = s["metric"].get("instance", "?")
        mountpoint = s["metric"].get("mountpoint", "?")
        values = s.get("values", [])
        if len(values) < 5:
            continue
        t0 = float(values[0][0])
        xs = [(float(t) - t0) / 86400 for t, _ in values]  # дни от начала окна
        ys = [float(v) / (1024 ** 3) for _, v in values]   # ГБ

        slope, intercept = linear_regression(xs, ys)  # ГБ/день
        current_gb = ys[-1]
        if slope >= -0.01:  # не убывает заметно — не в зоне риска
            continue
        days_to_full = -current_gb / slope
        if days_to_full <= FORECAST_WARN_DAYS:
            predictions.append((instance, mountpoint, current_gb, slope, days_to_full))

    if not predictions:
        await bot.send_message(
            chat,
            f"✅ По тренду за {FORECAST_LOOKBACK_DAYS} дн. ни один диск не близок к заполнению "
            f"(порог {FORECAST_WARN_DAYS} дн.)."
        )
        return

    predictions.sort(key=lambda x: x[4])
    lines = [f"📉 Прогноз заполнения дисков (линейная регрессия по {FORECAST_LOOKBACK_DAYS} дн.):"]
    for instance, mountpoint, current_gb, slope, days in predictions[:15]:
        emoji = "🔴" if days < 7 else "🟠"
        lines.append(
            f"{emoji} {instance} {mountpoint}: {current_gb:.1f} ГБ свободно, "
            f"тает на {abs(slope):.2f} ГБ/день → закончится через ~{days:.0f} дн."
        )
    await bot.send_message(chat, "\n".join(lines))

# ---------- Handlers ----------
@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    feeds, keywords = load_config()
    await message.answer(
        "Content Scout Bot\n\n"
        "Контент:\n"
        "  /check — проверить фиды прямо сейчас\n"
        "  /sources — список источников\n"
        "  /stats — сколько всего найдено материалов\n"
        f"  Перевод статей: {'включён' if TRANSLATE_ENABLED else 'выключен'} "
        f"(сначала 🇷🇺 перевод, потом 🇬🇧 оригинал)\n\n"
        "Наблюдение за кластером:\n"
        "  /waste — простаивающие контейнеры (Prometheus)\n"
        "  /certs — истечение SSL-сертификатов\n"
        "  /sla — аптайм сервисов за месяц\n"
        "  /forecast — прогноз заполнения дисков (линейная регрессия по тренду)\n"
        "  /audit — последние команды всех ботов (этот процесс)\n\n"
        f"Автопроверка фидов каждые {CHECK_INTERVAL_MINUTES} мин."
    )

@dp.message(Command("check"))
async def cmd_check(message: Message):
    log_audit("/check", message.chat.id)
    await message.answer("🔎 Проверяю фиды...")
    await check_feeds_job(manual_chat_id=message.chat.id)

@dp.message(Command("sources"))
async def cmd_sources(message: Message):
    log_audit("/sources", message.chat.id)
    feeds, _ = load_config()
    lines = ["Источники:"] + [f"• {f['name']}" for f in feeds]
    await message.answer("\n".join(lines))

@dp.message(Command("stats"))
async def cmd_stats(message: Message):
    log_audit("/stats", message.chat.id)
    conn = db()
    total = conn.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
    conn.close()
    await message.answer(f"Всего материалов в базе: {total}")

@dp.message(Command("waste"))
async def cmd_waste(message: Message):
    log_audit("/waste", message.chat.id)
    await message.answer("🔎 Анализирую метрики...")
    await job_resource_waste(manual_chat_id=message.chat.id)

@dp.message(Command("certs"))
async def cmd_certs(message: Message):
    log_audit("/certs", message.chat.id)
    await job_cert_check(manual_chat_id=message.chat.id)

@dp.message(Command("sla"))
async def cmd_sla(message: Message):
    log_audit("/sla", message.chat.id)
    await job_sla_check(manual_chat_id=message.chat.id)

@dp.message(Command("forecast"))
async def cmd_forecast(message: Message):
    log_audit("/forecast", message.chat.id)
    await message.answer("🔎 Считаю тренд по дискам...")
    await job_forecast(manual_chat_id=message.chat.id)

@dp.message(Command("audit"))
async def cmd_audit(message: Message):
    conn = db()
    rows = conn.execute("SELECT command, ts FROM audit ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    if not rows:
        await message.answer("Аудит пуст.")
        return
    lines = ["Последние команды (content-scout):"]
    for command, ts in rows:
        lines.append(f"[{ts[:16]}] {command}")
    await message.answer("\n".join(lines))

# ---------- Main ----------
async def main():
    os.makedirs("/app/data", exist_ok=True)
    db().close()

    scheduler.add_job(check_feeds_job, "interval", minutes=CHECK_INTERVAL_MINUTES)
    scheduler.add_job(job_resource_waste, "interval", hours=WASTE_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_cert_check, "interval", hours=CERT_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_sla_check, "interval", hours=SLA_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_forecast, "interval", hours=FORECAST_CHECK_INTERVAL_HOURS)
    scheduler.start()

    log.info("Bot starting. interval=%s min", CHECK_INTERVAL_MINUTES)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
