import asyncio
import json
import logging
import os
import sqlite3
import subprocess
from datetime import datetime

import aiohttp
import nmap
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sec-bot")

# ---------- Config ----------
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
SUBNET = os.environ.get("SUBNET", "192.168.5.0/24")
SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
NUCLEI_SEVERITY = os.environ.get("NUCLEI_SEVERITY", "critical,high,medium")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "")  # e.g. http://192.168.5.104:11434
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
DB_PATH = "/app/data/scans.db"

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
scheduler = AsyncIOScheduler()

# ---------- DB ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            host TEXT, port INTEGER, proto TEXT,
            service TEXT, product TEXT, version TEXT,
            first_seen TEXT, last_seen TEXT,
            PRIMARY KEY (host, port, proto)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT, template TEXT, severity TEXT,
            info TEXT, found_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT, finished_at TEXT,
            hosts_up INTEGER, new_ports INTEGER, closed_ports INTEGER
        )
    """)
    return conn

# ---------- Nmap scan ----------
def run_nmap_scan(subnet: str):
    """Discover live hosts + open ports/services. Returns dict host -> list of port dicts."""
    scanner = nmap.PortScanner()
    log.info("Starting nmap scan of %s", subnet)
    scanner.scan(hosts=subnet, arguments="-sV -T4 --top-ports 200")
    results = {}
    for host in scanner.all_hosts():
        if scanner[host].state() != "up":
            continue
        ports = []
        for proto in scanner[host].all_protocols():
            for port, data in scanner[host][proto].items():
                if data.get("state") != "open":
                    continue
                ports.append({
                    "port": port,
                    "proto": proto,
                    "service": data.get("name", ""),
                    "product": data.get("product", ""),
                    "version": data.get("version", ""),
                })
        results[host] = ports
    return results

def diff_and_store(scan_results: dict):
    """Compare new scan to DB, return (new_entries, closed_entries), update DB."""
    conn = db()
    now = datetime.utcnow().isoformat()
    seen_now = set()
    new_entries, closed_entries = [], []

    for host, ports in scan_results.items():
        for p in ports:
            key = (host, p["port"], p["proto"])
            seen_now.add(key)
            row = conn.execute(
                "SELECT host FROM ports WHERE host=? AND port=? AND proto=?",
                key
            ).fetchone()
            if row is None:
                new_entries.append((host, p))
                conn.execute(
                    "INSERT INTO ports (host, port, proto, service, product, version, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (host, p["port"], p["proto"], p["service"], p["product"], p["version"], now, now)
                )
            else:
                conn.execute(
                    "UPDATE ports SET service=?, product=?, version=?, last_seen=? "
                    "WHERE host=? AND port=? AND proto=?",
                    (p["service"], p["product"], p["version"], now, host, p["port"], p["proto"])
                )

    # find ports that were known before but not seen in this scan = closed
    for row in conn.execute("SELECT host, port, proto, service FROM ports"):
        key = (row[0], row[1], row[2])
        if key not in seen_now:
            closed_entries.append({"host": row[0], "port": row[1], "proto": row[2], "service": row[3]})

    for c in closed_entries:
        conn.execute(
            "DELETE FROM ports WHERE host=? AND port=? AND proto=?",
            (c["host"], c["port"], c["proto"])
        )

    conn.execute(
        "INSERT INTO scans (started_at, finished_at, hosts_up, new_ports, closed_ports) VALUES (?,?,?,?,?)",
        (now, datetime.utcnow().isoformat(), len(scan_results), len(new_entries), len(closed_entries))
    )
    conn.commit()
    conn.close()
    return new_entries, closed_entries

# ---------- Nuclei scan ----------
def run_nuclei(targets: list[str]):
    """Run nuclei against a list of host:port targets, return parsed JSON findings."""
    if not targets:
        return []
    target_file = "/app/data/targets.txt"
    with open(target_file, "w") as f:
        f.write("\n".join(targets))

    try:
        proc = subprocess.run(
            [
                "nuclei", "-l", target_file,
                "-severity", NUCLEI_SEVERITY,
                "-jsonl", "-silent",
                "-timeout", "5",
            ],
            capture_output=True, text=True, timeout=1200
        )
    except subprocess.TimeoutExpired:
        log.warning("Nuclei scan timed out")
        return []

    findings = []
    for line in proc.stdout.splitlines():
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings

def store_findings(findings: list):
    if not findings:
        return
    conn = db()
    now = datetime.utcnow().isoformat()
    for f in findings:
        conn.execute(
            "INSERT INTO findings (host, template, severity, info, found_at) VALUES (?,?,?,?,?)",
            (
                f.get("host", ""),
                f.get("template-id", ""),
                f.get("info", {}).get("severity", ""),
                f.get("info", {}).get("name", ""),
                now,
            )
        )
    conn.commit()
    conn.close()

# ---------- Ollama explain (optional) ----------
async def explain_finding(text: str) -> str:
    if not OLLAMA_HOST:
        return ""
    prompt = (
        f"Кратко (2-3 предложения, по-русски) объясни для домашнего сервера/сисадмина, "
        f"что означает эта находка сканера безопасности и что с ней делать:\n{text}"
    )
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{OLLAMA_HOST}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                data = await resp.json()
                return data.get("response", "").strip()
    except Exception as e:
        log.warning("Ollama explain failed: %s", e)
        return ""

# ---------- Core scan job ----------
async def full_scan_job(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    await bot.send_message(chat, "🔎 Запускаю скан подсети " + SUBNET + "...")

    loop = asyncio.get_event_loop()
    scan_results = await loop.run_in_executor(None, run_nmap_scan, SUBNET)
    new_entries, closed_entries = diff_and_store(scan_results)

    if new_entries:
        lines = ["🆕 Новые открытые порты:"]
        for host, p in new_entries:
            svc = f"{p['service']} {p['product']} {p['version']}".strip()
            lines.append(f"  {host}:{p['port']}/{p['proto']} — {svc}")
        await bot.send_message(chat, "\n".join(lines))
    if closed_entries:
        lines = ["🔒 Порты, которые закрылись/пропали:"]
        for c in closed_entries:
            lines.append(f"  {c['host']}:{c['port']}/{c['proto']} ({c['service']})")
        await bot.send_message(chat, "\n".join(lines))
    if not new_entries and not closed_entries:
        await bot.send_message(chat, f"✅ Скан завершён. Изменений нет. Хостов онлайн: {len(scan_results)}")

    # build target list for nuclei: only http/https-looking services
    targets = []
    for host, ports in scan_results.items():
        for p in ports:
            if p["service"] in ("http", "https", "http-proxy", "http-alt") or p["port"] in (80, 443, 8080, 8443):
                scheme = "https" if p["service"] == "https" or p["port"] == 443 else "http"
                targets.append(f"{scheme}://{host}:{p['port']}")

    if targets:
        await bot.send_message(chat, f"🛡 Прогоняю Nuclei по {len(targets)} веб-сервисам...")
        findings = await loop.run_in_executor(None, run_nuclei, targets)
        store_findings(findings)
        if findings:
            for f in findings[:15]:  # cap message spam
                sev = f.get("info", {}).get("severity", "unknown")
                name = f.get("info", {}).get("name", f.get("template-id", ""))
                host = f.get("host", "")
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(sev, "⚪")
                text = f"{emoji} [{sev.upper()}] {host}\n{name}"
                explanation = await explain_finding(f"{name} on {host}, severity {sev}")
                if explanation:
                    text += f"\n💡 {explanation}"
                await bot.send_message(chat, text)
            if len(findings) > 15:
                await bot.send_message(chat, f"...и ещё {len(findings) - 15} находок, см. /findings")
        else:
            await bot.send_message(chat, "✅ Nuclei ничего не нашёл.")

# ---------- Handlers ----------
@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    await message.answer(
        "Cluster Sentinel Security Bot\n\n"
        "/scan — запустить скан сети прямо сейчас\n"
        "/status — сводка по последнему скану\n"
        "/hosts — список известных хостов и портов\n"
        "/findings — последние находки Nuclei\n"
        f"Автоскан каждые {SCAN_INTERVAL_HOURS} ч, подсеть {SUBNET}"
    )

@dp.message(Command("scan"))
async def cmd_scan(message: Message):
    await full_scan_job(manual_chat_id=message.chat.id)

@dp.message(Command("status"))
async def cmd_status(message: Message):
    conn = db()
    row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if not row:
        await message.answer("Сканов пока не было. Запусти /scan")
        return
    await message.answer(
        f"Последний скан: {row[1]}\n"
        f"Хостов онлайн: {row[3]}\n"
        f"Новых портов: {row[4]}\n"
        f"Закрытых портов: {row[5]}"
    )

@dp.message(Command("hosts"))
async def cmd_hosts(message: Message):
    conn = db()
    rows = conn.execute("SELECT host, port, proto, service, product FROM ports ORDER BY host, port").fetchall()
    conn.close()
    if not rows:
        await message.answer("База пуста. Запусти /scan")
        return
    lines = []
    last_host = None
    for host, port, proto, service, product in rows:
        if host != last_host:
            lines.append(f"\n📍 {host}")
            last_host = host
        lines.append(f"  {port}/{proto} {service} {product}".strip())
    text = "\n".join(lines)
    for i in range(0, len(text), 3500):
        await message.answer(text[i:i+3500])

@dp.message(Command("findings"))
async def cmd_findings(message: Message):
    conn = db()
    rows = conn.execute(
        "SELECT host, template, severity, info, found_at FROM findings ORDER BY id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    if not rows:
        await message.answer("Находок нет.")
        return
    lines = ["Последние находки Nuclei:"]
    for host, template, severity, info, found_at in rows:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(severity, "⚪")
        lines.append(f"{emoji} {host} — {info} ({template})")
    await message.answer("\n".join(lines))

# ---------- Main ----------
async def main():
    os.makedirs("/app/data", exist_ok=True)
    db().close()

    scheduler.add_job(full_scan_job, "interval", hours=SCAN_INTERVAL_HOURS)
    scheduler.start()

    log.info("Bot starting. Subnet=%s interval=%sh", SUBNET, SCAN_INTERVAL_HOURS)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
