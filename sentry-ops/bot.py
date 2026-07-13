import asyncio
import difflib
import io
import json
import logging
import os
import random
import re
import sqlite3
import subprocess
import tarfile
import threading
import zipfile
from datetime import datetime, timedelta

import aiohttp
import nmap
import paramiko
import yaml
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sentry-ops")

# ---------- Общий конфиг ----------
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
DB_PATH = "/app/data/sentry.db"
SSH_USER = os.environ.get("SSH_USER", "admin1")
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/app/ssh/id_rsa")
CLUSTER_NODES = os.environ.get(
    "CLUSTER_NODES",
    "192.168.5.100:srv1,192.168.5.101:sand-box,192.168.5.102:host-196,"
    "192.168.5.104:hren-znaet,192.168.5.164:new-node,192.168.5.225:setevoipc",
)

# ---------- Network scan (nmap + nuclei) ----------
SUBNET = os.environ.get("SUBNET", "192.168.5.0/24")
SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
NUCLEI_SEVERITY = os.environ.get("NUCLEI_SEVERITY", "critical,high,medium")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")

# ---------- Backup verify ----------
BACKUP_CHECK_INTERVAL_HOURS = int(os.environ.get("BACKUP_CHECK_INTERVAL_HOURS", "168"))
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "")
MINIO_SECURE = os.environ.get("MINIO_SECURE", "false").lower() == "true"
DUPLICATI_URL = os.environ.get("DUPLICATI_URL", "")

# ---------- Docker bloat ----------
BLOAT_CHECK_INTERVAL_HOURS = int(os.environ.get("BLOAT_CHECK_INTERVAL_HOURS", "168"))

# ---------- Config drift ----------
DRIFT_CHECK_INTERVAL_HOURS = int(os.environ.get("DRIFT_CHECK_INTERVAL_HOURS", "24"))
DRIFT_WATCH_PATHS = os.environ.get("DRIFT_WATCH_PATHS", "")
BASELINE_DIR = "/app/data/baseline"

# ---------- On-call эскалация ----------
ESCALATION_MINUTES = int(os.environ.get("ESCALATION_MINUTES", "30"))
ESCALATION_CHECK_MINUTES = int(os.environ.get("ESCALATION_CHECK_MINUTES", "10"))

# ---------- Blast radius (docker-compose файлы по нодам, тот же формат что DRIFT_WATCH_PATHS) ----------
COMPOSE_PATHS = os.environ.get("COMPOSE_PATHS", "")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
scheduler = AsyncIOScheduler()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS ports (
        host TEXT, port INTEGER, proto TEXT, service TEXT, product TEXT, version TEXT,
        first_seen TEXT, last_seen TEXT, PRIMARY KEY (host, port, proto))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, template TEXT, severity TEXT,
        info TEXT, found_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT, finished_at TEXT,
        hosts_up INTEGER, new_ports INTEGER, closed_ports INTEGER)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS backup_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, ok INTEGER, detail TEXT, checked_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, command TEXT, chat_id TEXT, ts TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS maintenance (
        host TEXT PRIMARY KEY, until_ts TEXT, reason TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, message TEXT, severity TEXT,
        sent_at TEXT, acked INTEGER DEFAULT 0, escalated INTEGER DEFAULT 0)""")
    return conn


def parse_nodes():
    result = []
    for entry in CLUSTER_NODES.split(","):
        entry = entry.strip()
        if not entry:
            continue
        host, _, label = entry.partition(":")
        result.append((host.strip(), label.strip() or host.strip()))
    return result


def log_audit(command: str, chat_id):
    conn = db()
    conn.execute("INSERT INTO audit (command, chat_id, ts) VALUES (?,?,?)",
                 (command, str(chat_id), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


# ================= MAINTENANCE MODE =================

def set_maintenance(host: str, minutes: int, reason: str = ""):
    conn = db()
    until = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()
    conn.execute("INSERT OR REPLACE INTO maintenance (host, until_ts, reason) VALUES (?,?,?)",
                 (host, until, reason))
    conn.commit()
    conn.close()
    return until


def clear_maintenance(host: str):
    conn = db()
    conn.execute("DELETE FROM maintenance WHERE host=?", (host,))
    conn.commit()
    conn.close()


def in_maintenance(host: str) -> bool:
    conn = db()
    row = conn.execute("SELECT until_ts FROM maintenance WHERE host=?", (host,)).fetchone()
    conn.close()
    if not row:
        return False
    return datetime.fromisoformat(row[0]) > datetime.utcnow()


def list_maintenance():
    conn = db()
    rows = conn.execute("SELECT host, until_ts, reason FROM maintenance").fetchall()
    conn.close()
    now = datetime.utcnow()
    return [(h, u, r) for h, u, r in rows if datetime.fromisoformat(u) > now]


# ================= ON-CALL ESCALATION =================

async def send_alert(chat, host: str, text: str, severity: str = "high"):
    """Отправляет алерт с кнопкой подтверждения; неподтверждённые эскалируются."""
    conn = db()
    now = datetime.utcnow().isoformat()
    cur = conn.execute("INSERT INTO alerts (host, message, severity, sent_at) VALUES (?,?,?,?)",
                        (host, text, severity, now))
    alert_id = cur.lastrowid
    conn.commit()
    conn.close()
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Подтвердить", callback_data=f"ack:{alert_id}")
    ]])
    await bot.send_message(chat, text, reply_markup=kb)


@dp.callback_query(F.data.startswith("ack:"))
async def cb_ack(callback: CallbackQuery):
    alert_id = int(callback.data.split(":", 1)[1])
    conn = db()
    conn.execute("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    await callback.answer("Подтверждено ✅")
    try:
        await callback.message.edit_text(callback.message.text + "\n\n✅ Подтверждено")
    except Exception:
        pass


async def job_check_escalations():
    conn = db()
    cutoff = (datetime.utcnow() - timedelta(minutes=ESCALATION_MINUTES)).isoformat()
    rows = conn.execute(
        "SELECT id, host, message, severity, sent_at FROM alerts "
        "WHERE acked=0 AND escalated=0 AND sent_at < ?", (cutoff,)
    ).fetchall()
    for alert_id, host, message, severity, sent_at in rows:
        conn.execute("UPDATE alerts SET escalated=1 WHERE id=?", (alert_id,))
        kb = InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="✅ Подтвердить", callback_data=f"ack:{alert_id}")
        ]])
        text = (f"⚠️ ПОВТОРНО (не подтверждено {ESCALATION_MINUTES} мин.)\n\n{message}")
        await bot.send_message(CHAT_ID, text, reply_markup=kb)
    conn.commit()
    conn.close()


# ================= NETWORK SCAN =================

def run_nmap_scan(subnet: str):
    scanner = nmap.PortScanner()
    # -T5 (максимальная агрессивность, безопасно в локалке) + --min-rate 1000 (не ждать,
    # слать пакеты пачками) + -n (не резолвить DNS на каждый хост — лишние секунды)
    # + --version-intensity 0 (лёгкие пробы баннеров вместо полного перебора — быстрее,
    # чуть менее подробно, но для обнаружения http-сервисов для nuclei хватает)
    scanner.scan(hosts=subnet, arguments="-sV -T5 -n --top-ports 200 --min-rate 1000 "
                                          "--version-intensity 0 --host-timeout 45s")
    results = {}
    for host in scanner.all_hosts():
        if scanner[host].state() != "up":
            continue
        ports = []
        for proto in scanner[host].all_protocols():
            for port, data in scanner[host][proto].items():
                if data.get("state") != "open":
                    continue
                ports.append({"port": port, "proto": proto, "service": data.get("name", ""),
                              "product": data.get("product", ""), "version": data.get("version", "")})
        results[host] = ports
    return results


def diff_and_store(scan_results: dict):
    conn = db()
    now = datetime.utcnow().isoformat()
    seen_now = set()
    new_entries, closed_entries = [], []
    for host, ports in scan_results.items():
        for p in ports:
            key = (host, p["port"], p["proto"])
            seen_now.add(key)
            row = conn.execute("SELECT host FROM ports WHERE host=? AND port=? AND proto=?", key).fetchone()
            if row is None:
                new_entries.append((host, p))
                conn.execute(
                    "INSERT INTO ports (host,port,proto,service,product,version,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
                    (host, p["port"], p["proto"], p["service"], p["product"], p["version"], now, now))
            else:
                conn.execute(
                    "UPDATE ports SET service=?,product=?,version=?,last_seen=? WHERE host=? AND port=? AND proto=?",
                    (p["service"], p["product"], p["version"], now, host, p["port"], p["proto"]))
    for row in conn.execute("SELECT host, port, proto, service FROM ports"):
        key = (row[0], row[1], row[2])
        if key not in seen_now:
            closed_entries.append({"host": row[0], "port": row[1], "proto": row[2], "service": row[3]})
    for c in closed_entries:
        conn.execute("DELETE FROM ports WHERE host=? AND port=? AND proto=?", (c["host"], c["port"], c["proto"]))
    conn.execute("INSERT INTO scans (started_at,finished_at,hosts_up,new_ports,closed_ports) VALUES (?,?,?,?,?)",
                 (now, datetime.utcnow().isoformat(), len(scan_results), len(new_entries), len(closed_entries)))
    conn.commit()
    conn.close()
    return new_entries, closed_entries


def run_nuclei(targets: list[str]):
    if not targets:
        return []
    target_file = "/app/data/targets.txt"
    with open(target_file, "w") as f:
        f.write("\n".join(targets))
    try:
        proc = subprocess.run(
            ["nuclei", "-l", target_file, "-severity", NUCLEI_SEVERITY, "-jsonl", "-silent",
             "-timeout", "4", "-c", "50", "-rate-limit", "500", "-disable-clustering"],
            capture_output=True, text=True, timeout=1200)
    except subprocess.TimeoutExpired:
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
        conn.execute("INSERT INTO findings (host,template,severity,info,found_at) VALUES (?,?,?,?,?)",
                     (f.get("host", ""), f.get("template-id", ""), f.get("info", {}).get("severity", ""),
                      f.get("info", {}).get("name", ""), now))
    conn.commit()
    conn.close()


async def ask_ollama(prompt: str, timeout: int = 60) -> str:
    if not OLLAMA_HOST:
        return ""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{OLLAMA_HOST}/api/generate",
                                     json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                                     timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                data = await resp.json()
                return data.get("response", "").strip()
    except Exception as e:
        log.warning("Ollama request failed: %s", e)
        return ""


async def explain_finding(text: str) -> str:
    prompt = (f"Кратко (2-3 предложения, по-русски) объясни для домашнего сервера/сисадмина, "
              f"что означает эта находка сканера безопасности и что с ней делать:\n{text}")
    return await ask_ollama(prompt, timeout=60)


async def job_network_scan(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    await bot.send_message(chat, f"🔎 Скан подсети {SUBNET}...")
    loop = asyncio.get_event_loop()
    scan_results = await loop.run_in_executor(None, run_nmap_scan, SUBNET)
    new_entries, closed_entries = diff_and_store(scan_results)

    # фильтруем хосты в maintenance-режиме
    new_entries = [(h, p) for h, p in new_entries if not in_maintenance(h)]
    closed_entries = [c for c in closed_entries if not in_maintenance(c["host"])]

    if new_entries:
        lines = ["🆕 Новые открытые порты:"]
        for host, p in new_entries:
            svc = f"{p['service']} {p['product']} {p['version']}".strip()
            lines.append(f"  {host}:{p['port']}/{p['proto']} — {svc}")
        await bot.send_message(chat, "\n".join(lines))
    if closed_entries:
        lines = ["🔒 Порты закрылись:"]
        for c in closed_entries:
            lines.append(f"  {c['host']}:{c['port']}/{c['proto']} ({c['service']})")
        await bot.send_message(chat, "\n".join(lines))
    if not new_entries and not closed_entries:
        await bot.send_message(chat, f"✅ Изменений нет. Хостов онлайн: {len(scan_results)}")

    targets = []
    for host, ports in scan_results.items():
        if in_maintenance(host):
            continue
        for p in ports:
            if p["service"] in ("http", "https", "http-proxy", "http-alt") or p["port"] in (80, 443, 8080, 8443):
                scheme = "https" if p["service"] == "https" or p["port"] == 443 else "http"
                targets.append(f"{scheme}://{host}:{p['port']}")

    if targets:
        await bot.send_message(chat, f"🛡 Nuclei по {len(targets)} веб-сервисам...")
        findings = await loop.run_in_executor(None, run_nuclei, targets)
        store_findings(findings)
        if findings:
            top_findings = findings[:15]
            # объяснения от Ollama запрашиваем ОДНОВРЕМЕННО, а не по одной находке —
            # раньше 15 находок = 15 последовательных ожиданий ответа модели
            explanations = await asyncio.gather(*[
                explain_finding(f"{f.get('info', {}).get('name', f.get('template-id', ''))} "
                                 f"on {f.get('host', '')}, severity {f.get('info', {}).get('severity', 'unknown')}")
                for f in top_findings
            ])
            for f, explanation in zip(top_findings, explanations):
                sev = f.get("info", {}).get("severity", "unknown")
                name = f.get("info", {}).get("name", f.get("template-id", ""))
                host = f.get("host", "")
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(sev, "⚪")
                text = f"{emoji} [{sev.upper()}] {host}\n{name}"
                if explanation:
                    text += f"\n💡 {explanation}"
                if sev in ("critical", "high"):
                    await send_alert(chat, host, text, severity=sev)
                else:
                    await bot.send_message(chat, text)
        else:
            await bot.send_message(chat, "✅ Nuclei ничего не нашёл.")


# ================= BACKUP VERIFY =================

def check_archive_integrity(data: bytes, name: str) -> tuple[bool, str]:
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                bad = z.testzip()
                return (False, f"повреждён элемент: {bad}") if bad else (True, f"zip OK, {len(z.namelist())} файлов")
        elif name.endswith((".tar.gz", ".tgz", ".tar")):
            mode = "r:gz" if name.endswith((".tar.gz", ".tgz")) else "r"
            with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as t:
                return True, f"tar OK, {len(t.getmembers())} файлов"
        else:
            return (False, "нулевой размер") if len(data) == 0 else (True, f"размер {len(data)} байт")
    except Exception as e:
        return False, f"архив повреждён: {e}"


def minio_random_object_check() -> tuple[bool, str]:
    try:
        from minio import Minio
    except ImportError:
        return False, "пакет minio не установлен"
    if not (MINIO_ENDPOINT and MINIO_ACCESS_KEY and MINIO_SECRET_KEY and MINIO_BUCKET):
        return False, "MinIO не сконфигурирован"
    client = Minio(MINIO_ENDPOINT, access_key=MINIO_ACCESS_KEY, secret_key=MINIO_SECRET_KEY, secure=MINIO_SECURE)
    objects = list(client.list_objects(MINIO_BUCKET, recursive=True))
    if not objects:
        return False, f"бакет {MINIO_BUCKET} пуст"
    target = random.choice(objects)
    resp = client.get_object(MINIO_BUCKET, target.object_name)
    data = resp.read()
    resp.close()
    resp.release_conn()
    ok, detail = check_archive_integrity(data, target.object_name)
    return ok, f"{target.object_name} ({len(data)} байт) — {detail}"


async def duplicati_status_check() -> tuple[bool, str]:
    if not DUPLICATI_URL:
        return False, "Duplicati не сконфигурирован"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{DUPLICATI_URL}/api/v1/backups", timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return False, f"API вернул {resp.status}"
                data = await resp.json()
                if not data:
                    return False, "нет задач бэкапа"
                lines, any_bad = [], False
                for job in data:
                    name = job.get("Backup", {}).get("Name", "unknown")
                    result = job.get("Backup", {}).get("Metadata", {}).get("LastBackupResult", "Unknown")
                    if result != "Success":
                        any_bad = True
                    lines.append(f"{name}: {result}")
                return (not any_bad), "; ".join(lines)
    except Exception as e:
        return False, f"ошибка: {e}"


async def job_backup_verify(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    results = []
    if MINIO_ENDPOINT:
        loop = asyncio.get_event_loop()
        ok, detail = await loop.run_in_executor(None, minio_random_object_check)
        results.append(("MinIO restore-test", ok, detail))
    if DUPLICATI_URL:
        ok, detail = await duplicati_status_check()
        results.append(("Duplicati status", ok, detail))
    if not results:
        await bot.send_message(chat, "Бэкапы не сконфигурированы (MINIO_* / DUPLICATI_URL в .env)")
        return
    conn = db()
    now = datetime.utcnow().isoformat()
    lines = ["📦 Проверка бэкапов:"]
    any_failed = False
    for source, ok, detail in results:
        lines.append(f"{'✅' if ok else '🔴'} {source}: {detail}")
        if not ok:
            any_failed = True
        conn.execute("INSERT INTO backup_checks (source,ok,detail,checked_at) VALUES (?,?,?,?)",
                     (source, int(ok), detail, now))
    conn.commit()
    conn.close()
    if any_failed:
        await send_alert(chat, "backup", "\n".join(lines), severity="high")
    else:
        await bot.send_message(chat, "\n".join(lines))


# ================= DOCKER BLOAT =================

# ---------- SSH connection pool (переиспользуем соединения, не коннектимся заново на каждую команду) ----------
_ssh_pool: dict[str, paramiko.SSHClient] = {}
_ssh_pool_lock = threading.Lock()


def _get_ssh_client(host: str, timeout: int) -> paramiko.SSHClient:
    """Возвращает живое SSH-соединение к хосту из пула, переподключаясь только если
    соединения нет или оно умерло. Один транспорт спокойно держит много параллельных
    exec_command вызовов (paramiko открывает под каждый отдельный канал)."""
    with _ssh_pool_lock:
        client = _ssh_pool.get(host)
        if client is not None:
            transport = client.get_transport()
            if transport is not None and transport.is_active():
                return client
            try:
                client.close()
            except Exception:
                pass
            del _ssh_pool[host]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=SSH_USER, key_filename=SSH_KEY_PATH, timeout=timeout)
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)  # держим соединение живым между прогонами
        _ssh_pool[host] = client
        return client


def ssh_run(host: str, command: str, timeout=20) -> tuple[bool, str]:
    try:
        client = _get_ssh_client(host, timeout)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        if err.strip() and not out.strip():
            return False, err.strip()
        return True, out
    except Exception as e:
        # соединение могло протухнуть между прогонами — выкидываем из пула, попробуем один раз заново
        _ssh_pool.pop(host, None)
        try:
            client = _get_ssh_client(host, timeout)
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            if err.strip() and not out.strip():
                return False, err.strip()
            return True, out
        except Exception as e2:
            return False, str(e2)


def ssh_run_multi(host: str, commands: list[str], timeout=20) -> list[tuple[bool, str]]:
    """Прогоняет несколько команд через ОДНО (пуловое) соединение — каждая команда
    открывает свой канал на уже живом транспорте, коннект заново не нужен."""
    try:
        client = _get_ssh_client(host, timeout)
    except Exception as e:
        return [(False, str(e))] * len(commands)

    results = []
    for command in commands:
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            if err.strip() and not out.strip():
                results.append((False, err.strip()))
            else:
                results.append((True, out))
        except Exception as e:
            results.append((False, str(e)))
    return results


def analyze_node_bloat(host: str, label: str) -> dict:
    (ok, df_out), (ok2, dangling_out) = ssh_run_multi(host, [
        "docker system df --format '{{json .}}' 2>/dev/null",
        "docker images -f dangling=true --format '{{.Repository}}\t{{.Size}}' 2>/dev/null",
    ])
    if not ok:
        return {"label": label, "host": host, "error": df_out}
    dangling_count = len([l for l in dangling_out.strip().splitlines() if l.strip()]) if ok2 and dangling_out.strip() else 0

    rows = []
    for line in df_out.strip().splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return {"label": label, "host": host, "rows": rows, "dangling_count": dangling_count, "error": None}


def parse_size_to_gb(size_str: str) -> float:
    """'43.37GB' / '930MB' / '0B' -> число в ГБ."""
    if not size_str:
        return 0.0
    size_str = size_str.strip()
    m = re.match(r"([\d.]+)\s*([A-Za-z]+)", size_str)
    if not m:
        return 0.0
    value, unit = float(m.group(1)), m.group(2).upper()
    mult = {"B": 1e-9, "KB": 1e-6, "MB": 1e-3, "GB": 1, "TB": 1000}.get(unit, 0)
    return value * mult


async def job_docker_bloat(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    nodes = parse_nodes()
    loop = asyncio.get_event_loop()
    await bot.send_message(chat, f"🔎 Docker на {len(nodes)} нодах (параллельно)...")
    lines = ["🐳 Docker bloat отчёт:"]
    any_ok = False
    skipped = []
    node_summaries = []  # для AI-резюме: (label, host, reclaimable_gb, dangling_count, details)

    active_nodes = []
    for host, label in nodes:
        if in_maintenance(host):
            skipped.append(label)
        else:
            active_nodes.append((host, label))

    # опрашиваем все ноды ОДНОВРЕМЕННО, а не по очереди
    results = await asyncio.gather(*[
        loop.run_in_executor(None, analyze_node_bloat, host, label)
        for host, label in active_nodes
    ])

    for result in results:
        host, label = result["host"], result["label"]
        if result.get("error"):
            lines.append(f"\n📍 {label} ({host}) — ❌ {result['error'][:150]}")
            continue
        any_ok = True
        lines.append(f"\n📍 {label} ({host})")
        lines.append(f"  Висящих образов: {result['dangling_count']}")

        total_reclaimable_gb = 0.0
        details = []
        for row in result["rows"]:
            rtype = row.get("Type", "?")
            size = row.get("Size", "0B")
            reclaimable = row.get("Reclaimable", "0B (0%)")
            reclaimable_gb = parse_size_to_gb(reclaimable.split(" ")[0])
            total_reclaimable_gb += reclaimable_gb
            lines.append(f"  {rtype}: размер {size}, можно освободить {reclaimable}")
            details.append(f"{rtype}: {size}, reclaimable {reclaimable}")

        node_summaries.append((label, host, total_reclaimable_gb, result["dangling_count"], "; ".join(details)))

    if skipped:
        lines.append(f"\n⏸ Пропущены (maintenance): {', '.join(skipped)}")
    if not any_ok and not skipped:
        lines.append("\nНи одна нода не ответила — проверь SSH_KEY_PATH.")
    text = "\n".join(lines)
    for i in range(0, len(text), 3500):
        await bot.send_message(chat, text[i:i+3500])

    if node_summaries and OLLAMA_HOST:
        node_summaries.sort(key=lambda x: -x[2])
        summary_input = "\n".join(
            f"{label} ({host}): reclaimable {gb:.1f} ГБ, dangling images {dc}. {det}"
            for label, host, gb, dc, det in node_summaries
        )
        prompt = (
            "Ты — ассистент домашнего сисадмина. Вот отчёт docker system df по нодам кластера "
            "(reclaimable = место, которое можно освободить командой docker system prune):\n\n"
            f"{summary_input}\n\n"
            "Кратко на русском (4-6 предложений): какие ноды реально стоит почистить в первую очередь "
            "(если reclaimable места мало — так и скажи, что чистить не к спеху), "
            "и какую команду выполнить. Без вступлений, сразу по делу."
        )
        summary = await ask_ollama(prompt, timeout=90)
        if summary:
            await bot.send_message(chat, f"🤖 Резюме:\n{summary}")


# ================= CONFIG DRIFT =================

def parse_watch_paths():
    result = []
    for entry in DRIFT_WATCH_PATHS.split(","):
        entry = entry.strip()
        if not entry or "|" not in entry:
            continue
        host, path = entry.split("|", 1)
        result.append((host.strip(), path.strip()))
    return result


def ssh_read_file(host: str, path: str) -> tuple[bool, str]:
    return ssh_run(host, f"cat {path}")


def baseline_file_path(host: str, path: str) -> str:
    return os.path.join(BASELINE_DIR, f"{host}_{path.replace('/', '_')}")


async def job_config_drift(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    targets = parse_watch_paths()
    if not targets:
        await bot.send_message(chat, "DRIFT_WATCH_PATHS не задан в .env")
        return
    os.makedirs(BASELINE_DIR, exist_ok=True)
    loop = asyncio.get_event_loop()
    drift_found, errors, new_baselines = [], [], []

    # читаем файлы со всех нод ОДНОВРЕМЕННО, а не по очереди
    read_results = await asyncio.gather(*[
        loop.run_in_executor(None, ssh_read_file, host, path)
        for host, path in targets
    ])

    for (host, path), (ok, content) in zip(targets, read_results):
        if not ok:
            errors.append(f"{host}:{path} — {content[:100]}")
            continue
        bpath = baseline_file_path(host, path)
        if not os.path.exists(bpath):
            with open(bpath, "w") as f:
                f.write(content)
            new_baselines.append(f"{host}:{path}")
            continue
        with open(bpath) as f:
            baseline = f.read()
        if baseline != content:
            diff = list(difflib.unified_diff(baseline.splitlines(), content.splitlines(), lineterm="", n=1))
            drift_found.append((host, path, diff))
    lines = []
    if new_baselines:
        lines.append(f"📌 Создан baseline для {len(new_baselines)} новых файлов.")
    if errors:
        lines.append(f"❌ Не удалось прочитать {len(errors)}:")
        lines.extend(f"  {e}" for e in errors)
    if drift_found:
        lines.append(f"\n⚠️ Дрейф конфигов ({len(drift_found)}):")
        for host, path, diff in drift_found:
            lines.append(f"\n📍 {host}:{path}")
            lines.append(f"```\n{chr(10).join(diff[:20])}\n```")
    elif not new_baselines and not errors:
        lines.append("✅ Дрейфа нет.")
    text = "\n".join(lines)
    for i in range(0, len(text), 3500):
        await bot.send_message(chat, text[i:i+3500], parse_mode="Markdown")


# ================= BLAST RADIUS =================

def parse_compose_paths():
    result = []
    for entry in COMPOSE_PATHS.split(","):
        entry = entry.strip()
        if not entry or "|" not in entry:
            continue
        host, path = entry.split("|", 1)
        result.append((host.strip(), path.strip()))
    return result


def build_dependency_graph():
    """SSH ко всем нодам, парсит docker-compose файлы, строит граф depends_on + сети."""
    upstream = {}    # service -> [depends_on...]
    downstream = {}  # service -> [кто от него зависит...]
    siblings = {}     # service -> [остальные сервисы в том же compose-файле]
    errors = []

    for host, path in parse_compose_paths():
        ok, content = ssh_run(host, f"cat {path}")
        if not ok:
            errors.append(f"{host}:{path} — {content[:100]}")
            continue
        try:
            compose = yaml.safe_load(content)
        except Exception as e:
            errors.append(f"{host}:{path} — не распарсился YAML: {e}")
            continue
        services = (compose or {}).get("services", {})
        names = list(services.keys())
        for name, spec in services.items():
            deps = spec.get("depends_on", [])
            if isinstance(deps, dict):
                deps = list(deps.keys())
            upstream.setdefault(name, set()).update(deps)
            for d in deps:
                downstream.setdefault(d, set()).add(name)
            siblings.setdefault(name, set()).update(s for s in names if s != name)

    return upstream, downstream, siblings, errors


async def job_blast_radius(service: str, manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    if not parse_compose_paths():
        await bot.send_message(chat, "COMPOSE_PATHS не задан в .env — нечего анализировать.")
        return
    loop = asyncio.get_event_loop()
    upstream, downstream, siblings, errors = await loop.run_in_executor(None, build_dependency_graph)

    if service not in upstream and service not in downstream and service not in siblings:
        await bot.send_message(chat, f"Сервис '{service}' не найден ни в одном из отслеживаемых compose-файлов.")
        return

    lines = [f"💥 Blast radius для «{service}»:"]
    deps = upstream.get(service, set())
    if deps:
        lines.append(f"\n⬆️ Зависит от (должны быть живы, чтобы {service} стартовал):")
        lines.extend(f"  • {d}" for d in sorted(deps))
    dependents = downstream.get(service, set())
    if dependents:
        lines.append(f"\n⬇️ От него зависят (упадут/не стартуют, если {service} остановить):")
        lines.extend(f"  • {d}" for d in sorted(dependents))
    sib = siblings.get(service, set())
    if sib:
        lines.append(f"\n↔️ Соседи по тому же compose-файлу (общая сеть):")
        lines.extend(f"  • {s}" for s in sorted(sib))
    if not deps and not dependents:
        lines.append("\nПрямых зависимостей не найдено — сервис изолирован (в рамках отслеживаемых файлов).")
    if errors:
        lines.append(f"\n⚠️ Не удалось прочитать {len(errors)} compose-файлов:")
        lines.extend(f"  {e}" for e in errors)

    await bot.send_message(chat, "\n".join(lines))


# ================= HANDLERS =================

@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    await message.answer(
        "🛡 Sentry Ops Bot\n\n"
        "Сеть/безопасность:\n"
        "  /scan — скан подсети + nuclei\n"
        "  /status — сводка последнего скана\n"
        "  /hosts — известные хосты/порты\n"
        "  /findings — находки Nuclei\n\n"
        "Инфраструктура (SSH):\n"
        "  /backup — проверка бэкапов (restore-тест)\n"
        "  /bloat — bloat Docker-образов по нодам\n"
        "  /drift — дрейф конфигов\n"
        "  /rebaseline — принять текущие конфиги как baseline\n\n"
        "Энтерпрайз:\n"
        "  /maintenance <нода> <минуты> — заглушить алерты по ноде\n"
        "  /maintenance_clear <нода> — снять заглушку\n"
        "  /maintenance_list — активные заглушки\n"
        "  /blast <сервис> — что уронит перезапуск/остановка сервиса\n"
        "  /audit — последние команды\n\n"
        f"Критичные алерты требуют подтверждения (кнопка), иначе повтор через {ESCALATION_MINUTES} мин."
    )

@dp.message(Command("scan"))
async def cmd_scan(message: Message):
    log_audit("/scan", message.chat.id)
    await job_network_scan(manual_chat_id=message.chat.id)

@dp.message(Command("status"))
async def cmd_status(message: Message):
    log_audit("/status", message.chat.id)
    conn = db()
    row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if not row:
        await message.answer("Сканов не было. /scan")
        return
    await message.answer(f"Последний скан: {row[1]}\nХостов онлайн: {row[3]}\nНовых портов: {row[4]}\nЗакрытых: {row[5]}")

@dp.message(Command("hosts"))
async def cmd_hosts(message: Message):
    log_audit("/hosts", message.chat.id)
    conn = db()
    rows = conn.execute("SELECT host, port, proto, service, product FROM ports ORDER BY host, port").fetchall()
    conn.close()
    if not rows:
        await message.answer("База пуста. /scan")
        return
    lines, last_host = [], None
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
    log_audit("/findings", message.chat.id)
    conn = db()
    rows = conn.execute("SELECT host, template, severity, info FROM findings ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    if not rows:
        await message.answer("Находок нет.")
        return
    lines = ["Последние находки Nuclei:"]
    for host, template, severity, info in rows:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(severity, "⚪")
        lines.append(f"{emoji} {host} — {info} ({template})")
    await message.answer("\n".join(lines))

@dp.message(Command("backup"))
async def cmd_backup(message: Message):
    log_audit("/backup", message.chat.id)
    await message.answer("🔎 Проверяю бэкапы...")
    await job_backup_verify(manual_chat_id=message.chat.id)

@dp.message(Command("bloat"))
async def cmd_bloat(message: Message):
    log_audit("/bloat", message.chat.id)
    await job_docker_bloat(manual_chat_id=message.chat.id)

@dp.message(Command("drift"))
async def cmd_drift(message: Message):
    log_audit("/drift", message.chat.id)
    await job_config_drift(manual_chat_id=message.chat.id)

@dp.message(Command("rebaseline"))
async def cmd_rebaseline(message: Message):
    log_audit("/rebaseline", message.chat.id)
    targets = parse_watch_paths()
    loop = asyncio.get_event_loop()
    read_results = await asyncio.gather(*[
        loop.run_in_executor(None, ssh_read_file, host, path)
        for host, path in targets
    ])
    updated = 0
    for (host, path), (ok, content) in zip(targets, read_results):
        if ok:
            with open(baseline_file_path(host, path), "w") as f:
                f.write(content)
            updated += 1
    await message.answer(f"✅ Baseline обновлён для {updated}/{len(targets)} файлов.")

@dp.message(Command("maintenance"))
async def cmd_maintenance(message: Message):
    parts = message.text.split()
    if len(parts) < 3:
        await message.answer("Использование: /maintenance <нода> <минуты>\nНапример: /maintenance host-196 60")
        return
    host, minutes_str = parts[1], parts[2]
    try:
        minutes = int(minutes_str)
    except ValueError:
        await message.answer("Минуты должны быть числом.")
        return
    log_audit(f"/maintenance {host} {minutes}", message.chat.id)
    until = set_maintenance(host, minutes)
    await message.answer(f"⏸ {host} в maintenance до {until[:16]} (алерты по этой ноде заглушены).")

@dp.message(Command("maintenance_clear"))
async def cmd_maintenance_clear(message: Message):
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("Использование: /maintenance_clear <нода>")
        return
    host = parts[1]
    log_audit(f"/maintenance_clear {host}", message.chat.id)
    clear_maintenance(host)
    await message.answer(f"▶️ {host} снят с maintenance.")

@dp.message(Command("maintenance_list"))
async def cmd_maintenance_list(message: Message):
    active = list_maintenance()
    if not active:
        await message.answer("Активных заглушек нет.")
        return
    lines = ["⏸ Активные maintenance-окна:"]
    for host, until, reason in active:
        lines.append(f"  {host} — до {until[:16]}" + (f" ({reason})" if reason else ""))
    await message.answer("\n".join(lines))

@dp.message(Command("blast"))
async def cmd_blast(message: Message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Использование: /blast <имя_сервиса>\nНапример: /blast jellyfin")
        return
    service = parts[1].strip()
    log_audit(f"/blast {service}", message.chat.id)
    await message.answer(f"🔎 Строю граф зависимостей для «{service}»...")
    await job_blast_radius(service, manual_chat_id=message.chat.id)

@dp.message(Command("audit"))
async def cmd_audit(message: Message):
    conn = db()
    rows = conn.execute("SELECT command, ts FROM audit ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    if not rows:
        await message.answer("Аудит пуст.")
        return
    lines = ["Последние команды (sentry-ops):"]
    for command, ts in rows:
        lines.append(f"[{ts[:16]}] {command}")
    await message.answer("\n".join(lines))


# ================= MAIN =================

async def main():
    os.makedirs("/app/data", exist_ok=True)
    os.makedirs(BASELINE_DIR, exist_ok=True)
    db().close()

    # Явно расширяем пул потоков: нагрузка тут I/O-bound (SSH, HTTP, subprocess-и ждут сеть),
    # а не CPU-bound — дефолтный executor (min(32, cpu+4)) на слабом CPU слишком мал
    # для параллельных SSH-сессий на 6+ нод одновременно.
    from concurrent.futures import ThreadPoolExecutor
    asyncio.get_event_loop().set_default_executor(ThreadPoolExecutor(max_workers=24))

    # регистрируем меню команд в Telegram (кнопка "/" рядом с полем ввода)
    from aiogram.types import BotCommand
    await bot.set_my_commands([
        BotCommand(command="scan", description="Скан подсети + nuclei"),
        BotCommand(command="status", description="Сводка последнего скана"),
        BotCommand(command="hosts", description="Известные хосты/порты"),
        BotCommand(command="findings", description="Находки Nuclei"),
        BotCommand(command="backup", description="Проверка бэкапов"),
        BotCommand(command="bloat", description="Bloat Docker-образов"),
        BotCommand(command="drift", description="Дрейф конфигов"),
        BotCommand(command="rebaseline", description="Принять текущие конфиги как baseline"),
        BotCommand(command="maintenance", description="Заглушить алерты по ноде"),
        BotCommand(command="maintenance_list", description="Активные заглушки"),
        BotCommand(command="blast", description="Что уронит сервис"),
        BotCommand(command="audit", description="Последние команды"),
    ])

    scheduler.add_job(job_network_scan, "interval", hours=SCAN_INTERVAL_HOURS)
    scheduler.add_job(job_backup_verify, "interval", hours=BACKUP_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_docker_bloat, "interval", hours=BLOAT_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_config_drift, "interval", hours=DRIFT_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_check_escalations, "interval", minutes=ESCALATION_CHECK_MINUTES)
    scheduler.start()

    log.info("Sentry Ops bot starting")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
