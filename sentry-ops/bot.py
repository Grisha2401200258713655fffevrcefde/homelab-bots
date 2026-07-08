import asyncio
import difflib
import io
import json
import logging
import os
import random
import socket
import sqlite3
import ssl
import subprocess
import tarfile
import zipfile
from datetime import datetime

import aiohttp
import nmap
import paramiko
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
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

# ---------- Resource waste ----------
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://192.168.5.100:9090")
WASTE_CHECK_INTERVAL_HOURS = int(os.environ.get("WASTE_CHECK_INTERVAL_HOURS", "168"))
WASTE_LOOKBACK = os.environ.get("WASTE_LOOKBACK", "30d")
WASTE_CPU_IDLE_THRESHOLD_PCT = float(os.environ.get("WASTE_CPU_IDLE_THRESHOLD_PCT", "2"))
WASTE_MIN_MEM_MB = float(os.environ.get("WASTE_MIN_MEM_MB", "100"))

# ---------- Docker bloat ----------
BLOAT_CHECK_INTERVAL_HOURS = int(os.environ.get("BLOAT_CHECK_INTERVAL_HOURS", "168"))

# ---------- Cert monitor ----------
CERT_CHECK_INTERVAL_HOURS = int(os.environ.get("CERT_CHECK_INTERVAL_HOURS", "24"))
CERT_WARN_DAYS = int(os.environ.get("CERT_WARN_DAYS", "14"))
CERT_TARGETS = os.environ.get("CERT_TARGETS", "")

# ---------- Config drift ----------
DRIFT_CHECK_INTERVAL_HOURS = int(os.environ.get("DRIFT_CHECK_INTERVAL_HOURS", "24"))
DRIFT_WATCH_PATHS = os.environ.get("DRIFT_WATCH_PATHS", "")
BASELINE_DIR = "/app/data/baseline"

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


# ================= NETWORK SCAN =================

def run_nmap_scan(subnet: str):
    scanner = nmap.PortScanner()
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
            ["nuclei", "-l", target_file, "-severity", NUCLEI_SEVERITY, "-jsonl", "-silent", "-timeout", "5"],
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


async def explain_finding(text: str) -> str:
    if not OLLAMA_HOST:
        return ""
    prompt = (f"Кратко (2-3 предложения, по-русски) объясни для домашнего сервера/сисадмина, "
              f"что означает эта находка сканера безопасности и что с ней делать:\n{text}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{OLLAMA_HOST}/api/generate",
                                     json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                                     timeout=aiohttp.ClientTimeout(total=60)) as resp:
                data = await resp.json()
                return data.get("response", "").strip()
    except Exception:
        return ""


async def job_network_scan(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    await bot.send_message(chat, f"🔎 Скан подсети {SUBNET}...")
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
        lines = ["🔒 Порты закрылись:"]
        for c in closed_entries:
            lines.append(f"  {c['host']}:{c['port']}/{c['proto']} ({c['service']})")
        await bot.send_message(chat, "\n".join(lines))
    if not new_entries and not closed_entries:
        await bot.send_message(chat, f"✅ Изменений нет. Хостов онлайн: {len(scan_results)}")

    targets = []
    for host, ports in scan_results.items():
        for p in ports:
            if p["service"] in ("http", "https", "http-proxy", "http-alt") or p["port"] in (80, 443, 8080, 8443):
                scheme = "https" if p["service"] == "https" or p["port"] == 443 else "http"
                targets.append(f"{scheme}://{host}:{p['port']}")

    if targets:
        await bot.send_message(chat, f"🛡 Nuclei по {len(targets)} веб-сервисам...")
        findings = await loop.run_in_executor(None, run_nuclei, targets)
        store_findings(findings)
        if findings:
            for f in findings[:15]:
                sev = f.get("info", {}).get("severity", "unknown")
                name = f.get("info", {}).get("name", f.get("template-id", ""))
                host = f.get("host", "")
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(sev, "⚪")
                text = f"{emoji} [{sev.upper()}] {host}\n{name}"
                explanation = await explain_finding(f"{name} on {host}, severity {sev}")
                if explanation:
                    text += f"\n💡 {explanation}"
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
    for source, ok, detail in results:
        lines.append(f"{'✅' if ok else '🔴'} {source}: {detail}")
        conn.execute("INSERT INTO backup_checks (source,ok,detail,checked_at) VALUES (?,?,?,?)",
                     (source, int(ok), detail, now))
    conn.commit()
    conn.close()
    await bot.send_message(chat, "\n".join(lines))


# ================= RESOURCE WASTE =================

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


# ================= DOCKER BLOAT =================

def ssh_run(host: str, command: str, timeout=20) -> tuple[bool, str]:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=SSH_USER, key_filename=SSH_KEY_PATH, timeout=timeout)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        client.close()
        if err.strip() and not out.strip():
            return False, err.strip()
        return True, out
    except Exception as e:
        return False, str(e)


def analyze_node_bloat(host: str, label: str) -> dict:
    ok, df_out = ssh_run(host, "docker system df --format '{{json .}}' 2>/dev/null")
    ok2, dangling_out = ssh_run(host, "docker images -f dangling=true --format '{{.Repository}}\t{{.Size}}' 2>/dev/null")
    if not ok:
        return {"label": label, "host": host, "error": df_out}
    dangling_count = len([l for l in dangling_out.strip().splitlines() if l.strip()]) if ok2 and dangling_out.strip() else 0
    return {"label": label, "host": host, "df_raw": df_out.strip(), "dangling_count": dangling_count, "error": None}


async def job_docker_bloat(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    nodes = parse_nodes()
    loop = asyncio.get_event_loop()
    await bot.send_message(chat, f"🔎 Docker на {len(nodes)} нодах...")
    lines = ["🐳 Docker bloat отчёт:"]
    any_ok = False
    for host, label in nodes:
        result = await loop.run_in_executor(None, analyze_node_bloat, host, label)
        if result.get("error"):
            lines.append(f"\n📍 {label} ({host}) — ❌ {result['error'][:150]}")
            continue
        any_ok = True
        lines.append(f"\n📍 {label} ({host})")
        lines.append(f"  Висящих образов: {result['dangling_count']}")
        for row in result["df_raw"].splitlines():
            lines.append(f"  {row}")
    if not any_ok:
        lines.append("\nНи одна нода не ответила — проверь SSH_KEY_PATH.")
    text = "\n".join(lines)
    for i in range(0, len(text), 3500):
        await bot.send_message(chat, text[i:i+3500])


# ================= CERT MONITOR =================

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
    for host, path in targets:
        ok, content = await loop.run_in_executor(None, ssh_read_file, host, path)
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


# ================= HANDLERS =================

@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    await message.answer(
        "🛡 Sentry Ops Bot — всё в одном\n\n"
        "Сеть/безопасность:\n"
        "  /scan — скан подсети + nuclei\n"
        "  /status — сводка последнего скана\n"
        "  /hosts — известные хосты/порты\n"
        "  /findings — находки Nuclei\n\n"
        "Инфраструктура:\n"
        "  /backup — проверка бэкапов (restore-тест)\n"
        "  /waste — простаивающие контейнеры\n"
        "  /bloat — bloat Docker-образов по нодам\n"
        "  /certs — истечение SSL\n"
        "  /drift — дрейф конфигов\n"
        "  /rebaseline — принять текущие конфиги как baseline"
    )

@dp.message(Command("scan"))
async def cmd_scan(message: Message):
    await job_network_scan(manual_chat_id=message.chat.id)

@dp.message(Command("status"))
async def cmd_status(message: Message):
    conn = db()
    row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if not row:
        await message.answer("Сканов не было. /scan")
        return
    await message.answer(f"Последний скан: {row[1]}\nХостов онлайн: {row[3]}\nНовых портов: {row[4]}\nЗакрытых: {row[5]}")

@dp.message(Command("hosts"))
async def cmd_hosts(message: Message):
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
    await message.answer("🔎 Проверяю бэкапы...")
    await job_backup_verify(manual_chat_id=message.chat.id)

@dp.message(Command("waste"))
async def cmd_waste(message: Message):
    await message.answer("🔎 Анализирую метрики...")
    await job_resource_waste(manual_chat_id=message.chat.id)

@dp.message(Command("bloat"))
async def cmd_bloat(message: Message):
    await job_docker_bloat(manual_chat_id=message.chat.id)

@dp.message(Command("certs"))
async def cmd_certs(message: Message):
    await job_cert_check(manual_chat_id=message.chat.id)

@dp.message(Command("drift"))
async def cmd_drift(message: Message):
    await job_config_drift(manual_chat_id=message.chat.id)

@dp.message(Command("rebaseline"))
async def cmd_rebaseline(message: Message):
    targets = parse_watch_paths()
    loop = asyncio.get_event_loop()
    updated = 0
    for host, path in targets:
        ok, content = await loop.run_in_executor(None, ssh_read_file, host, path)
        if ok:
            with open(baseline_file_path(host, path), "w") as f:
                f.write(content)
            updated += 1
    await message.answer(f"✅ Baseline обновлён для {updated}/{len(targets)} файлов.")


# ================= MAIN =================

async def main():
    os.makedirs("/app/data", exist_ok=True)
    os.makedirs(BASELINE_DIR, exist_ok=True)
    db().close()

    scheduler.add_job(job_network_scan, "interval", hours=SCAN_INTERVAL_HOURS)
    scheduler.add_job(job_backup_verify, "interval", hours=BACKUP_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_resource_waste, "interval", hours=WASTE_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_docker_bloat, "interval", hours=BLOAT_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_cert_check, "interval", hours=CERT_CHECK_INTERVAL_HOURS)
    scheduler.add_job(job_config_drift, "interval", hours=DRIFT_CHECK_INTERVAL_HOURS)
    scheduler.start()

    log.info("Sentry Ops bot starting")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
