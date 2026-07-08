import asyncio
import io
import logging
import os
import random
import sqlite3
import tarfile
import zipfile
from datetime import datetime

from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("backup-verify")

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
CHECK_INTERVAL_HOURS = int(os.environ.get("CHECK_INTERVAL_HOURS", "168"))  # раз в неделю по умолчанию
DB_PATH = "/app/data/backup_verify.db"

# --- MinIO (S3-совместимый) ---
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "")   # напр. 192.168.5.102:9000
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "")
MINIO_SECURE = os.environ.get("MINIO_SECURE", "false").lower() == "true"

# --- Duplicati REST API (статус последнего бэкапа) ---
DUPLICATI_URL = os.environ.get("DUPLICATI_URL", "")     # напр. http://192.168.5.102:8200
DUPLICATI_PASSWORD = os.environ.get("DUPLICATI_PASSWORD", "")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
scheduler = AsyncIOScheduler()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT, target TEXT, ok INTEGER,
            detail TEXT, checked_at TEXT
        )
    """)
    return conn


def check_archive_integrity(data: bytes, name: str) -> tuple[bool, str]:
    """Проверяет, что архив реально открывается и не битый."""
    try:
        if name.endswith((".zip",)):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                bad = z.testzip()
                if bad:
                    return False, f"повреждён элемент внутри архива: {bad}"
                return True, f"zip OK, {len(z.namelist())} файлов внутри"
        elif name.endswith((".tar.gz", ".tgz", ".tar")):
            mode = "r:gz" if name.endswith((".tar.gz", ".tgz")) else "r"
            with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as t:
                members = t.getmembers()
                return True, f"tar OK, {len(members)} файлов внутри"
        else:
            if len(data) == 0:
                return False, "файл нулевого размера"
            return True, f"файл не архив, размер {len(data)} байт — базовая проверка (не пустой) пройдена"
    except Exception as e:
        return False, f"архив повреждён: {e}"


def minio_random_object_check() -> tuple[bool, str]:
    try:
        from minio import Minio
    except ImportError:
        return False, "пакет minio не установлен в контейнере"

    if not (MINIO_ENDPOINT and MINIO_ACCESS_KEY and MINIO_SECRET_KEY and MINIO_BUCKET):
        return False, "MinIO не сконфигурирован (проверь MINIO_* переменные в .env)"

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
        return False, "Duplicati не сконфигурирован (DUPLICATI_URL пуст)"
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{DUPLICATI_URL}/api/v1/backups", timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return False, f"Duplicati API вернул {resp.status} (возможна авторизация)"
                data = await resp.json()
                if not data:
                    return False, "нет настроенных задач бэкапа"
                lines = []
                any_bad = False
                for job in data:
                    name = job.get("Backup", {}).get("Name", "unknown")
                    metadata = job.get("Backup", {}).get("Metadata", {})
                    last_result = metadata.get("LastBackupResult", "Unknown")
                    if last_result != "Success":
                        any_bad = True
                    lines.append(f"{name}: {last_result}")
                return (not any_bad), "; ".join(lines)
    except Exception as e:
        return False, f"не смог достучаться до Duplicati: {e}"


async def run_check(manual_chat_id: int | None = None):
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
        await bot.send_message(chat, "Ничего не настроено — заполни MINIO_* или DUPLICATI_* в .env")
        return

    conn = db()
    now = datetime.utcnow().isoformat()
    lines = ["📦 Проверка бэкапов:"]
    for source, ok, detail in results:
        emoji = "✅" if ok else "🔴"
        lines.append(f"{emoji} {source}: {detail}")
        conn.execute(
            "INSERT INTO checks (source, target, ok, detail, checked_at) VALUES (?,?,?,?,?)",
            (source, "", int(ok), detail, now)
        )
    conn.commit()
    conn.close()

    await bot.send_message(chat, "\n".join(lines))


@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    await message.answer(
        "Backup Verify Bot\n\n"
        "/verify — запустить проверку прямо сейчас (скачивает случайный файл и тестирует архив)\n"
        "/history — последние результаты проверок\n"
        f"Авто-проверка каждые {CHECK_INTERVAL_HOURS} ч."
    )


@dp.message(Command("verify"))
async def cmd_verify(message: Message):
    await message.answer("🔎 Проверяю бэкапы...")
    await run_check(manual_chat_id=message.chat.id)


@dp.message(Command("history"))
async def cmd_history(message: Message):
    conn = db()
    rows = conn.execute("SELECT source, ok, detail, checked_at FROM checks ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    if not rows:
        await message.answer("Проверок ещё не было. /verify")
        return
    lines = ["История проверок:"]
    for source, ok, detail, checked_at in rows:
        emoji = "✅" if ok else "🔴"
        lines.append(f"{emoji} [{checked_at[:16]}] {source}: {detail}")
    await message.answer("\n".join(lines))


async def main():
    os.makedirs("/app/data", exist_ok=True)
    db().close()
    scheduler.add_job(run_check, "interval", hours=CHECK_INTERVAL_HOURS)
    scheduler.start()
    log.info("Backup Verify bot starting, interval=%sh", CHECK_INTERVAL_HOURS)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
