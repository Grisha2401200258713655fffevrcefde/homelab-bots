import asyncio
import difflib
import logging
import os
from datetime import datetime

import paramiko
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("config-drift")

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
CHECK_INTERVAL_HOURS = int(os.environ.get("CHECK_INTERVAL_HOURS", "24"))
SSH_USER = os.environ.get("SSH_USER", "admin1")
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/app/ssh/id_rsa")
BASELINE_DIR = "/app/data/baseline"

# формат: host|/remote/path/file[,host|/remote/path/file2,...]
# путь внутри baseline зеркалит host+path
WATCH_PATHS = os.environ.get("WATCH_PATHS", "")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
scheduler = AsyncIOScheduler()


def parse_watch_paths():
    result = []
    for entry in WATCH_PATHS.split(","):
        entry = entry.strip()
        if not entry or "|" not in entry:
            continue
        host, path = entry.split("|", 1)
        result.append((host.strip(), path.strip()))
    return result


def ssh_read_file(host: str, path: str) -> tuple[bool, str]:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=SSH_USER, key_filename=SSH_KEY_PATH, timeout=15)
        stdin, stdout, stderr = client.exec_command(f"cat {path}", timeout=15)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        client.close()
        if err.strip() and not out.strip():
            return False, err.strip()
        return True, out
    except Exception as e:
        return False, str(e)


def baseline_file_path(host: str, path: str) -> str:
    safe = path.replace("/", "_")
    return os.path.join(BASELINE_DIR, f"{host}_{safe}")


async def run_check(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    targets = parse_watch_paths()
    if not targets:
        await bot.send_message(chat, "WATCH_PATHS не задан в .env — нечего сравнивать.")
        return

    os.makedirs(BASELINE_DIR, exist_ok=True)
    loop = asyncio.get_event_loop()

    drift_found = []
    errors = []
    new_baselines = []

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
            diff = list(difflib.unified_diff(
                baseline.splitlines(), content.splitlines(),
                lineterm="", n=1
            ))
            drift_found.append((host, path, diff))

    lines = []
    if new_baselines:
        lines.append(f"📌 Создан baseline для {len(new_baselines)} новых файлов (первый запуск).")
    if errors:
        lines.append(f"❌ Не удалось прочитать {len(errors)} файлов:")
        lines.extend(f"  {e}" for e in errors)
    if drift_found:
        lines.append(f"\n⚠️ Обнаружен дрейф конфигов ({len(drift_found)}):")
        for host, path, diff in drift_found:
            lines.append(f"\n📍 {host}:{path}")
            diff_text = "\n".join(diff[:20])
            lines.append(f"```\n{diff_text}\n```")
    elif not new_baselines and not errors:
        lines.append("✅ Дрейфа не обнаружено, всё совпадает с baseline.")

    text = "\n".join(lines)
    for i in range(0, len(text), 3500):
        await bot.send_message(chat, text[i:i+3500], parse_mode="Markdown")


@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    targets = parse_watch_paths()
    await message.answer(
        "Config Drift Bot\n\n"
        "/check — сравнить конфиги с baseline прямо сейчас\n"
        "/rebaseline — принять текущее состояние как новый baseline (после осознанных правок)\n"
        f"Отслеживаемых файлов: {len(targets)}\n"
        f"Автопроверка каждые {CHECK_INTERVAL_HOURS} ч."
    )


@dp.message(Command("check"))
async def cmd_check(message: Message):
    await run_check(manual_chat_id=message.chat.id)


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


async def main():
    os.makedirs(BASELINE_DIR, exist_ok=True)
    scheduler.add_job(run_check, "interval", hours=CHECK_INTERVAL_HOURS)
    scheduler.start()
    log.info("Config Drift bot starting")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
