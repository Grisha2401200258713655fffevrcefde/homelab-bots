import asyncio
import logging
import os
import socket
import ssl
from datetime import datetime

from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cert-monitor")

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
CHECK_INTERVAL_HOURS = int(os.environ.get("CHECK_INTERVAL_HOURS", "24"))
WARN_DAYS = int(os.environ.get("WARN_DAYS", "14"))

# формат: host:port,host:port  (port по умолчанию 443)
TARGETS = os.environ.get("TARGETS", "")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
scheduler = AsyncIOScheduler()


def parse_targets():
    result = []
    for entry in TARGETS.split(","):
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
        not_after = cert["notAfter"]
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days
        return {"host": host, "port": port, "ok": True, "days_left": days_left, "expires": expires.isoformat()}
    except Exception as e:
        return {"host": host, "port": port, "ok": False, "error": str(e)}


async def run_check(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    targets = parse_targets()
    if not targets:
        await bot.send_message(chat, "TARGETS не задан в .env — нечего проверять.")
        return

    loop = asyncio.get_event_loop()
    lines = []
    problems = 0
    for host, port in targets:
        result = await loop.run_in_executor(None, check_cert, host, port)
        if not result["ok"]:
            problems += 1
            lines.append(f"❌ {host}:{port} — не смог проверить: {result['error']}")
            continue
        days = result["days_left"]
        if days < 0:
            problems += 1
            lines.append(f"🔴 {host}:{port} — СЕРТИФИКАТ ПРОТУХ {abs(days)} дн. назад!")
        elif days <= WARN_DAYS:
            problems += 1
            lines.append(f"🟠 {host}:{port} — истекает через {days} дн. ({result['expires'][:10]})")
        else:
            lines.append(f"✅ {host}:{port} — ещё {days} дн. ({result['expires'][:10]})")

    header = f"🔐 Проверка сертификатов ({len(targets)} целей"
    header += f", {problems} проблем)" if problems else ")"
    await bot.send_message(chat, header + "\n" + "\n".join(lines))


@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    targets = parse_targets()
    await message.answer(
        "Cert/Domain Expiry Bot\n\n"
        "/check — проверить сертификаты прямо сейчас\n"
        f"Целей в конфиге: {len(targets)}\n"
        f"Порог тревоги: {WARN_DAYS} дн. до истечения\n"
        f"Автопроверка каждые {CHECK_INTERVAL_HOURS} ч."
    )


@dp.message(Command("check"))
async def cmd_check(message: Message):
    await run_check(manual_chat_id=message.chat.id)


async def main():
    scheduler.add_job(run_check, "interval", hours=CHECK_INTERVAL_HOURS)
    scheduler.start()
    log.info("Cert Monitor bot starting")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
