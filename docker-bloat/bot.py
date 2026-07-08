import asyncio
import logging
import os
from datetime import datetime

import paramiko
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("docker-bloat")

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
CHECK_INTERVAL_HOURS = int(os.environ.get("CHECK_INTERVAL_HOURS", "168"))
SSH_USER = os.environ.get("SSH_USER", "admin1")
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/app/ssh/id_rsa")

# host:label — по умолчанию твой кластер
NODES = os.environ.get(
    "NODES",
    "192.168.5.100:srv1,192.168.5.101:sand-box,192.168.5.102:host-196,"
    "192.168.5.104:hren-znaet,192.168.5.164:new-node,192.168.5.225:setevoipc",
)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
scheduler = AsyncIOScheduler()


def parse_nodes():
    result = []
    for entry in NODES.split(","):
        entry = entry.strip()
        if not entry:
            continue
        host, _, label = entry.partition(":")
        result.append((host.strip(), label.strip() or host.strip()))
    return result


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


def analyze_node(host: str, label: str) -> dict:
    """Собирает docker system df + список dangling images по одной ноде."""
    ok, df_out = ssh_run(host, "docker system df --format '{{json .}}' 2>/dev/null")
    ok2, dangling_out = ssh_run(host, "docker images -f dangling=true --format '{{.Repository}}\t{{.Size}}' 2>/dev/null")
    ok3, prune_size = ssh_run(host, "docker system df -v 2>/dev/null | grep 'Reclaimable' -A2 || true")

    if not ok:
        return {"label": label, "host": host, "error": df_out}

    dangling_count = 0
    if ok2 and dangling_out.strip():
        dangling_count = len([l for l in dangling_out.strip().splitlines() if l.strip()])

    return {
        "label": label,
        "host": host,
        "df_raw": df_out.strip(),
        "dangling_count": dangling_count,
        "error": None,
    }


async def run_check(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    nodes = parse_nodes()
    loop = asyncio.get_event_loop()

    await bot.send_message(chat, f"🔎 Проверяю Docker на {len(nodes)} нодах...")

    lines = ["🐳 Docker bloat отчёт:"]
    any_ok = False
    for host, label in nodes:
        result = await loop.run_in_executor(None, analyze_node, host, label)
        if result.get("error"):
            lines.append(f"\n📍 {label} ({host}) — ❌ {result['error'][:150]}")
            continue
        any_ok = True
        lines.append(f"\n📍 {label} ({host})")
        lines.append(f"  Висящих (dangling) образов: {result['dangling_count']}")
        # df_raw содержит JSON-строки построчно (Images/Containers/Volumes/BuildCache)
        for row in result["df_raw"].splitlines():
            lines.append(f"  {row}")

    if not any_ok:
        lines.append("\nНи одна нода не ответила — проверь SSH_KEY_PATH и доступ.")

    text = "\n".join(lines)
    for i in range(0, len(text), 3500):
        await bot.send_message(chat, text[i:i+3500])


@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    nodes = parse_nodes()
    await message.answer(
        "Docker Bloat Bot\n\n"
        "/scan — проверить все ноды прямо сейчас\n"
        "/nodes — список нод в конфиге\n"
        f"Нод в конфиге: {len(nodes)}\n"
        f"Автопроверка каждые {CHECK_INTERVAL_HOURS} ч."
    )


@dp.message(Command("scan"))
async def cmd_scan(message: Message):
    await run_check(manual_chat_id=message.chat.id)


@dp.message(Command("nodes"))
async def cmd_nodes(message: Message):
    nodes = parse_nodes()
    lines = ["Ноды:"] + [f"• {label} ({host})" for host, label in nodes]
    await message.answer("\n".join(lines))


async def main():
    scheduler.add_job(run_check, "interval", hours=CHECK_INTERVAL_HOURS)
    scheduler.start()
    log.info("Docker Bloat bot starting")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
