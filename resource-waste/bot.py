import asyncio
import logging
import os
from datetime import datetime

import aiohttp
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("resource-waste")

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://192.168.5.100:9090")
CHECK_INTERVAL_HOURS = int(os.environ.get("CHECK_INTERVAL_HOURS", "168"))  # раз в неделю
LOOKBACK = os.environ.get("LOOKBACK", "30d")
CPU_IDLE_THRESHOLD_PCT = float(os.environ.get("CPU_IDLE_THRESHOLD_PCT", "2"))
MIN_MEM_MB_TO_FLAG = float(os.environ.get("MIN_MEM_MB_TO_FLAG", "100"))

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
scheduler = AsyncIOScheduler()


async def prom_query(query: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            data = await resp.json()
            if data.get("status") != "success":
                raise RuntimeError(data)
            return data["data"]["result"]


async def find_wasted_resources():
    """Возвращает список контейнеров с низким CPU за LOOKBACK, но заметным потреблением RAM."""
    # средний % CPU за период по каждому контейнеру (cadvisor метрики)
    cpu_query = f'avg by (name) (rate(container_cpu_usage_seconds_total{{name!=""}}[{LOOKBACK}])) * 100'
    mem_query = 'avg by (name) (container_memory_usage_bytes{name!=""})'

    cpu_results = await prom_query(cpu_query)
    mem_results = await prom_query(mem_query)

    mem_by_name = {}
    for r in mem_results:
        name = r["metric"].get("name", "")
        try:
            mem_by_name[name] = float(r["value"][1]) / (1024 * 1024)  # MB
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
        if cpu_pct < CPU_IDLE_THRESHOLD_PCT and mem_mb >= MIN_MEM_MB_TO_FLAG:
            wasted.append((name, cpu_pct, mem_mb))

    wasted.sort(key=lambda x: -x[2])
    return wasted


async def run_check(manual_chat_id: int | None = None):
    chat = manual_chat_id or CHAT_ID
    try:
        wasted = await find_wasted_resources()
    except Exception as e:
        await bot.send_message(chat, f"Не смог достучаться до Prometheus ({PROMETHEUS_URL}): {e}")
        return

    if not wasted:
        await bot.send_message(chat, f"✅ За последние {LOOKBACK} простаивающих контейнеров с заметным RAM не найдено.")
        return

    total_mem = sum(m for _, _, m in wasted)
    lines = [f"💸 Простаивающие контейнеры за {LOOKBACK} (CPU < {CPU_IDLE_THRESHOLD_PCT}%):"]
    for name, cpu, mem in wasted[:20]:
        lines.append(f"  {name}: CPU {cpu:.2f}%, RAM {mem:.0f} МБ")
    lines.append(f"\nИтого можно потенциально освободить: ~{total_mem:.0f} МБ RAM")
    await bot.send_message(chat, "\n".join(lines))


@dp.message(Command("start", "help"))
async def cmd_help(message: Message):
    await message.answer(
        "Resource Waste Bot\n\n"
        "/scan — найти простаивающие контейнеры прямо сейчас\n"
        f"Смотрит на Prometheus: {PROMETHEUS_URL}\n"
        f"Порог: CPU < {CPU_IDLE_THRESHOLD_PCT}% за {LOOKBACK}, RAM >= {MIN_MEM_MB_TO_FLAG} МБ\n"
        f"Автопроверка каждые {CHECK_INTERVAL_HOURS} ч."
    )


@dp.message(Command("scan"))
async def cmd_scan(message: Message):
    await message.answer("🔎 Анализирую метрики...")
    await run_check(manual_chat_id=message.chat.id)


async def main():
    scheduler.add_job(run_check, "interval", hours=CHECK_INTERVAL_HOURS)
    scheduler.start()
    log.info("Resource Waste bot starting, prometheus=%s", PROMETHEUS_URL)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
