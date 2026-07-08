#!/usr/bin/env bash
set -e

echo "=== Homelab Bots — установка ==="

# 1. Проверка docker
if ! command -v docker &> /dev/null; then
    echo "Docker не найден. Ставлю..."
    curl -fsSL https://get.docker.com | sh
fi

if ! docker compose version &> /dev/null; then
    echo "ERROR: docker compose plugin не найден. Установи docker-compose-plugin вручную."
    exit 1
fi

# 2. .env
if [ ! -f .env ]; then
    cp .env.example .env
    echo ""
    echo ">>> Создан .env из шаблона. ЗАПОЛНИ токены ботов перед продолжением:"
    echo "    nano .env"
    echo ""
    read -p "Открыть .env в nano сейчас? [y/N] " yn
    if [[ "$yn" == "y" || "$yn" == "Y" ]]; then
        nano .env
    else
        echo "Отредактируй .env вручную и запусти скрипт заново."
        exit 0
    fi
fi

# 3. Проверка что токены заполнены
if grep -q "123456:AA\|123456:BB" .env; then
    echo "ERROR: похоже, токены в .env ещё не заполнены (стоят placeholder-значения)."
    echo "Открой .env и впиши реальные BOT_TOKEN/CHAT_ID."
    exit 1
fi

# 4. Сборка и запуск
mkdir -p data/content-scout data/security-scanner
echo "Собираю и запускаю контейнеры..."
docker compose up -d --build

echo ""
echo "=== Готово ==="
docker compose ps
echo ""
echo "Логи: docker compose logs -f"
echo "Остановить: docker compose down"
