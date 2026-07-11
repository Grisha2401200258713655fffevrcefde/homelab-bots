FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Скачиваем офлайн-модель перевода en->ru ОДИН РАЗ при сборке образа.
# Дальше перевод работает полностью локально, без единого сетевого запроса —
# больше никаких зависаний из-за подвисшей сети до Google Translate.
RUN python3 -c "\
import argostranslate.package; \
argostranslate.package.update_package_index(); \
available = argostranslate.package.get_available_packages(); \
pkg = next(p for p in available if p.from_code == 'en' and p.to_code == 'ru'); \
argostranslate.package.install_from_path(pkg.download())"

COPY bot.py .
COPY feeds.yaml .

CMD ["python", "bot.py"]
