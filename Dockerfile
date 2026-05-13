FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY reconlite.py ./reconlite.py
COPY README.md ./README.md

ENTRYPOINT ["python", "/app/reconlite.py"]