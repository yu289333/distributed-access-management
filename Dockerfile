FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY examples ./examples

RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8080

CMD ["python", "-m", "src.server"]
