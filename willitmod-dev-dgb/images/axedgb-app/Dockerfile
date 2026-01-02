FROM python:3.11-alpine

WORKDIR /app

RUN pip install --no-cache-dir pg8000==1.31.2

COPY app.py /app/app.py
COPY static/ /app/static/

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 3000

CMD ["python", "/app/app.py"]
