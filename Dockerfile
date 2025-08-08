FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
COPY phishing_checker.py .
COPY config.py .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "phishing_checker.py"]

