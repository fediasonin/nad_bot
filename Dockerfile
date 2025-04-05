FROM python


WORKDIR /app


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY script.py .
COPY config.py .

CMD ["python", "script.py"]