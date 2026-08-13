FROM python:3.12-alpine

WORKDIR /app
RUN pip install --no-cache-dir --upgrade "pip==26.1.2"
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER 10001
EXPOSE 5000
CMD ["python", "app.py"]
