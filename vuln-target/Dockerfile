FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN mkdir -p /data
CMD ["sh", "-c", "python init_db.py && python app.py"]
