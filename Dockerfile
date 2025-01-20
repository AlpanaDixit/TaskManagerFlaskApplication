FROM python:3.9-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8005

ENV FLASK_APP=app.py

CMD ["flask", "run", "--host=0.0.0.0"]