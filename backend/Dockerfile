# FastAPI + LangGraph backend
FROM python:3.11-slim

WORKDIR /app

# System deps kept minimal; psycopg[binary] ships its own libpq.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
# Config comes from the environment (compose env_file + overrides), not a .env file.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
