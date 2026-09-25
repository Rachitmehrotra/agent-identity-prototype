FROM python:3.12-slim
WORKDIR /app
ENV APP_ROOT=/app PYTHONPATH=/app PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ ./shared/
COPY sts/ ./sts/
COPY agents/ ./agents/
COPY mcp_gateway/ ./mcp_gateway/
COPY downstream/ ./downstream/
# Component selected per-Deployment via `command:` (e.g. ["python","sts/app.py"])
CMD ["python", "sts/app.py"]
