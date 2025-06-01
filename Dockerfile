FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY docx_builder/package.json docx_builder/
RUN cd docx_builder && npm install --production && cd ..

COPY . .
RUN mkdir -p reports database ui/static/logos

EXPOSE 5000

CMD ["python", "app.py"]
