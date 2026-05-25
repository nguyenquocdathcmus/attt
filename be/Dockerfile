FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential curl perl libnet-ssleay-perl libjson-perl libxml-writer-perl libwhisker2-perl git \
  && rm -rf /var/lib/apt/lists/* \
  && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
  && chmod +x /opt/nikto/program/nikto.pl \
  && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=120 --retries=5 -r requirements.txt

COPY app ./app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
