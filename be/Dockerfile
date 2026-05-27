# syntax=docker/dockerfile:1.7
# BuildKit cache mounts — pip và apt cache giữa các lần build
# Lần đầu build: ~3-5 phút | Rebuild sau khi sửa code: ~10 giây

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ── System deps + Nikto ──────────────────────────────────────────────────────
# Cache apt packages giữa các lần build (không download lại nếu không đổi layer)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        perl \
        libnet-ssleay-perl \
        libjson-perl \
        libxml-writer-perl \
        libwhisker2-perl \
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# ── Python dependencies ───────────────────────────────────────────────────────
# Tách layer này ra: chỉ rebuild khi requirements.txt thay đổi
COPY requirements.txt .

# Install CPU-only torch to avoid pulling CUDA wheels during build
ARG TORCH_CPU_INDEX_URL=https://download.pytorch.org/whl/cpu
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --index-url "${TORCH_CPU_INDEX_URL}" torch

# Cache pip packages tại /root/.cache/pip giữa các lần build
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# ── Application code ──────────────────────────────────────────────────────────
# Layer này thay đổi thường xuyên nhất — để cuối cùng để tận dụng cache
COPY app ./app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
