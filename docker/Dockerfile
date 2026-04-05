# Stage 1: install dependencies
# BUILDPLATFORM = the machine running the build (e.g. linux/arm64 on Mac M1).
# Using the native build platform here keeps dependency installation fast —
# no emulation needed for pip install.
FROM --platform=$BUILDPLATFORM python:3.12-slim AS builder

WORKDIR /install

COPY requirements.txt .
RUN pip install --prefix=/install/deps --no-cache-dir -r requirements.txt


# Stage 2: runtime image
# TARGETPLATFORM = the platform the final image is intended to run on.
# This ensures the runtime layer matches the target architecture (amd64 or arm64).
FROM --platform=$TARGETPLATFORM python:3.12-slim AS runtime

ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install/deps /usr/local

# Copy application code
COPY app/ .

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BUILD_COMMIT=${BUILD_COMMIT} \
    BUILD_DATE=${BUILD_DATE}

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
