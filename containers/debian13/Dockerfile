ARG DEBIAN_IMAGE=debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

FROM ${DEBIAN_IMAGE} AS runtime

# Model a normal Debian deployment with Debian's supported Node.js package.
ARG NODEJS_PACKAGE_VERSION=20.19.2+dfsg-1+deb13u3
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        "nodejs=${NODEJS_PACKAGE_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && node --version

FROM runtime AS app-builder

# npm and its Debian build dependencies are intentionally absent from the
# final target stage.
ARG NPM_PACKAGE_VERSION=9.2.0~ds1-3
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        "npm=${NPM_PACKAGE_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && npm --version

WORKDIR /app
COPY lab/package.json lab/package-lock.json ./
RUN npm ci --ignore-scripts=false
COPY lab/ ./
RUN npm run build \
    && mkdir -p uploads

FROM runtime AS target

LABEL org.opencontainers.image.title="KAN-2162 Debian 13 Next.js/libheif target" \
      org.opencontainers.image.version="debian-nodejs-20.19.2" \
      uk.co.fortbridge.research-task="KAN-2162"

WORKDIR /app
COPY --from=app-builder /app /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

EXPOSE 3000
CMD ["node", "node_modules/next/dist/bin/next", "start", "-p", "3000"]
