ARG UBUNTU_IMAGE=ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78

FROM ${UBUNTU_IMAGE} AS node-builder

ARG NODE_VERSION=25.8.1
ARG NODE_SOURCE_SHA256=0b25b2b5fab80ea8b43fdaa7451f50065571e0bfda2524ca42bde8b98fe4d2d9
ARG NODE_BINARY_SHA256=4f068fde6d1856f5884072d086999e9ac82234139ddbd3157d15bd1c623e9f5c

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        ninja-build \
        python3 \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# The profiled Ubuntu target uses a PIE Node executable. Node's official Linux
# binary is ET_EXEC, so this stage reproduces the Ubuntu compiler-default PIE
# build used by the profile. The final image does not contain the toolchain.
WORKDIR /home/adrian/Targets/libheif/node-v25.8.1-pie-src
RUN curl -fsSLo /tmp/node.tar.xz \
        "https://nodejs.org/download/release/v${NODE_VERSION}/node-v${NODE_VERSION}.tar.xz" \
    && echo "${NODE_SOURCE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/node.tar.xz --strip-components=1 \
    && rm /tmp/node.tar.xz \
    && ./configure --ninja \
    && ninja -C out/Release node \
    && echo "${NODE_BINARY_SHA256}  out/Release/node" | sha256sum -c -

FROM ${UBUNTU_IMAGE} AS app-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY lab/package.json lab/package-lock.json ./
RUN npm ci --ignore-scripts=false
COPY lab/ ./
RUN npm run build \
    && mkdir -p uploads

FROM ${UBUNTU_IMAGE} AS target

LABEL org.opencontainers.image.title="Ubuntu 26.04 Next.js/libheif target" \
      org.opencontainers.image.version="ubuntu-nodejs-25.8.1-pie" \
      org.opencontainers.image.source="https://github.com/FORTBRIDGE-UK/libheif-grid-nextjs-rce"

WORKDIR /app
COPY --from=node-builder \
    /home/adrian/Targets/libheif/node-v25.8.1-pie-src/out/Release/node \
    /usr/local/bin/node
COPY --from=app-builder /app /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

EXPOSE 3000
CMD ["node", "node_modules/next/dist/bin/next", "start", "-p", "3000"]
