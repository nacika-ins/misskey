ARG NODE_VERSION=21.6.2-bullseye

FROM node:${NODE_VERSION} AS builder

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
	--mount=type=cache,target=/var/lib/apt,sharing=locked \
	rm -f /etc/apt/apt.conf.d/docker-clean \
	; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache \
	&& apt-get update \
	&& apt-get install -yqq --no-install-recommends \
	build-essential

RUN corepack enable

WORKDIR /misskey

COPY . ./

ARG NODE_ENV=production

RUN apt-get update
RUN apt-get install -y build-essential
RUN git submodule update --init
RUN npm ci
RUN npm run ci:all
RUN npm run build
RUN rm -rf .git

FROM node:${NODE_VERSION}-slim AS runner

ARG UID="991"
ARG GID="991"

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
	--mount=type=cache,target=/var/lib/apt,sharing=locked \
	rm -f /etc/apt/apt.conf.d/docker-clean \
	; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
	ffmpeg tini curl \
	&& corepack enable \
	&& groupadd -g "${GID}" misskey \
	&& useradd -l -u "${UID}" -g "${GID}" -m -d /misskey misskey \
	&& find / -type f -perm /u+s -ignore_readdir_race -exec chmod u-s {} \; \
	&& find / -type f -perm /g+s -ignore_readdir_race -exec chmod g-s {} \;

USER misskey
WORKDIR /misskey

COPY --chown=misskey:misskey . ./
COPY --chown=misskey:misskey --from=builder /misskey/node_modules ./node_modules
COPY --chown=misskey:misskey --from=builder /misskey/built ./built
COPY --chown=misskey:misskey --from=builder /misskey/packages/backend/node_modules ./packages/backend/node_modules
COPY --chown=misskey:misskey --from=builder /misskey/packages/backend/built ./packages/backend/built
COPY --chown=misskey:misskey --from=builder /misskey/packages/frontend/node_modules ./packages/frontend/node_modules
COPY --chown=misskey:misskey --from=builder /misskey/fluent-emojis /misskey/fluent-emojis

# ファイル所在チェック(/misskey/packages/backend/built/boot/index.js)
RUN if [ ! -f /misskey/packages/backend/built/boot/index.js ]; then \
    echo "Error: /misskey/packages/backend/built/boot/index.js not found" && exit 1; \
    fi


# ファイル所在チェック(/misskey/built/_vite_/meta.json)
RUN if [ ! -f /misskey/built/_vite_/meta.json ]; then \
    echo "Error: /misskey/built/_vite_/meta.json not found" && exit 1; \
    fi

# ファイル所在チェック(/misskey/built/_sw_dist_/sw.js)
RUN if [ ! -f /misskey/built/_sw_dist_/sw.js ]; then \
    echo "Error: /misskey/built/_sw_dist_/sw.js not found" && exit 1; \
    fi

ENV NODE_ENV=production
HEALTHCHECK --interval=5s --retries=20 CMD ["/bin/bash", "/misskey/healthcheck.sh"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["npm", "run", "migrateandstart"]
