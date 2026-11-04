# builds the reviewed commit of the fork; to update, change REF here and version in config.yaml
ARG REF=e9336f55f17acd42afb6d0de185b6b2641e395c4

FROM node:22-alpine AS build
ARG REF
RUN apk add --no-cache git
RUN git clone https://github.com/edonnel/lubelogger-mcp.git /src && git -C /src checkout --detach "$REF"
WORKDIR /src
RUN npm ci && npm run build && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /src/package.json /src/package-lock.json ./
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
COPY launch.mjs /launch.mjs
CMD ["node", "/launch.mjs"]
