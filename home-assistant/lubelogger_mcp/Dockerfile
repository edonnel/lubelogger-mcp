# builds the reviewed commit of the fork; to update, change REF here and version in config.yaml
ARG REF=53b68651cf2322bc9100ecceccc3b3f8e51da607

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
