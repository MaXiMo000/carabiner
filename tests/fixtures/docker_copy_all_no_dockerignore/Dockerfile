FROM node:22-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
USER 10001
CMD ["node", "server.js"]
