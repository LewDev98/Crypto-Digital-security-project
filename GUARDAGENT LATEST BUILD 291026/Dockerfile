FROM node:22-slim
WORKDIR /app
COPY server ./server
COPY web ./web
WORKDIR /app/server
ENV NODE_ENV=production DATA_DIR=/data
EXPOSE 8080
CMD ["node", "--disable-warning=ExperimentalWarning", "src/index.js"]
