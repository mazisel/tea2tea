FROM node:20-bullseye-slim

ENV NODE_ENV=production
ENV PORT=3010

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 build-essential \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

RUN npm install --omit=dev

COPY . .

EXPOSE ${PORT}

CMD ["npm", "run", "start"]
