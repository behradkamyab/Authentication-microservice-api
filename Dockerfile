FROM node:latest

WORKDIR /app

COPY package.json .

RUN npm install

COPY . .

ARG DEFAULT_PORT=8080

ENV PORT ${DEFAULT_PORT}

EXPOSE ${PORT}

CMD [ "node", "app.js" ]

