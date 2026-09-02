FROM node:20-alpine

WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
EXPOSE 5173
ENV API_PROXY=http://api:8000
CMD ["npm", "run", "dev"]
