FROM node:18-alpine

WORKDIR /usr/src/app

# Install required dependencies for Google Cloud KMS
RUN apk add --no-cache python3 make g++

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"] 