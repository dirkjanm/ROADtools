# Build stage
FROM node:latest AS builder

COPY package*.json /usr/src/
WORKDIR /usr/src/
RUN npm install
ENV PATH /usr/src/node_modules/.bin:$PATH
COPY . /usr/src/app
WORKDIR /usr/src/app
RUN npm run docker

# Development stage
FROM node:latest AS dev
COPY package*.json /usr/src/
WORKDIR /usr/src/
RUN npm install --include=dev
ENV PATH /usr/src/node_modules/.bin:$PATH
COPY . /usr/src/app
WORKDIR /usr/src/app
EXPOSE 5173
CMD ["npm", "run", "dev"]

# Production stage
FROM nginx:alpine AS prod
COPY ./nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /usr/src/app/dist /usr/share/nginx/html

EXPOSE 5173
CMD ["nginx", "-g", "daemon off;"]