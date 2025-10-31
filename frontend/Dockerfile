# -------- build --------
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --include=dev
COPY . .
# Default can be overridden by docker-compose build args
ARG VITE_DEFAULT_API_BASE=http://localhost:8000
ENV VITE_DEFAULT_API_BASE=$VITE_DEFAULT_API_BASE
RUN npm run build

# -------- runtime --------
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
