# client/Dockerfile
FROM nginx:stable-alpine3.20-perl

RUN apk add --no-cache curl

CMD ["sh", "-c", "while true; do curl -s http://server:80; sleep 5; done"]