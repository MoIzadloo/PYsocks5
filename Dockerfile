FROM alpine:latest
WORKDIR /code
COPY . .
RUN apk add --no-cache py3-pip py3-setuptools python3
CMD [ "python3", "-u", "./app.py"]