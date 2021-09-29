FROM golang:1.16

EXPOSE 80
EXPOSE 443

ENV GO111MODULE=on

# Go get awscli so we can S3 in our private key at startup
RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*
RUN cd /tmp && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip awscliv2.zip && ./aws/install && rm -rf aws

ADD . /go/src/github.com/sullivanmatt/check.tls.support
ADD config /config
RUN cd /go/src/github.com/sullivanmatt/check.tls.support && go install -mod=vendor github.com/sullivanmatt/check.tls.support

# Provided by kubernetes secrets or some such
VOLUME "/secrets"

RUN mkdir -p /secrets/ && mv /config/development_cert.pem /secrets/tls.crt && mv /config/development_key.pem /secrets/tls.key
RUN chown -R www-data /go/src/github.com/sullivanmatt/check.tls.support && chown -R www-data /secrets

# Fargate doesn't seem to play well with non-root bound to priv ports.
# Hopefully we can revisit and find a better way.
#RUN setcap cap_net_bind_service=+ep bin/check.tls.support
#USER www-data

CMD ["/bin/bash", "-c", "aws s3 cp s3://tls-support-prod/tls.support.cert /secrets/tls.crt && aws s3 cp s3://tls-support-prod/tls.support.key /secrets/tls.key; \
    check.tls.support \
    -httpsAddr=:443 \
    -httpAddr=:80 \
    -templateDir=/go/src/github.com/sullivanmatt/check.tls.support/templates \
    -staticDir=/go/src/github.com/sullivanmatt/check.tls.support/static \
    -cert=/secrets/tls.crt \
    -key=/secrets/tls.key \
    -hmacSecret=$HMACSECRET"]
