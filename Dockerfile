FROM golang:1.16.8

EXPOSE 80
EXPOSE 443

ENV GO111MODULE=on
RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*
RUN cd /tmp && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip awscliv2.zip && ./aws/install && rm -rf aws

ADD . /go/src/github.com/sullivanmatt/howsmyssl
ADD config /config
RUN cd /go/src/github.com/sullivanmatt/howsmyssl && go install -mod=vendor github.com/sullivanmatt/howsmyssl

# Provided by kubernetes secrets or some such
VOLUME "/secrets"

RUN mkdir -p /secrets/ && mv /config/development_cert.pem /secrets/tls.crt && mv /config/development_key.pem /secrets/tls.key
RUN chown -R www-data /go/src/github.com/sullivanmatt/howsmyssl && chown -R www-data /secrets
#RUN setcap cap_net_bind_service=+ep bin/howsmyssl

#USER www-data

CMD ["/bin/bash", "-c", "aws s3 cp s3://tls-support-prod/tls.support.cert /secrets/tls.crt && aws s3 cp s3://tls-support-prod/tls.support.key /secrets/tls.key; \
    howsmyssl \
    -httpsAddr=:443 \
    -httpAddr=:80 \
    -templateDir=/go/src/github.com/sullivanmatt/howsmyssl/templates \
    -staticDir=/go/src/github.com/sullivanmatt/howsmyssl/static \
    -cert=/secrets/tls.crt \
    -key=/secrets/tls.key"]
    #-allowListsFile=/etc/howsmyssl-allowlists/allow_lists.json \
    #-adminAddr=:4567 \
    #-vhost=tls.support \
    #-acmeRedirect=$ACME_REDIRECT_URL \
    #-allowLogName=howsmyssl_allowance_checks \
