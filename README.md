howsmyssl
=========

check.tls.support is the web service that drives the TLS detection mechanisms on [https://tls.support](https://tls.support).
It is a fork of https://github.com/jmhodges/howsmyssl

Orientation
--------
This is a Go project.

Determining the client's security is done in
client_info.go.

This project requires Go 1.16 (or newer). `go build` will generate a static
binary called howsmyssl. This repo is `go get`'able, of course.

It has a fork of the Go crypto/tls library at ./tls/ in order to add a
ServerHandshake and expose the ClientHello struct.

It's been useful to me to use [justrun][justrun] to recompile the project
while modifying the template. Typical use is simply:

    justrun -c "go build && ./howsmyssl" -i howsmyssl . templates/

(Justrun has the benefit of controlling the lifecycle of a process, unlike
most other file watch utilities.)

[justrun]: https://github.com/jmhodges/justrun
