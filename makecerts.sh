#!/bin/bash

openssl genrsa -des3 -out ca.key 4096 && 
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt &&
openssl genrsa -des3 -out server.key 4096 &&
openssl req -new -key server.key -out server.csr &&
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt &&
openssl rsa -in server.key -out server.key.insecure &&
mv server.key.insecure server.key &&
openssl genrsa -des3 -out client.key 4096 &&
openssl req -new -key client.key -out client.csr &&
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt &&
openssl rsa -in client.key -out client.key.insecure &&
mv client.key.insecure client.key
