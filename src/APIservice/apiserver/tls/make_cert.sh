#!/bin/bash
openssl req -new -x509 -nodes -days 356 -sha384 -subj "/O=ZeroPass PassID/OU=PassID Server/CN=PassID Server" -key server_key.pem -out "passid_server_new.cer"

# der encoding
openssl x509 -outform der -in "passid_server_new.cer" -out "passid_server_new.der"
