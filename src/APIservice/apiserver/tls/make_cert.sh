#!/bin/bash
openssl req -new -x509 -nodes -sha384 -subj "/O=ZeroPass PassID/OU=PassID Server/CN=PassID Server" -key server_key.pem -out "passid_server_new.cer"
