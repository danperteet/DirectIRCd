#!/bin/sh
echo "Original code from genssl by charybdis development team, modified by the DirectIRCd Team "
echo "Generating self-signed certificate .. "
openssl req -x509 -nodes -newkey rsa:2048 -keyout ../etc/ssl.key -out ../etc/ssl.pub

echo "Now it's time to make the final part"

openssl req -new -days 365 -x509 -key ssl.key -out cert.pem
echo " 
Now change these lines in the IRCd config file:

    rsa_private_key_file = "etc/ssl.key";
    ssl_certificate_file = "etc/dh.pem";

Enjoy using ssl.
"