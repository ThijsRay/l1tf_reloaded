#!/bin/bash

echo "===[GENERATE SELF SIGNED SSL KEY AND CERTIFICATE]==="
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt -subj /C=NL/ST=nl/L=nl/O=vu/OU=vusec/CN=mathe.nl
sudo openssl rsa -in /etc/ssl/private/nginx-selfsigned.key -text

echo "===[INSTALL NGINX]==="
sudo apt install nginx -y

echo "===[CONFIGURE NGINX FOR HTTPS WITH OUR OWN KEY/CERT]==="
sudo sed -i -e 's|listen 80|# listen 80|g' /etc/nginx/sites-available/default
sudo sed -i -e 's|listen \[::\]:80|# listen \[::\]:80|g' /etc/nginx/sites-available/default
sudo sed -i -e 's|# listen 443|listen 443|g' /etc/nginx/sites-available/default
sudo sed -i -e 's|# listen \[::\]:443|listen \[::\]:443|g' /etc/nginx/sites-available/default
sudo sed -i -e 's|server_name _;|server_name mathe.nl;\n\tssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;\n\tssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;|g' /etc/nginx/sites-available/default
# let nginx sanity check the config:
sudo nginx -t

echo "===[RESTART NGINX]==="
sudo systemctl restart nginx

echo "===[HTTPS WEBPAGE]==="
wget -O /dev/stdout --no-check-certificate https://localhost:443
