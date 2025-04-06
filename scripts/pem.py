#!/usr/bin/python3
import sys
from Cryptodome.PublicKey import RSA
import subprocess

p = int(sys.argv[1], 16)
q = int(sys.argv[2], 16)
N = p * q
e = 65537
d = pow(e, -1, (p-1)*(q-1))
key = RSA.construct((N,e,d,p,q))
pem = key.export_key('PEM')

# pem.decode() gives an (according to openssl) "traditional" format PEM key;
# let openssl convert it to its normal PEM format.
subprocess.run(["openssl", "rsa"], input=pem.decode(), encoding='utf-8', stderr=subprocess.DEVNULL) 
