# Setup of the Cloudsuite VM

```
sudo apt install -y locales-all tmux docker.io htop


sudo docker run -dt --net=host --name=web_server cloudsuite/web-serving:web_server /etc/bootstrap.sh https 172.17.0.1 172.17.0.1 172.17.0.1 4 auto


mathe@gcex-cloudsuite1:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: ens4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc mq state UP group default qlen 1000
    link/ether 42:01:0a:84:00:05 brd ff:ff:ff:ff:ff:ff
    altname enp0s4
    inet 10.132.0.5/32 metric 100 scope global dynamic ens4
       valid_lft 2306sec preferred_lft 2306sec
    inet6 fe80::4001:aff:fe84:5/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:67:91:ea:65 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever



wget https://172.17.0.1:8443 --no-check-certificate

```

