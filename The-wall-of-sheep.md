设置静态 ip

> vim /etc/network/interfaces

```shell
auto lo
iface lo inet loopback

auto eth0
# iface eth0 inet dhcp
iface eth0 inet static
address 192.168.0.106
netmask 255.255.255.0
gateway 192.168.0.1

auto at0
iface at0 inet static
address 192.168.1.1
netmask 255.255.255.0
```

安装 dhcp 服务所需软件

```
apt install isc-dhcp-server
```



vim /etc/dhcp/dhcpd.conf

```shell
authoritative;
default-lease-time 700;
max-lease-time 8000;

subnet 192.168.1.0 netmask 255.255.255.0 {
	option routers 192.168.1.1;
	option subnet-mask 255.255.255.0;
	option domain-name-servers 192.168.0.106;
	range 192.168.1.100 192.168.1.150;
}
```

> vim /etc/default/isc-dhcp-server

```shell
INTERFACESv4="at0"
INTERFACESv6="at0"
```

将无线网卡启动起来：

```shell
ifconfig wlan0 up
```

杀死其余影响进程:

```shell
airmon-ng check kill
```

将无线网卡设置为监听模式：

```shell
airmon-ng start wlan0
```

产生虚假 WiFi 信号

```shell
airbase-ng -e "Free-WiFi" -c 6 wlan0mon
airbase-ng -e "Free-WiFi" -P -C 30 -v wlan0mon | tee nohup.out
```

配置 at0 虚拟网卡

```shell
ifconfig at0 up
ifconfig at0 192.168.1.1 netmask 255.255.255.0 #分配IP和掩码
# route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1 #增加路由项，统一由10.0.0.1(at0)来传输数据。
```

\# 打开 ip 地址转发

```shell
echo 1 > /proc/sys/net/ipv4/ip_forward
```

\# 开启 dhcp 服务

```shell
dhcpd -cf /etc/dhcp/dhcpd.conf -pf /var/run/dhclient-eth0.pid at0
service isc-dhcp-server start
```

配置 NAT

```
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 
iptables -A FORWARD -i wlan0mon -o eth0 -j ACCEPT
iptables -A FORWARD -i wlan0mon -o eth0 -j ACCEPT 

iptables -t nat -A POSTROUTING -o ens32 -j MASQUERADE 
iptables -A FORWARD -i wlan0mon -o ens32 -j ACCEPT
```

