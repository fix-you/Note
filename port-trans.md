### 服务器端:（只用ssh映射，不用跑shadowsocks）
```shell

ssh -R 0.0.0.0:2333:localhost:2333 root@120.79.1.209

vi /etc/ssh/sshd_config
添加一行 //添加GatewayPorts yes  # 使服务器的ssh允许转发0.0.0.0

netstat -an | grep 2333  # 查看端口转发情况
ufw allow 2333    # 防火墙打开端口，记得打开阿里云官网的防火墙端口
service sshd restart

```

### 内网端（跑shadowsocks）
```shell
ssserver -p 2333 -k login_233 -m aes-256-cfb  # 跑shadowsocks
ssh -R 0.0.0.0:2333:localhost:2333 root@120.79.1.209  # ssh设置

```
### 访问
```shell
sslocal -s 35.201.152.114 -p 2333 -k 123456 -m aes-256-cfb -l 1082
//第三方进行
//测试端口
```

## 小问题

出现 问题 ssserver 无法打开
原因：本文适用于解决openssl升级到1.1.0以上版本，导致shadowsocks2.8.2启动报undefined symbol: EVP_CIPHER_CTX_cleanup错误。
解决https://blog.csdn.net/vbaspdelphi/article/details/72993626