# Code breaking WP

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
chdir(DATA_DIR);

$domain = isset($_POST['domain']) ? $_POST['domain'] : '';
$log_name = isset($_POST['log']) ? $_POST['log'] : date('-Y-m-d');
?>
<!doctype html>
<html lang="en">
<head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/css/bootstrap.min.css" integrity="sha256-eSi1q2PG6J7g7ib17yAaWMcrr5GrtohYChqibrV7PBE=" crossorigin="anonymous">

    <title>Domain Detail</title>
    <style>
    pre {
        width: 100%;
        background-color: #f6f8fa;
        border-radius: 3px;
        font-size: 85%;
        line-height: 1.45;
        overflow: auto;
        padding: 16px;
        border: 1px solid #ced4da;
    }
    </style>
</head>
<body>

<div class="container">
    <div class="row">
        <div class="col">
            <form method="post">
                <div class="input-group mt-3">
                    <div class="input-group-prepend">
                        <span class="input-group-text" id="basic-addon1">dig -t A -q</span>
                    </div>
                    <input type="text" name="domain" class="form-control" placeholder="Your domain">
                    <div class="input-group-append">
                        <button class="btn btn-outline-secondary" type="submit">执行</button>
                    </div>
                </div>
            </form>
        </div>
    
    </div>

    <div class="row">
        <div class="col">
            <pre class="mt-3"><?php if(!empty($_POST) && $domain):
                $command = sprintf("dig -t A -q %s", escapeshellarg($domain));
                $output = shell_exec($command);

                $output = htmlspecialchars($output, ENT_HTML401 | ENT_QUOTES);

                $log_name = $_SERVER['SERVER_NAME'] . $log_name;
                if(!in_array(pathinfo($log_name, PATHINFO_EXTENSION), ['php', 'php3', 'php4', 'php5', 'phtml', 'pht'], true)) {
                    file_put_contents($log_name, $output);
                }

                echo $output;
            endif; ?></pre>
        </div>
    </div>

</div>

</body>
</html> 1
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