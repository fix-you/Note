## 学习路线

+ java基本语法

    重点学习与 C++ 有区别的语法

    面向对象（1 类、2 对象、3 封装、继承、多态、4 构造器、5super、this、6 接口、抽象类、7 权限修饰符、8 内部类、9 Random、ArrayList、String、Arrays、Math）

+ API

    + Date
    + DateFormat
    + Calendar
    + System
    + StringBuilde

+ 集合
    + Collection
    +  泛型
    + List
    + Set
    + Collections
    + Map
    + HashMap

+ 异常
    + 异常体系
    + 异常分类
    + 声明抛出捕获异常
    + 自定义异常

+ 多线程
    + 线程概念
    + 线程同步
    + Lock
    + 线程生命周期
    + 线程池

+ Lambda表达式（1 函数式思想概述、2 Lambda标准格式、3 Lambda语法与注意事项）

+ IO流（1 文件、2 字节流、字符流、3 转换流、高效流）

+ 网络编程（1 网络编程三要素、2 Socket原理机制、3 UDP传输、4 TCP传输）

+ 数据库（1 mysql、2 jdbc、3 连接池、4 JdbcTemplate ）

+ xml与（1 xml基本语法、2 约束）

+ jsonp（ 1 jsoup概述、2 jsoup作用使用、3 xpath）

+ Servlet（1 tomcat、2 request、response、3 cookie、session、4 jsp、el、jstl、Filter）

+ maven（1 maven概念与作用、2 idea集成maven、3 maven常用命令、4 依赖管理）

+ spring（1 spring体系结构、2 spring配置、3 bean管理、 4 IOC/DI、AOP、5 事务管理、6 spring5新特性 ）

+ spring mvc（1 springmvc概述、2 控制器、3 常用注解、4 参数绑定、5 json数据交换、6 resutful、7 拦截器、8 文件上传、9 异常处理）

+ mybatis（1 自定义mybatis框架、2 mybatis入门、3 架构分析、4 常用API、5 配置与事务管理、6 mapper代理、7 数据封装、8 动态sql、9 关联查询、10 性能优化、11 查询缓存、12 SSM整合）

+ 拓展（1 Oracle、2 springboot、3、spring data jpa、4 springcloud、5 vue.js 、6 分布式服务、7 中间件 、8 高并发 、9 微服务技术 等等）

## XML

### 概念

### 语法

### 约束模式

## Java

```java
// 数据类型
boolean	byte char double float int long	short

// 变量类型
public class Variable{
	static int a = 0;  // 类变量，独立于方法之外的变量，用 static 修饰。
	String str = "hello world";  // 实例变量，独立于方法之外的变量，不过没有 static 修饰
    public void method() {
    	int tt = 0;  // 局部变量
    }
}
// 上面给出了静态变量，现在看看静态方法。static 关键词用来声明独立于对象的静态方法。静态方法不能使用类的非静态变量。静态方法从参数列表得到数据，然后计算这些数据。

// 修饰符
default(啥也不写)
public private protected

// 基本语法
final double PI = 3.14;  // 常量表示
int[] scores = new int[5];
int[] scores = new int[]{1, 2, 3};  // 此时不能指定长度
int[][] scores = new int[3][];
for (int s : scores) {}
// 可以使用 Arrays 类操作数组
```