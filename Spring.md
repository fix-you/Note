# Spring

## 简介

轻量级：与 EJB 对比，依赖资源少，销毁资源少。

为了降低 Java 开发的复杂性，Spring 采取了以下关键策略：

+ 基于 POJO 的轻量级和最小侵入性编程
+ 通过依赖注入和面向接口实现松耦合
+ 基于切面和惯例进行声明式编程
+ 通过切面和模板减少样板式代码

分层：一站式，每层都提供解决方案

+ web 层：Struts，spring-MVC
+ service 层：spring
+ dao 层： hibernate，mybatis，jdbcTemplate，spring-data

spring 是一个生产 `bean` 的工厂。

## 核心

+ 控制反转（Inverse of Control，IoC）、依赖注入（dependency injection，DI）

    管理 bean 间的依赖关系

+ 面向切面（aspect-oriented programming，AOP）