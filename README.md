# DNS Relay Server

这是一个计算机网络课程设计项目，实现本地 DNS 中继服务器。程序既可以根据本地域名表直接返回结果，也可以在本地未命中时转发到上游 DNS，并通过 ID 映射把响应返回给原客户端。

## 已实现功能

- 接收并解析 UDP DNS 查询报文
- 本地域名-IP 映射表查询
- `0.0.0.0` 拦截域名，返回 NXDOMAIN
- 本地命中时构造 A 记录响应
- 本地未命中时转发到上游 DNS
- 复用主 socket 转发上游请求和接收上游响应
- DNS ID 映射，支持多个客户端并发查询
- `select()` 事件循环，避免忙等待
- 上游响应超时清理
- A 记录缓存，按 TTL 过期
- 模块化代码结构和封装日志输出

## 目录结构

```text
include/      头文件
src/          源文件
data/         本地域名-IP表
CMakeLists.txt
README.md
```

主要模块：

- `dns.c`：DNS 查询解析、响应构造、上游 A 记录提取
- `table.c`：本地域名-IP 映射表
- `relay.c`：上游 DNS 转发和响应回送
- `idmap.c`：DNS ID 映射和超时清理
- `cache.c`：A 记录缓存
- `config.c`：命令行配置
- `netutil.c`：socket、select、时间工具
- `logger.c`：日志输出

## 编译

```powershell
cmake -S . -B build
cmake --build build --config Debug
```

默认可执行文件输出在 `build/` 目录：

```text
build/Main.exe
build/Client.exe
```

## 运行

默认监听 UDP 53 端口：

```powershell
.\build\Main.exe
```

Windows 下监听 53 端口通常需要管理员权限。如果不想使用管理员权限，可以改用 5353：

```powershell
.\build\Main.exe --port 5353
```

命令行参数：

```text
-p, --port <port>           监听端口，默认 53
-u, --upstream <ip>         上游 DNS，默认 8.8.8.8
-t, --table <file>          本地域名表，默认 data/dnsrelay.txt
    --event-timeout <ms>    select 唤醒间隔，默认 1000
    --id-timeout <ms>       上游响应超时，默认 5000
```

示例：

```powershell
.\build\Main.exe --port 5353 --upstream 8.8.8.8 --table data\dnsrelay.txt
```

## 本地域名表格式

文件默认路径：

```text
data/dnsrelay.txt
```

支持两种格式：

```text
1.2.3.4 test.example.com
test2.example.com 5.6.7.8
0.0.0.0 ads.example.com
```

其中：

- 普通 IP 表示本地命中后直接返回该 A 记录
- `0.0.0.0` 表示拦截，服务器返回 NXDOMAIN
- `#` 开头的行会被忽略

## 测试

监听 53 端口时：

```powershell
nslookup www.baidu.com 127.0.0.1
```

监听 5353 端口时：

```powershell
nslookup -port=5353 www.baidu.com 127.0.0.1
```

本地表命中测试：

```text
1.2.3.4 test.example.com
0.0.0.0 ads.example.com
```

```powershell
nslookup -port=5353 test.example.com 127.0.0.1
nslookup -port=5353 ads.example.com 127.0.0.1
```

也可以使用项目自带客户端，输出中文提示：

```powershell
.\build\Client.exe www.baidu.com 127.0.0.1 5353
.\build\Client.exe test.example.com 127.0.0.1 5353
.\build\Client.exe ads.example.com 127.0.0.1 5353
```

客户端参数：

```text
Client.exe <domain> [dns_server] [dns_port]
```

如果省略 DNS 服务器和端口，默认使用：

```text
127.0.0.1:53
```

## 当前支持范围

- 主要支持 IPv4 A 记录
- 缓存只保存上游响应中的第一个 A 记录
- 不缓存 NXDOMAIN、AAAA、CNAME 链和 SERVFAIL
- 上游超时后只清理 ID 映射，不主动给客户端返回 SERVFAIL
- 本地拦截当前返回 NXDOMAIN

这些限制不影响基本 DNS Relay 课程设计流程，但如果需要更完整 DNS 行为，可以继续扩展。
