<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 liaoyq / ASRT Contributors -->

# PgFile

PgFile 是一款基于命令行的文件传输与远程更新工具。​它采用C/S（客户端/服务端）架构，支持按用户粒度配置独立的上传目录，并提供了完备的命令行管理接口。该工具设计精简，能够无缝集成至自动化脚本、CI/CD 构建流水线及受控运维环境。

项目启动于 2026 年，目前处于早期活跃开发阶段


## 支持平台

PgFile 支持 Windows、Linux 和 macOS，客户端与服务端使用相同的命令行接口和传输协议。

- **Windows**：使用 Visual Studio 工程构建，普通命令行程序运行。
- **Linux**：使用 GNU Make 构建，可作为普通命令运行，也可使用项目提供的 systemd 服务文件部署服务端。
- **macOS**：使用 Xcode 构建，普通命令行程序运行。

PgFile 依赖 AsyncRuntime 和 MinoCrypt，因此构建前需要先为相同目标平台和架构生成这两个依赖库。`pgfile.service` 仅适用于使用 systemd 的 Linux 系统。

## 项目特点

- **统一的命令行工具**：单个 `pgfile` 程序同时提供服务端、文件上传、目录同步、远程清理和权限管理功能。
- **按用户限制上传目录**：每个用户 Key 可配置多个允许目录，这个目录包含子目录,服务端在写入或删除文件前检查目标路径权限。
- **支持文件和目录更新**：既可上传单个文件，也可递归上传目录；目录更新前可按需清理远端目标目录。
- **命令行配置**：无需单独的图形界面或管理程序，可直接添加、删除和查询用户权限，便于自动化管理,也可配合其他管理系统使用。
- **加密传输**：使用 C25519 协商共享密钥，并使用 SM4 加密文件数据,做到一次一密钥。
- **并发服务**：文件传输基于 AsyncRuntime 的 `SocketQueueService`，可并发处理客户端连接。
- **轻量部署**：Linux 下可作为普通命令运行，也提供 systemd 服务文件示例。

## 依赖

PgFile 不是独立库，构建时依赖本仓库中的以下两个项目：

- **AsyncRuntime**：提供网络、并发、文件系统、字符串、日志和运行时基础设施。
- **MinoCrypt**：提供 C25519、SM4、SM3 等密码算法实现。

构建 PgFile 前，应先构建这两个项目，并将头文件和库放到 Makefile 使用的 `Product/include` 与 `Product/<ARCH>` 目录。

## 构建

Linux 下使用 GNU Make 构建：

```bash
cd PgFile
make
```

默认构建 `x86_64` 版本，也可指定 ARM64：

```bash
make ARCH=aarch64
```

生成的 `pgfile` 会被移动到 `../Product/<ARCH>/`。项目同时包含 Visual Studio 工程文件，可用于 Windows 构建。

## 快速使用

### 启动服务端

```bash
pgfile server -p 8100 -a 8101 -f /etc/pgfile.auth
```

- `-p`：文件传输监听端口，默认 `8100`。
- `-a`：管理接口监听端口，默认 `8101`。
- `-f`：权限文件，默认 `auth.txt`。
- `-l`：日志级别，可选 `DEBUG`、`INFO`、`WARN` 或 `ERROR`。

### 上传文件

```bash
pgfile file -s 192.168.1.10:8100 -u <user-key> \
  -f ./package.tar.gz -d /srv/releases/package.tar.gz
```

### 上传目录

上传目录时，远端目标路径必须以 `/` 结尾。工具会先清理远端目标目录，再递归上传本地目录内容。

```bash
pgfile file -s 192.168.1.10:8100 -u <user-key> \
  -f ./dist -d /srv/www/app/
```

### 清理远端路径

```bash
pgfile path -s 192.168.1.10:8100 -u <user-key> -d /srv/www/app/
```

执行远端目录中的 `update.sh`，并实时显示脚本的标准输出和错误输出。脚本可以接收一个可选参数：

```bash
pgfile deploy -s 192.168.1.10:8100 -u <user-key> -d /srv/www/app release
```

目标目录必须在该用户的授权路径内；如果 `update.sh` 不存在，命令会直接报错。

该操作会删除文件，或清空以 `/` 结尾的目录，请谨慎使用。

## 权限管理

管理命令通过管理端口执行。`-s` 可写为 `IP:端口`；未指定端口时默认使用 `8101`。

```bash
# 为用户增加允许目录
pgfile admin -s 192.168.1.10:8101 add <user-key> /srv/releases

# 删除用户的一条目录权限
pgfile admin -s 192.168.1.10:8101 del <user-key> /srv/releases

# 删除用户及其全部权限
pgfile admin -s 192.168.1.10:8101 del <user-key>

# 列出全部用户
pgfile admin -s 192.168.1.10:8101 dis user

# 列出指定用户的允许目录
pgfile admin -s 192.168.1.10:8101 dis <user-key>
```

管理命令可附加 `--json` 获取 JSON 格式结果。权限文件按 `用户Key:允许目录` 逐行保存，一个用户可以有多条记录。

## 安全说明

- 管理接口目前没有独立的管理员身份认证。应当注意,使用主机防火墙限制该端口的访问。
- C25519 与 SM4 用于保护传输数据，但当前协议不等同于经过完整审计的 TLS 协议，也不提供证书式服务端身份验证。不要直接用于不可信公网或高安全等级场景。
- 用户 Key 相当于上传凭据，应通过安全渠道分发并妥善保管，避免写入日志、公开脚本或版本库,同时建议使用较长的随机字符串。
- 服务端进程应使用专用的低权限系统账户运行；允许目录也应遵循最小权限原则。
- `path` 命令及目录上传流程可能删除远端内容，投入生产前应验证允许目录和备份策略。

## 项目结构

```text
PgFile/
├── src/                     # 全部源码与内部头文件
│   ├── main.cpp             # 统一命令行入口
│   ├── PgFileServer.*       # 传输服务与管理接口
│   ├── PgFileClient.*       # 文件、目录和管理命令客户端
│   ├── PgFileAuth.*         # 用户与允许目录管理
│   ├── MapObject.*          # 管理接口响应数据结构
│   └── calc_self.*          # 可执行文件校验与更新辅助逻辑
├── Makefile                 # Linux 构建文件
├── PgFile.vcxproj           # Visual Studio 工程
├── pgfile.service           # systemd 服务示例
├── LICENSE                  # MIT License
└── README.md
```

## 许可证

PgFile 采用 MIT License。AsyncRuntime、MinoCrypt 及其包含的第三方代码可能有各自的许可证要求，发布二进制或源码时应同时保留相应项目中的许可证与第三方声明。
