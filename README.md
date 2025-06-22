# MPwn: Environment Configuration Tool for Pwn

**仅支持Python3(3.10.x or higher)**

## 0x1 安装（Setup）

只需一行命令：

```bash
./setup.sh
```

此脚本会安装必要依赖项，并自动创建默认目录结构。

---

## 0x2 使用说明（Usage）

MPwn 目前支持以下三种调用方式：

### 1. `mpwn <executable>`

自动匹配当前二进制所依赖的 libc 版本并附加调试：

```bash
mpwn <executable>
```

---

### 2. `mpwn --fetch`

列出所有可用libc版本：

```bash
mpwn --fetch
```

功能：

* 列出支持的 `glibc` 版本和架构
* 从清华镜像源下载对应版本的 `libc6` 和 `libc6-dbg`
* 自动提取至 `~/.config/mpwn/list` 文件下

---

### 3. `mpwn --fetch-all`

批量下载所有可识别的 glibc 版本：

```bash
mpwn --fetch-all
```

---

## 0x3 目录结构（默认）

```bash
~/.local/mpwn_libs/
├── debs/          # 下载的 deb 包存放处
└── libs/          # 提取的 libc 版本目录
    ├── 2.31-0ubuntu9.9_amd64/
    ├── 2.27-3ubuntu1_i386/
    └── ...
```

```bash
~/.config/mpwn/
.
├── config.json # 配置文件
├── list # fetch获得的libc版本
└── template.py # 模板
```
---
