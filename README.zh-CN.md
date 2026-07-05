# CipherID

> 面向 CTF 竞赛的一键式密码/编码识别、解码与编码工具 —— 支持 115 种类型，71 种可编码，置信度排名，多层嵌套自动解码，GUI + CLI 双模式。

CipherID 是一款面向 CTF 竞赛的一键式密码与编码识别、解码和编码工具。粘贴任意密文，即可获得按置信度排名的候选结果，也可一键自动解码多层嵌套编码直至匹配 flag 格式。支持 **115 种密码与编码类型**，涵盖 Base 编码、古典密码、哈希算法、JWT、API Token、加密货币地址、奇奇怪怪的编程语言以及中文 CTF 密码。同时提供 **编码/加密** 功能 —— 支持 **71 种算法**按分类（编码类、古典密码、中文密码、现代密码、深奥语言、哈希）浏览，部分算法支持指定密钥。提供多主题 PySide6 GUI（暗色/亮色/蓝色/绿色/Monokai）、无头 CLI、图片输入（二维码/条形码/OCR）以及单文件可执行程序打包。

## 快速开始

### 直接使用预编译的可执行程序（推荐）

去 [Releases](https://github.com/except695-prog/CipherID/releases) 下载最新的 `CipherID.exe` / `CipherID`，双击即可运行。无需安装、无需 Python。

### 从源码运行

```bash
git clone https://github.com/except695-prog/CipherID
cd CipherID
pip install -e ".[dev]"
cipherid-gui            # 启动 GUI
cipherid identify "U2FsdGVkX1+..."   # 或使用命令行
```

要求 Python 3.10+。

## 特性

- **115 种密码 / 编码**：完整清单见 [支持的密码](#支持的密码)
- **71 种可编码算法**：支持 Base*、古典、中文、现代密码的编码 —— `cipherid encode --list-algorithms`
- **置信度排序**：每个候选都带 0–100% 的置信度，由结构匹配 + 统计特征（熵 + 英文卡方）+ 是否能成功解码综合得出
- **一键自动解密**，支持**用户自定义 flag 格式**：`flag{}`、`CTF{}`、`DASCTF{}`、`hkcert{}` 或任意正则
- **嵌套解码**：可自动解开多层套娃（如 base64 套 hex 套 caesar）
- **图片 / 截图输入**：把图片拖进 GUI（或在命令行传图片路径），CipherID 会先用 `pyzbar` 解 QR / Data Matrix / PDF417 / Aztec / 一维条码，解不出再回退到 Tesseract OCR，提取出来的文本立刻喂回正常的 identify / auto-decode 管线
- **拖拽文件 / 图片 / 文本**、**剪贴板粘贴** 快捷键
- **多主题 UI**：基于 PySide6，支持暗色/亮色/蓝色/绿色/Monokai 五款主题
- **单文件可执行**：通过 PyInstaller 输出 Windows / Linux / macOS 单文件
- **命令行版**：`cipherid identify`、`cipherid auto`、`cipherid encode`、`cipherid decode`、`cipherid image`、`cipherid config`、`cipherid backends`，方便接入 CI / 自动化脚本

## 支持的密码

| 类别 | 包含 |
| --- | --- |
| **Base 系编码** | Base16(Hex)、Base32、Base32 Crockford、Base32 Hex、Base45、Base58 (Bitcoin)、Base62、Base64、Base64-URLsafe、Base85 (RFC1924)、Base91、Base100 (Emoji)、Base2048、ASCII85 (Adobe)、ASCII85 (ZeroMQ)、ASCII85 (Z85)、Punycode (IDNA) |
| **其它编码** | URL/百分号编码、HTML 实体、Unicode `\uXXXX`、Quoted-printable (MIME)、UUencode、二进制 (8-bit)、八进制、十进制字节流、A1Z26 字母序号、反转、Whitespace、Hex Dump |
| **符号 / 信号** | 摩斯码、盲文、旗语、敲击码、猪圈密码 |
| **古典替换** | 凯撒/位移（暴力 25 种 + 卡方挑选）、ROT5/13/18/47/52、Atbash、仿射 (a·x + b)、Vigenère、培根、Beaufort、Gronsfeld、Autokey、Playfair、Porta、Hill矩阵、关键词替换 |
| **古典置换** | 栅栏密码、Polybius 5×5、Bifid、Nihilist、Scytale、四方密码、列置换、路线密码 |
| **深奥语言** | Brainfuck（内置解释器）、Ook!、JSFuck、AAencode、JJencode、Malbolge、Befunge、Whitespace（深奥版）、Shakespeare、Chef、Rock、Emojinal、BinaryFuck |
| **哈希 / 摘要** | MD5、MD4、NTLM、LM、SHA-1/224/256/384/512、RIPEMD-160、BLAKE2、CRC32、bcrypt、scrypt、Argon2、Tiger、Keccak/SHA-3、SM3、Unix `$1$/$5$/$6$`、HMAC（计算） |
| **API Token / 协议格式** | JWT（解析并展示 header/payload）、OpenAI `sk-`/`sk-proj-`、Anthropic `sk-ant-`、GitHub PAT / 服务器 / 细粒度、Google `AIza`、AWS `AKIA`、Slack `xox*`、HuggingFace `hf_`、Replicate `r8_`、Stripe `sk_live`/`pk_live`、Discord Webhook URL、GitLab、SendGrid、Heroku、DigitalOcean、Twilio、Bitcoin Legacy/Bech32 地址、Ethereum、Solana、Litecoin、Ripple、Monero、Dash、Dogecoin、NEM、Stellar 地址、PEM 证书/密钥 |
| **现代加密** | AES 块（hex/base64）检测、AES-GCM、RSA 模数/密文、DSA 签名检测、**XOR**（编解码 + 单字节爆破 + 多字节爆破）、**RC4** 流密码、Vigenère autokey（密文/明文变体）、HMAC（计算） |
| **中文 CTF 密码** | 社会主义核心价值观、当铺密码、中文电码、与佛论禅 / 新约佛论禅、QWERTY 键盘密码、五行密码、天干地支、注音符号、仓颉、拼音 |

## GUI 使用流程

1. 在输入框粘贴密文、拖入任意文件，或者直接把 **图片**（QR / 条码 / 截图）丢进来。图片会在后台线程里解码，提取到的文本自动填回输入框
2. （可选）在 Flag 格式输入框里写 `flag{}`、`CTF{}`、`DASCTF{}` 或自定义正则
3. 点击 **识别 Identify** 看候选清单，或点击 **一键解密 Auto-decode** 自动递归解码
4. 在左侧候选表中点任意一条，右侧立即显示解码结果
5. 通过 **复制 Copy** 复制结果，或 **当作新输入 Use as input** 继续手动解码下一层

也可以从菜单 **文件 → 打开图片…**（Ctrl+Shift+O）显式打开图片；如果 QR / OCR 静悄悄无反应，去 **帮助 → 图像后端状态…** 看 `pyzbar` / `pytesseract` / Tesseract 二进制是否都就绪。

Flag 格式支持：

- 模板 `前缀{}`（如 `flag{}`、`CTF{}`、`DASCTF{}`），花括号内会被当作非贪婪通配
- 原生正则（如 `flag\{[A-Za-z0-9_]+\}`）
- 留空时使用内置的"常见 flag 格式"并集，覆盖 `flag{}` / `CTF{}` / `hkcert{}` / `DASCTF{}` / `n1ctf{}` 等

## 命令行

```bash
# 识别（按置信度排序）
cipherid identify "U2FsdGVkX1+..."
cipherid identify "U2FsdGVkX1+..." --flag-format "flag{}" --top 5

# 输出 JSON，方便接脚本
cipherid identify "..." --json

# 递归自动解码
cipherid auto "..." --flag-format "CTF{}" --max-depth 5

# 用指定算法编码明文
cipherid encode "Hello World" -a base64
cipherid encode "flag{test}" -a caesar -k 3
cipherid encode "Hello" -a xor -k secret
cipherid encode --list-algorithms                  # 列出全部 65 种可编码算法
cipherid encode --list-algorithms -c classical     # 按分类筛选

# 用指定算法解码密文
cipherid decode "SGVsbG8=" -a base64
cipherid decode "cixd{qbpq}" -a caesar -k 3

# 直接传图片路径，identify / auto 都支持
cipherid identify ./screenshot.png --flag-format "flag{}"
cipherid auto ./qr.png --flag-format "flag{}"

# 只做图像提取，不跑识别
cipherid image ./qr.png
cipherid image ./scan.jpg --no-ocr           # 只解 QR / 条码，不跑 OCR
cipherid image ./qr.png --json               # JSON 输出

# 查看当前机器上的图像后端可用情况
cipherid backends

# 启动 GUI
cipherid gui
```

### 图片 / QR / 条码 / OCR

`cipherid identify` 和 `cipherid auto` 都可以直接传图片路径。CipherID 会先用 `pyzbar`
逐种尝试解码所有 1D / 2D 条码（QR Code、Data Matrix、PDF417、Aztec、EAN、Code 128 ……）；
没解出来再回退到 Tesseract OCR（除非 `--no-ocr`）。提取出来的文本会立刻喂回正常的识别管线，
因此"截图里的 base64 的 flag"这种组合一条命令就能解到底。

可选后端：

- `pyzbar` + `libzbar` 共享库 —— QR / 条码必备
- `pytesseract` + Tesseract 二进制 —— OCR 必备。Windows 推荐 UB-Mannheim 的构建，
  并确保 `tesseract.exe` 在 `PATH` 上

运行 `cipherid backends` 查看当前机器上的后端就绪情况。

## 项目结构

```
CipherID/
├── pyproject.toml              # 构建配置、依赖、入口点
├── README.md                   # 英文说明
├── README.zh-CN.md             # 中文说明（本文件）
├── LICENSE                     # MIT
├── CHANGELOG.md                # 版本历史
├── .github/
│   └── workflows/
│       ├── ci.yml              # Linux/Win/macOS × Python 3.10–3.12 测试与 lint
│       └── release.yml         # tag 触发：自动构建三平台 exe 并发 GitHub Release
├── build_scripts/
│   ├── cipherid.spec           # PyInstaller spec（单文件、windowed）
│   └── build_exe.py            # 一键打包脚本
├── docs/
│   └── adding_a_cipher.md      # 如何贡献新检测器
├── tests/
│   ├── __init__.py
│   ├── test_engine.py          # 识别 + 自动解码 + flag 提取 端到端测试
│   └── test_image.py           # QR 往返 + 图片 → 引擎管线
└── src/
    └── cipherid/
        ├── __init__.py         # 对外 API
        ├── cli.py              # 命令行（identify / auto / encode / decode / image / backends / gui）
        ├── cipher.py           # Cipher 基类 + Candidate / DecodeResult
        ├── engine.py           # 识别引擎 + 自动解码 + encode_one/decode_one + 嵌套解开
        ├── config.py           # 配置文件处理（cipherid.json）
        ├── flag.py             # Flag 格式编译器（模板 OR 正则）
        ├── heuristics.py       # 熵 + 英文卡方 + 语言判断
        ├── image.py            # QR / 条码（pyzbar）+ OCR（Tesseract）提取
        ├── plugins.py          # 插件系统，加载自定义密码器
        ├── ciphers/
        │   ├── __init__.py     # load_ciphers() 注册表
        │   ├── encodings.py    # Base* / URL / HTML / Morse / UU / binary / hex / Braille / Semaphore…
        │   ├── classical.py    # Caesar / ROT / Atbash / Affine / Vigenère / Bacon / Polybius / Playfair / …
        │   ├── esoteric.py     # Brainfuck / Ook! / JSFuck / AAencode / JJencode / Malbolge / …
        │   ├── hashes.py       # MD5 / SHA* / NTLM / bcrypt / Argon2 / scrypt / Tiger / Keccak / SM3 / CRC32 识别 + 哈希计算
        │   ├── tokens.py       # JWT、OpenAI/Anthropic/AWS/GitHub/Stripe Token、PEM、BTC、ETH、SOL…
        │   ├── modern.py       # AES/GCM/RSA 检测、XOR、RC4、HMAC、Vigenère autokey
        │   └── chinese.py      # 核心价值观 / 当铺密码 / 与佛论禅 / 中文电码 / 键盘 / 五行 / 仓颉 / 拼音
        └── gui/
            ├── __init__.py
            ├── app.py          # 主窗口 + 后台识别 / 自动解码 / 图像提取 worker
            └── theme.py        # 暗色 / 亮色 / 蓝色 / 绿色 / Monokai QSS 主题
```

### 各模块职责

| 文件 | 作用 |
| --- | --- |
| `src/cipherid/cipher.py` | 定义抽象基类 `Cipher` 与 `Candidate`、`DecodeResult` 数据类。所有检测器/编码器都是 `Cipher` 的子类，实现 `identify()`（必要）、`decode()`（可选）和 `encode()`（可选）。 |
| `src/cipherid/engine.py` | 核心引擎 `Engine`。`identify()` 跑所有规则、按置信度排序返回；`auto_decode()` 贪心递归解开嵌套密码；`encode_one()` / `decode_one()` 用于指定算法的编解码操作。 |
| `src/cipherid/flag.py` | 解析用户输入的 flag 格式。支持 `前缀{}` 模板写法、原生正则、空（用内置常见 flag 格式并集）。 |
| `src/cipherid/heuristics.py` | 通用统计原语——Shannon 熵、英文字母频率卡方、UTF-8/CJK 合理性判定、可打印率检查。供各检测器评分使用。 |
| `src/cipherid/image.py` | 图像预处理——用 `pyzbar` 解 QR / 条码，用 `pytesseract` + Tesseract 跑 OCR。所有后端都可选，`backend_status()` 报告哪个已就绪。 |
| `src/cipherid/config.py` | 配置文件处理——加载/保存 `cipherid.json`，支持自定义阈值、禁用密码器、flag 预设。 |
| `src/cipherid/plugins.py` | 插件系统——从 `~/.cipherid/plugins/` 或 `./cipherid_plugins/` 加载自定义 `Cipher` 子类。 |
| `src/cipherid/ciphers/` | 按类别分文件，每个文件导出一个 `Cipher` 实例列表；`ciphers/__init__.py` 把它们汇总成总注册表。 |
| `src/cipherid/gui/app.py` | PySide6 主窗口。识别 / 自动解码 / 图像提取放在后台 `QThread` 里跑，UI 不卡。支持拖拽（文本 / 文件 / 图片）、剪贴板粘贴、文件打开、图片打开、复制、手动链式解码。 |
| `src/cipherid/gui/theme.py` | 手工调色的多款 QSS 主题（暗色/亮色/蓝色/绿色/Monokai）。 |
| `src/cipherid/cli.py` | 基于 Click 的命令行，子命令：`identify`、`auto`、`encode`、`decode`、`image`、`backends`、`gui`、`config`。 |

## 自动解码工作原理

`Engine.auto_decode()` 是一个贪心搜索：

1. 当前文本喂给全部检测器
2. 对每个能成功 decode 的候选，计算分数 = `置信度 + 1.0·命中flag加成 + 0.2·语言合理性加成`
3. 选分数最高的解码结果，递归继续
4. 命中 flag 模式 / 已经是普通英文中文 / 不能再继续解码 / 达到 `max_depth` 时停止

这种简单策略已经能覆盖 95% 的嵌套 CTF 题（base64 套 hex 套 rot13 之类）。极端情况下用 **识别 Identify** 多次 + **当作新输入 Use as input** 按钮手工接力。

## 打包成可执行文件

```bash
pip install -e ".[dev]"
python build_scripts/build_exe.py
# -> dist/CipherID.exe (Windows) 或 dist/CipherID (Linux/macOS)
```

单文件，目标机器无需 Python。

## 运行测试

```bash
pytest -q
ruff check src tests
```

## 新增一种密码

1. 在合适的 `src/cipherid/ciphers/*.py` 里继承 `Cipher` 写一个子类
2. 实现 `identify(text) -> list[Candidate]`，需要的话再实现 `decode(text, key=None) -> str | None` 和 `encode(text, key=None) -> str | None`
3. 把实例追加到本文件的导出列表（如 `ENCODING_CIPHERS`）
4. 在 `tests/test_engine.py` 加一条正向测试

基类极小，看 `cipher.py` 和任意现有检测器就能照葫芦画瓢。

## 贡献

欢迎 PR——新密码、更准的置信度、更好的 GUI、新 flag 格式都行。改动较大的话建议先开 Issue 聊一下。

## 许可证

MIT
