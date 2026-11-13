# Hodor 设计文档

> **Hodor — Hold the door between your AI agent and your secrets.**
> 密钥托管守卫:agent 只见别名,不见密钥。

| | |
|---|---|
| 状态 | v2 草案,待项目所有者评审通过后开工 |
| 语言 | Rust(单二进制 + 独立 root helper) |
| 平台 | Linux 优先,macOS / Windows 同步支持 |
| 许可 | Apache-2.0 |
| 命名 | repo `<user>/hodor`;crate `hodor-cli`(或收回 `hodor`);命令/包名一律 `hodor` |

**v2 修订**:guard 模型由"磁盘脱敏(只存别名)"反转为**"读取时代理"(磁盘保留真实密钥,FS 层在读取瞬间替换)**,以保障代码不经 hodor 也能正确执行;新增 VSCode 插件(R23)、README 双语切换(R24)、工程规范章节;CLI 新增 guard 一键替换/显现转换。

---

## 1. 项目定位

Hodor 是一个 **CLI-first 的 AI agent 凭证托管平台(broker)**。它替 agent 保管一切"需要用、但不应该看见"的东西——sudo 密码、SSH 凭证、API key、token——并代为执行需要这些凭证的操作。

核心口号即全部设计哲学:**Hodor 守住那扇门**。agent 的世界里只有别名(alias)和执行结果;真实密钥只存在于 Hodor 进程的内存和用户的指纹/口令之后。

### 非目标(明确不做的事)

- 不做自绘 GUI 应用(交互 = 原生弹窗/pinentry + CLI;可视化管理交给 VSCode 插件,见 §5.12)
- 不做面向人类的通用密码管理器(那是 Bitwarden 的领域)
- 不做多人/团队密钥分发(单机单用户,sidecar 可进 git 但解锁权在个人)
- 不做 webview 类组件(webview 本身是威胁模型里最不信任的东西)

---

## 2. 需求总清单(R1–R24)

> 本清单是全部讨论的累积记录,编号在后续开发中作为需求追踪 ID 使用。

### 2.1 核心不变量

| ID | 需求 |
|---|---|
| R1 | 密钥(密码/密钥/凭证)永远不出现在 agent 上下文:工具结果、stdout、文件内容,一切渠道 |
| R2 | 工具接口只有"使用密钥做 X",不存在任何"读取/解密密钥"操作 |
| R3 | 人工批准 = 带外原生弹窗 + 主口令或指纹;审批与确切命令哈希绑定;反钓鱼短语;连续输错冷却 |

### 2.2 加密与存储

| ID | 需求 |
|---|---|
| R4 | 保险库:Argon2id + XChaCha20-Poly1305;密钥仅驻内存(mlock + zeroize);反钓鱼短语、askpass 路径、策略全部入库 |
| R5 | 通用 object 托管:sudo 密码 / SSH 凭证 / API key / token,统一以 alias 引用 |
| R6 | 每 object 细粒度策略:允许的 agent、确认模式、允许用途、TTL / 次数 / 到期日 |
| R7 | 审计日志 append-only 哈希链,链头入 vault,篡改可检测 |
| R8 | 所有可变安全数据(策略/审计/入档记录)一律存加密库,agent 无法篡改 |

### 2.3 sudo 通道

| ID | 需求 |
|---|---|
| R9 | root supervisor 模式:密码单次经管道,之后特权命令由常驻 root 进程代为执行 |
| R10 | 三档授权:仅此一次 / 本任务(TTL,绑定 session)/ 命令白名单(逐字哈希匹配) |
| R11 | 可选 sudoers NOPASSWD 变体(仅限签名的 hodor-supervisor 二进制) |
| R12 | sudo 命令黑名单:防 agent 借 sudo 改密码、改 sudoers、读 shadow、攻击 hodor 自身 |

### 2.4 密钥使用与防外流

| ID | 需求 |
|---|---|
| R13 | 模板注入:命令中 `{{alias}}` 由 broker 在 execve 前替换,直接构造 argv,不经 shell |
| R14 | 输出清洗:返回结果中任何形式的密钥文本(明文/base64/hex/URL 编码)替换回 alias;不可分析输出默认扣留 |
| R15 | **读取时代理**:磁盘文件保留真实密钥(代码不经 hodor 也能正确执行);文件虚拟化层(FUSE/ProjFS)在**一切读取发生的瞬间**对不可信进程做 key→alias 替换——agent 用任何工具(原生 Read、cat、编辑器)读取均被代理 |
| R16 | **同步写拦截**:agent 写入经 FS 层同步检查,密钥流入文件即弹窗告知具体文件,用户决定;可配置每次询问/默认允许;"哪个 key 流入哪个文件"加密入档 |
| R17 | **存量登记与一键转换**:key ↔ 文件 ↔ alias 映射存加密 sidecar(`.hodor-guard`,git 可提交);CLI 一键 替换视图/真实视图 转换(`guard on/off`),支持脱敏导出(`export --redacted`),方便测试与发布 |
| R22 | 允许用途细分:命令执行 / HTTP 头注入 / SSH 认证,按 object 逐项配置 |

### 2.5 生态与分发

| ID | 需求 |
|---|---|
| R18 | 指纹解锁:macOS Touch ID / Windows Hello 密码学级;Linux fprintd+TPM 尽力级;口令兜底 |
| R19 | MCP 五工具 + skill 自动安装(agent 注册表扫描,支持本地与远程) |
| R20 | SSH 反向通道转发:配置只在本地,服务器零配置,批准/指纹在本地弹 |
| R21 | CLI-first、中英双语(Fluent)、跨三平台、开源并上架 brew / apt / winget |
| R23 | **VSCode 插件**:自动/引导安装 hodor;可视化管理 object、guard 保护文件、策略与审计;批准操作仍走带外 pinentry(插件只做展示与配置,不做批准,防 agent 操纵 IDE 界面) |
| R24 | **README 中英双语**:README.md(英文)与 README.zh-CN.md(中文)顶部互链切换,内容严格对齐 |

### 2.6 工程规范(详见 AGENTS.md)

- 代码简洁清晰,避免冗余函数嵌套(guard clause / 早返回,控制流保持扁平)
- 高内聚低耦合:crate 边界即依赖方向图(§6),只允许向下依赖
- 复用优先:禁止复制粘贴逻辑,公共能力一律下沉到 core / 纯函数库
- **注释一律英文**,只写代码本身表达不了的约束,不写叙事
- rustfmt + clippy(`-D warnings`)强制通过;面向用户的文本必须走 Fluent,禁止硬编码

---

## 3. 信任模型与三大闸门

**Agent 被视为不可信**(LLM 上下文可能被提示词注入、会被模型服务商接收;agent 进程可能以当前用户身份执行任意代码)。在此前提下:

| 闸门 | 位置 | 机制 |
|---|---|---|
| 输入端 | 密钥进入命令的瞬间 | 模板注入:密钥只在 execve 构造 argv 的最后一刻出现,不经 shell |
| 输出端 | 结果返回 agent 的瞬间 | 全库扫描清洗:所有密钥 × 四种编码形态,Aho-Corasick 流式匹配 |
| 静态端 | **文件被读取的瞬间** | 读取时代理:磁盘保留真实密钥,FS 虚拟化层对不可信进程返回别名视图 |

核心不变量的数学基础:**保险库密钥只从人类手指产生**(口令经 Argon2id 推导,或硬件封装的生物识别验证)。agent 读文件、破解、替换 hodor 二进制,都"变不出"密钥。

---

## 4. 总体架构

```
                ┌──────────────────── hodor daemon (Rust, 用户态) ────────────────────┐
                │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌─────────────┐        │
agent ──MCP──▶  │  │策略引擎 │ │黑名单   │ │模板注入 │ │输出清洗 │ │文件守护层    │        │
(五工具,       │  │R6/R22  │ │R12     │ │R13     │ │R14     │ │R15–R17     │        │
 无读密钥操作)  │  └───┬────┘ └───┬────┘ └────────┘ └────────┘ └──────┬──────┘        │
                │      └──┬───────┴─────────────▶ 弹窗/指纹 ◀─────────┘              │
                │  ┌──────┴─────────────────────────────────────┐                    │
                │  │ 加密 vault:objects + 策略 + 审计链 + guard │                    │
                │  └────────────────────────────────────────────┘                    │
                └───────┬──────────────────┬────────────────┬────────────────────────┘
                 root supervisor       FS 虚拟化层         SSH 反向通道
                 (R9–R12 sudo)     (FUSE/ProjFS,R15–R17)  (R20 远程)
```

**单二进制原则**:`hodor` 一个二进制承载全部用户态子命令,daemon 按需自动拉起;第二二进制是 `hodor-supervisor`(root 执行,放 `/usr/lib/hodor/`)。

---

## 5. 关键机制设计

### 5.1 保险库与加密(R4/R8)

- 格式:单文件加密 blob(版本头 + Argon2id 参数 + 盐 + XChaCha20-Poly1305 密文 + tag),AEAD 自带防篡改。
- 主密钥(DEK,256 位随机)两条封装路径:**口令路径**(Argon2id(passphrase) 推导 KEK 包裹 DEK)与**硬件路径**(macOS Keychain `kSecAccessControlBiometryCurrentSet` / Windows Hello CNG 密钥 / Linux TPM2 seal + fprintd 手势)。
- 解锁后 DEK 常驻内存:`mlock()` 锁页 + `zeroize` 清零,默认 15 分钟空闲自动上锁。
- 库内数据:`objects[]`(值+策略)、策略、反钓鱼短语、askpass 路径、审计链头、guard 档案索引。

### 5.2 解锁与指纹(R18/R3)

- 三平台:macOS Touch ID / Windows Hello 为密码学级(DEK 被硬件封装);Linux fprintd 只提供"是/否",组合 TPM2 尽力级,文档如实标注弱于口令。
- 口令永远兜底;主口令 ≠ sudo 密码 ≠ 登录密码(安装时强制提示)。
- 弹窗三级回退:① 图形桌面 → pinentry 图形版 / 原生对话框(Windows 用官方 CredUI);② 纯终端 → `pinentry-curses` 在**用户本人**的控制终端全屏绘制;③ 无终端 → 桌面通知 + `hodor approve <id>`。
- 反钓鱼短语:init 时由用户设定、存加密库,每个合法弹窗必显示;输错 5 次冷却 5 分钟。

### 5.3 root supervisor 与 sudo 三档授权(R9–R11)

```
解锁后的 daemon 执行一次: sudo -S /usr/lib/hodor/hodor-supervisor
  (密码经管道喂入后管道立即关闭;或走 R11 sudoers 白名单免密)
    └─ 常驻 root 进程,只接受 daemon 经 unix socket 发来的:
       { exec: argv[], hash: H, session: S }
       ├─ 校验 hash 与已批准命令一致 → fork + exec → 流回 stdout/stderr/exit
       └─ 不一致 → 拒绝并记审计
```

| 档位 | 行为 | 回收 |
|---|---|---|
| 仅此一次(默认) | 命令结束立即重新上锁 | 自动 |
| 本任务 | 绑定 MCP session ID,TTL 默认 15 分钟 | agent 断开 / TTL 到期 → 终止 supervisor + `sudo -k` + zeroize |
| 白名单 | 逐字哈希匹配的命令永久免弹窗 | 策略存加密库,改动需解锁 |

### 5.4 命令策略引擎与黑名单(R12)

评估顺序固定,前者一票否决:

```
请求 → ① 硬黑名单(编译进二进制,不可覆盖)
     → ② 用户黑名单(加密存 vault)
     → ③ 白名单(逐字哈希)命中 → 免弹窗执行
     → 都不命中 → 弹窗询问(用户指纹/口令确认)
```

硬黑名单分类:

| 攻击目的 | 拦截对象 |
|---|---|
| 重置/改 sudo 密码 | `passwd`(任何参数)、`chage`、`chpasswd` |
| 篡改提权体系 | `visudo`、写 `/etc/sudoers*` `/etc/pam.d/*`、`usermod -aG sudo`、`useradd/userdel` |
| 离线窃取口令 | 读 `/etc/shadow`、`/var/lib/fprint` |
| 攻击 hodor 自身 | kill/替换/ptrace hodor 与 supervisor、写 `~/.hodor/**` 及二进制路径 |
| 提权跳板 | 嵌套 `sudo`、`su`、`pkexec`、`nsenter`、`unshare --map-root-user` |

解析硬化:argv 逐元素处理(默认不经 shell)、二进制路径 `realpath` 规范化、`env`/`xargs`/解释器内联代码(`python -c` 等)强制弹窗展示完整字符串。黑名单是最后一层纵深,承重的门仍是逐条人工确认。

### 5.5 模板注入(R13)

```
agent: hodor_request_run("curl -s -H 'Authorization: Bearer {{openai}}' https://api.example.com/v1/models")
   → daemon 解析模板,记下涉及的密钥集合
   → 解析后的 argv 直接 execve(不经 shell,无 $() 、无重定向解释)
   → agent 原文里只有 {{openai}}
```

### 5.6 输出清洗引擎(R14)

```
① 执行前:登记本命令密钥集合;加载全库密钥(长度 ≥ 8)
② 子进程输出经 daemon 管道缓冲(不直接透传给 agent)
③ Aho-Corasick 多模式匹配,分块流式 + 重叠窗口,同时匹配:
     明文 / base64 / hex / URL 编码
④ 命中 → 替换为 {{alias}};未命中 → 原样放行
⑤ 持有过密钥的命令产出二进制/高熵输出 → 整段扣留,返回
   "output withheld: potential secret leak (见 hodor audit)"
```

扫描范围覆盖**全部**密钥而非仅本命令用到的——堵住"注入环境变量后 `cat /proc/<pid>/environ` 读回"这类旁路。不可分析输出默认扣留,按 object 策略可放宽。

### 5.7 文件守护层:读取时代理模型(R15–R17)

**原则(v2 修订)**:磁盘上的项目文件**保留真实密钥**——代码、应用、构建不经 hodor 也能正确执行;防护发生在**读取发生的瞬间**,由文件虚拟化层完成 key→alias 的最终替换。agent 无论用原生 Read 工具、`cat`、还是其他任何程序读取,都经过代理。

```
                    项目目录 ~/code/myapp(挂载点)
   ┌────────────────── hodor-fs 虚拟化层(FUSE / macFUSE / ProjFS)──────────────────┐
   │  open()/read() 到来 → 查询打开进程归属:                                        │
   │    · 不可信进程树(daemon 登记的 agent 运行时及其后代)→ 返回别名视图            │
   │      (.env 内容: OPENAI_API_KEY={{openai}})                                  │
   │    · 其余进程(用户终端、IDE、应用/测试本身)→ 返回真实视图                     │
   │  write() 到来(不可信进程)→ 同步扫描写入内容:                                  │
   │    · 含密钥 → 阻塞该写操作,弹窗决策(允许/拒绝,入档加密)                       │
   └────────────────────────────────────────────────────────────────────────────┘
                     ↓ 底层                            ↑ 真实视图
        真实文件树(daemon 经 bind mount/预打开 FD 持有,
        挂载层覆盖原路径,unmount/bind mount 需特权,agent 无法绕过)
```

关键机制:

- **进程视图决策**:daemon 通过 MCP 连接掌握 agent 运行时的进程树;后代进程 → 别名视图,其余 → 真实视图。agent 无法通过"换一个程序读"绕过——它启动的任何程序都是它进程树的后代。
- **真实文件的可达性**:挂载层覆盖原路径后,原始内容只能经 daemon 持有的 bind mount/文件描述符访问;agent 无特权无法 unmount、无法自行 bind mount。
- **同步写拦截(v2 升级)**:写入在 FS 层 `write()` 时同步检查,密钥流入文件即刻拦截弹窗——原 v1 设计的秒级窗口归零。"允许"= 登记映射(加密入档)后放行写入真实树;"拒绝"= 写入内容中的密钥替换为别名后放行。两种结果下 agent 后续读到的都是别名。
- **存量登记**:`hodor guard add .env --key OPENAI_API_KEY --alias openai` 建立 key↔文件↔alias 映射,存 `.hodor-guard` 加密 sidecar(密文 blob,可安全提交 git;哈希链入中央审计,删改可检测)。
- **一键转换(测试与发布)**:
  - `hodor guard on / off / status` —— 挂载/卸载虚拟化层,一键在"受保护视图"与"全真实视图"间切换;`off` 需用户弹窗确认,防 agent 自行关闭;
  - `hodor export --redacted <path>` —— 输出全量别名替换后的脱敏副本(目录/单文件),用于对外分享、开源发布、打包 CI。

**平台实现**:Linux 用 FUSE(`fuser` crate,成熟);macOS 用 macFUSE(kext)或 NFS loopback 挂载(免 kext 的替代方案,安装时探测择优);Windows 用 ProjFS。三平台能力差异如实写入文档。

**诚实边界**:`guard on` 激活前的窗口内文件可被直读(对策:IDE 插件/守护进程检测到 agent 会话打开项目时自动 `guard on` 并通知);agent 通过 IPC 请求受信进程(如用户已开的编辑器)代读属于已知边界,记入威胁模型。

### 5.8 审计哈希链(R7)

每条记录 `hash_n = SHA256(entry_n ‖ hash_{n-1})`,链头存 vault;`hodor audit --verify` 校验链条,断链即报告;整文件删除在下次解锁时通过链头比对发现。记录内容:请求/策略变更/解锁/批准/拒绝/扣留/隔离/guard 开关,每条含 session、时间、命令哈希、决策来源。

### 5.9 MCP 工具面与 skill 分发(R19/R2)

Agent 侧仅五个工具,**没有任何一个能返回密钥本体**:

| 工具 | 作用 |
|---|---|
| `hodor_request_run(template, reason)` | 提交含 `{{alias}}` 的命令,返回 request_id |
| `hodor_request_http(method, url, headers, body)` | daemon 注入 Authorization 头执行 HTTP |
| `hodor_request_ssh(alias, command)` | 经 daemon 的 ssh 凭证远程执行 |
| `hodor_status()` | 库状态、待审批请求 |
| `hodor_get_output(request_id)` | 取执行结果(已经 R14 清洗) |

skill 分发:内置 agent 注册表(名 → skill 目录 + MCP 配置方式),`hodor agent install --all` 扫描发现、询问、写入:① skill 包(SKILL.md,中英,含"永远用别名引用密钥,你无法也无需看到密钥本身"的红线说明);② MCP 注册(stdio 拉起 `hodor mcp serve`)。`--remote user@host` 走 SSH 投放。

### 5.10 SSH 反向转发(R20)

```
笔记本(vault+指纹)                      服务器(仅瘦客户端 hodor)
┌───────────────┐    SSH 加密通道       ┌──────────────────┐
│ hodor daemon   │◀── RemoteForward ──▶ │ /tmp/hodor.sock  │
│ 弹窗/指纹在本地│  (ssh_config 一行)    │ 服务器 agent → MCP │
└───────────────┘                      └──────────────────┘
```

`hodor forward setup prod-1` 自动写入 `~/.ssh/config` 的 `RemoteForward`;服务器零密钥零配置,批准与指纹全部发生在笔记本;服务器端执行时凭证仅短暂存在于瘦客户端内存(批准期间、单次使用),文档明示:服务器本身被入侵则无法保护在其上使用的凭证。

### 5.11 国际化(R21)

Mozilla Fluent(`fluent-rust`),`en-US.flt` / `zh-CN.flt` 两套消息文件;`hodor config lang zh|en`,默认跟随 `$LANG`。CLI 帮助、弹窗、错误信息、skill 文档全覆盖。**README 双语结构(R24)**:`README.md`(英文)+ `README.zh-CN.md`(中文),两文件顶部放置切换链接(`[English](README.md) | [中文](README.zh-CN.md)`),内容严格对齐,由 CI 校验段落一致性。

### 5.12 VSCode 插件(R23,远期 M7)

- **安装引导**:插件检测 `hodor` 是否可用,不可用则一键安装(调用官方渠道 brew/apt/winget 或下载 GitHub Release),并引导 `hodor init` 与 `hodor agent install --all`。
- **可视化管理**(连接本地 daemon 的 unix socket):
  - object 列表:别名、类型、策略、使用状态(值本身**不显示**);
  - guard 保护文件:受保护文件、映射、视图状态(保护中/未启用),`guard on/off` 按钮;
  - 待审批请求与审计流:实时查看,支持跳转命令详情;
  - 状态栏:锁定/解锁、激活授权的 TTL 倒计时。
- **红线**:插件只做展示与配置,**批准/解锁操作一律走带外 pinentry 弹窗**——因为 agent 可能与插件同处一个 IDE 进程环境,插件界面不能成为批准通道。
- 技术栈:TypeScript,与 daemon 通信复用 `hodor-proto` 的消息定义(经 schema 生成)。

---

## 6. 代码布局

```
hodor/                                # GitHub: <user>/hodor
├── Cargo.toml                        # [workspace] resolver=2
├── crates/
│   ├── hodor-core/                   # 🔐 加密与数据模型(零网络、零进程启动,可独立审计)
│   │   ├── crypto.rs                 #   Argon2id、XChaCha20-Poly1305、mlock/zeroize 封装
│   │   ├── vault.rs                  #   保险库读写、封解包、版本迁移
│   │   ├── object.rs                 #   object 模型 + 策略结构
│   │   ├── biometric/                #   macos.rs(LAContext)/ windows.rs(Hello)/ linux.rs(fprintd+TPM)
│   │   └── audit.rs                  #   哈希链追加与校验
│   ├── hodor-scrub/                  # 🧹 输出清洗引擎(纯函数库,无 IO,最适合先行单测)
│   │   ├── patterns.rs               #   密钥→四形态(明文/base64/hex/URL)候选生成
│   │   ├── scanner.rs                #   Aho-Corasick 流式分块扫描 + 重叠窗口
│   │   └── verdict.rs                #   高熵/二进制判定与扣留策略
│   ├── hodor-policy/                 # ⚖️ 命令解析与策略评估(纯函数库)
│   │   ├── normalize.rs              #   argv 规范化、realpath、shell/解释器识别
│   │   ├── blacklist.rs              #   硬黑名单表 + 分类匹配
│   │   └── engine.rs                 #   三层评估:hard-deny → user-deny → whitelist → ask
│   ├── hodor-askpass/                # 💬 弹窗三级回退 + 反钓鱼短语 + i18n 集成
│   │   ├── pinentry.rs               #   assuan 协议调用 pinentry
│   │   ├── native.rs                 #   zenity / osascript / Windows CredUI
│   │   ├── tty.rs                    #   用户本人控制终端的读入(rpassword)
│   │   └── notify.rs                 #   桌面通知 + hodor approve 引导
│   ├── hodor-vfs/                    # 🗂️ 文件虚拟化层(读取时代理,§5.7)
│   │   ├── view.rs                   #   进程归属 → alias/real 视图决策
│   │   ├── intercept.rs              #   read 替换 / write 同步拦截(共享 scrub 引擎)
│   │   ├── linux.rs                  #   fuser(FUSE)挂载与生命周期
│   │   ├── macos.rs                  #   macFUSE / NFS loopback 探测择优
│   │   └── windows.rs                #   ProjFS provider
│   ├── hodor-guard/                  # 📁 守护编排:登记、sidecar、on/off/export
│   │   ├── registry.rs               #   .hodor-guard 加密 sidecar 读写
│   │   ├── manage.rs                 #   add/list/remove/on/off/status/export --redacted
│   │   └── quarantine.rs             #   写拦截弹窗决策 + 入档
│   ├── hodor-proto/                  # 📡 协议定义(serde 类型,被所有 crate 共享)
│   │   ├── daemon.rs                 #   CLI/MCP/VSCode 插件 ↔ daemon 的消息
│   │   ├── supervisor.rs             #   daemon ↔ root supervisor 的受控 exec 消息
│   │   └── forward.rs                #   远程瘦客户端 ↔ 本地 daemon 的转发消息
│   ├── hodor-daemon/                 # 🧠 daemon 库:会话状态机、授权生命周期、socket 服务
│   │   ├── state.rs                  #   locked/unlocked、grants(session+TTL)、自动上锁
│   │   ├── sessions.rs               #   MCP session 绑定、agent 进程树登记与回收
│   │   ├── exec.rs                   #   模板解析→策略评估→supervisor/本地 exec 编排
│   │   └── server.rs                 #   unix socket / named pipe 监听
│   ├── hodor-mcp/                    # 🤖 MCP server(rmcp,stdio,被 agent 拉起)
│   │   └── tools.rs                  #   五工具实现(透传 daemon,不落密钥)
│   ├── hodor-cli/                    # ⌨️ bin: hodor —— 唯一用户二进制
│   │   ├── main.rs                   #   clap 子命令分发
│   │   └── cmds/                     #   init/unlock/lock/status/add/policy/guard/forward/agent/run/audit/config/verify/mcp/setup-sudoers
│   └── hodor-supervisor/             # 🔑 bin: hodor-supervisor —— root 受控执行器
│       └── main.rs                   #   仅接受 hash 校验通过的 exec,流回输出
├── vscode/                           # 🧩 VSCode 插件(TypeScript,§5.12,M7)
│   ├── src/                          #   状态栏/管理面板/安装引导
│   └── protocol/                     #   由 hodor-proto schema 生成的消息类型
├── skills/                           # 分发给各 agent 的 skill 模板(中英双语)
│   ├── zcode/  claude/  cursor/ ...
├── i18n/                             # en-US.flt / zh-CN.flt
├── packaging/                        # brew formula、deb、winget manifest、systemd unit、sudoers 样例
├── docs/DESIGN.md                    # 本文档
├── AGENTS.md                         # AI 协作工程规范(代码风格、红线、流程)
├── README.md / README.zh-CN.md       # 双语 README,顶部互链切换(R24)
└── LICENSE                           # Apache-2.0
```

分层依赖方向(只允许向下):`cli / mcp / supervisor / vscode(经 socket)` → `daemon` → `proto + guard + vfs + askpass + policy + scrub` → `core`。`core`/`scrub`/`policy` 三个纯库无网络、无进程副作用,作为安全审计重点单独划分;`vfs` 依赖 `scrub` 复用同一套替换引擎(命令输出清洗与文件读取替换**共用一个库**,避免两套实现逻辑漂移)。

---

## 7. CLI 与数据文件

### 7.1 CLI 总览(日常 6 条 + 功能组)

```bash
# 日常
hodor init / unlock / lock / status / audit --verify / config

# 密钥管理
hodor add sudo                          # 存 sudo 密码(pinentry 输入,不进命令行)
hodor add ssh <alias> | hodor add key <alias>
hodor list | hodor policy <alias> set --agents zcode --confirm always --ttl 30m
hodor revoke <alias>

# 执行与测试(人工用;agent 走 MCP)
hodor run -- <含 {{alias}} 的命令>
hodor approve <request-id>              # 无 GUI 环境的审批通道

# 文件守护(读取时代理)
hodor guard init                        # 扫描 .env 等,启发式发现密钥条目,逐条确认登记
hodor guard add <file> --key <NAME> --alias <alias>
hodor guard list / remove / set-policy
hodor guard on / off / status           # 一键 替换视图/真实视图 转换(off 需弹窗确认)
hodor export --redacted <path>          # 生成脱敏副本,用于分享与发布

# sudo 强化 / agent 分发 / 远程
hodor setup-sudoers
hodor agent install [--all | --remote user@host]
hodor forward setup|up|down <host>

# 内部/发布
hodor mcp serve        # agent 拉起          hodor verify   # 二进制完整性校验
hodor daemon           # 手动启动(通常自动)
```

### 7.2 数据文件布局(XDG)

| 路径 | 内容 |
|---|---|
| `~/.config/hodor/vault.bin` | 加密保险库(600) |
| `~/.local/state/hodor/audit.log` | 哈希链审计日志 |
| `$XDG_RUNTIME_DIR/hodor.sock` | daemon socket(Unix;Windows 用 named pipe) |
| `~/.config/hodor/config.toml` | 明文偏好:语言、TTL、askpass 顺序、锁定时长(**不含任何密钥材料**) |
| `/usr/lib/hodor/hodor-supervisor` | root helper 二进制 |
| `/etc/sudoers.d/hodor` | 可选 NOPASSWD 白名单(仅 supervisor) |
| `<project>/.hodor-guard` | 项目内加密 sidecar(git 可提交) |
| `<project>` 真实文件 | **保留真实密钥**(代码直接可执行);agent 视图由挂载层动态替换 |

---

## 8. 威胁模型与诚实边界(写进 README)

**防得住**:密钥进入模型上下文(注入/好奇/日志);密钥进 argv/env;弹窗被 GUI 自动化点穿(口令/指纹是人类才有的秘密);静默提权(逐条可见、哈希绑定);审批重放(绑精确命令);策略/审计/入档篡改(全在加密库+链校验);替换 hodor 二进制后直接取密钥(解不开保险库);**agent 用任何工具读取受保护文件(FS 层按进程树统一代理)**;agent 把密钥写入文件(同步写拦截)。

**缓解但不根除**:一屏合法请求里夹带恶意命令(每弹窗只展示一条命令);审批疲劳(不提供"本会话全部批准");`guard on` 激活前的窗口(对策:自动挂载+通知);agent 经 IPC 请求受信进程代读(已知边界);Linux 指纹弱于口令(fprintd 只给布尔值)。

**防不住(如实声明)**:以当前用户身份执行任意代码的自适应攻击者,伪造弹窗钓鱼口令(反钓鱼短语降低,无法根除);X11 下键盘监听(Wayland/生物识别规避);已被入侵的远程服务器上短暂驻留的凭证(物理必然);`guard on` 之前被读走的文件内容。

---

## 9. 里程碑

| 里程碑 | 内容 | 涉及 crate |
|---|---|---|
| **M1** 本地托管核心 | vault 加密 + object 模型 + pinentry 三级回退 + 三平台指纹 + 自动上锁。产出:可独立使用的 CLI 密钥管家 | core, askpass, cli |
| **M2** sudo 通道 | root supervisor + 黑名单三层评估 + 三档授权 + sudoers 引导 + MCP + skill 安装器 | proto, supervisor, daemon, mcp, policy |
| **M3** 防外流引擎 | 模板注入 + 输出清洗(四形态/不可分析扣留)+ 审计哈希链 | scrub, daemon/exec |
| **M4** 文件守护层 | 读取时代理 FS 层(三平台)+ guard 登记/sidecar + 同步写拦截 + on/off/export。**全项目工程量最大、平台差异最大的一期** | vfs, guard |
| **M5** 转发与远程 | SSH 反向通道 + 远程瘦客户端 + 远程 skill 投放 | proto/forward, cli |
| **M6** 发布 | Fluent 双语、README 双语切换、三平台包管理渠道(brew tap → core、PPA/deb、winget)、`hodor verify`、CI 交叉编译 | i18n, packaging, 全部 |
| **M7** VSCode 插件 | 安装引导 + object/guard/策略/审计可视化管理(批准仍走带外弹窗) | vscode/ |

**建议的第一个动手模块**:`hodor-scrub`(M3 核心)是纯函数库,输入输出均为文本对,可先行编写完整单元测试,不依赖 daemon 与加密;`hodor-core` 的 vault 封解包其次。两者是整个信任模型的承重墙。

---

## 10. 分发与命名

- repo:`<user>/hodor`,About 栏:*Hodor — Hold the door between your AI agent and your secrets.*
- crate:先联系 crates.io 上已 yanked 的 `hodor` 原作者请求转让;兜底 crate 名 `hodor-cli`(package 名与 `[[bin]] name = "hodor"` 可不同)。
- 渠道:GitHub Releases 三平台产物 → Homebrew tap(成熟后投 homebrew-core)→ Linux `.deb` + PPA/Cloudsmith apt 仓库 → winget/scoop/choco → `cargo install`。
- CI:GitHub Actions,三平台交叉编译 + `hodor verify` 所用的发布签名。

---

## 11. 待项目所有者决策的问题

1. **crate 名**:并行推进"联系原作者转让 `hodor`"和"直接启用 `hodor-cli`"?转让失败不影响任何对外名字。
2. **平台顺序**:M1 是否按 Linux 优先(当前开发环境是 Linux)落地,macOS/Windows 的指纹与 vfs 模块在各期末尾补齐?
3. **macOS 虚拟化层**:macFUSE(需 kext,体验重)与 NFS loopback(免 kext,较冷门)如何取舍?建议安装时探测、默认 macFUSE 存在则用之。
4. **默认参数**:任务档 TTL 15 分钟、空闲自动上锁 15 分钟、扣留阈值(输出 ≥ 多少字节且高熵才扣留)是否符合预期?
5. **别名语法**:`{{alias}}` 双花括号 OK?还是想用 `hodor:alias` 等不易与其他模板引擎冲突的语法?
6. **pinentry 依赖**:接受把它作为打包时的可选依赖(推荐路径),默认回退到 hodor 自带 TTY 读入?
7. **MCP 实现**:采用官方 Rust SDK(rmcp)走 stdio,OK?
8. **HTTP 工具范围**:M3 先只做 `Authorization: Bearer {{alias}}` 注入,还是同时支持自定义头名(如 `X-API-Key`)按 object 配置?
9. **guard on 的自动触发**:由 VSCode 插件在项目打开时自动挂载,还是 daemon 检测到 agent 会话 cwd 位于受保护项目时自动挂载(或两者结合)?
