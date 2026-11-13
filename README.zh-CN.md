# Hodor

**[English](README.md) | [中文](README.zh-CN.md)**

> Hodor — 守住 AI agent 与你的密钥之间的那扇门。

Hodor 是一个 CLI-first 的 AI agent 凭证托管平台。它保管一切 agent 需要*使用*但绝不能*看见*的东西——sudo 密码、SSH 凭证、API key、token——并代表 agent 执行需要这些凭证的操作。

在 agent 的世界里只有**别名**(`{{openai}}`、`{{sudo}}`)和执行结果。真实密钥只存在于 Hodor 的进程内存和你的指纹/主口令之后。

## 当前状态

早期开发中(M1:本地保险库、对象模型、审计链、策略引擎、输出清洗)。完整架构、需求清单(R1–R24)与路线图见 [docs/DESIGN.md](docs/DESIGN.md)。

## 核心保证

- **密钥永远不会进入 agent 的上下文**——不在工具输出里,不在命令行参数里,不在 agent 能读到的文件里。
- **带外审批**——原生 pinentry 弹窗 + 反钓鱼短语;审批与确切的命令哈希绑定。
- **防篡改审计**——只追加的哈希链,链头存于加密保险库之内。
- **sudo 硬黑名单**——改密码、改 sudoers、读 shadow、提权跳板,无论怎么配置一律拒绝。

## 安装

尚未发布,目前为开发仓库。源码构建:

```bash
cargo install --path crates/hodor-cli
```

## 快速上手

```bash
hodor init                 # 创建保险库:主口令 + 反钓鱼短语
hodor add key openai       # 以别名存入密钥(弹窗输入,绝不经过命令行)
hodor add sudo             # 存入 sudo 密码
hodor run -- curl -s -H "Authorization: Bearer {{openai}}" https://api.example.com
hodor audit --verify       # 校验防篡改审计链
```

## 许可

Apache-2.0
