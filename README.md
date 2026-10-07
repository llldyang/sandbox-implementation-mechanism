# Coding Agent Sandbox 实现机制

这份仓库整理了主流 Coding Agent 在 macOS、Linux 和 Windows 上的沙箱方案。内容分成两章：先建立产品与操作系统的全景，再沿固定源码提交追到实际启动流程、文件边界和网络边界。

## 阅读顺序

### 第一章：主流机制调研

[主流 Coding Agent 跨操作系统沙箱机制调研](./coding-agent-sandbox-research-2026-10-05.md)

这一章适合先读，主要回答：

- Codex、Claude Code、Gemini CLI、Cursor、VS Code/Copilot、Hermes Agent、OpenCode 和 OpenHands 分别采用什么路线；
- Seatbelt、Bubblewrap、Landlock、seccomp、Windows Restricted Token、WFP 和 MXC 各自解决什么问题；
- “需要审批”“运行在容器里”和“具有 OS 沙箱”为什么不是一回事；
- 跨产品比较时容易遗漏哪些文件、网络、IPC 和降级边界。

### 第二章：源码实现分析

[Sandbox 实现机制：Coding Agent 如何把权限落到操作系统](./coding-agent-sandbox-implementation-analysis-2026-10-05.md)

这一章继续追踪配置如何变成 OS 约束，包含关键调用链、短源码结构和伪代码，重点覆盖：

- macOS 的动态 SBPL 与 `sandbox-exec`；
- Linux 的 Bubblewrap、namespace、seccomp 和代理桥；
- Windows 的 Restricted Token、独立用户、ACL、Job Object、WFP 与 PSEC；
- Hermes Agent 的可插拔终端后端、Docker 加固与整进程隔离；
- 个人本地、企业受管本地、厂商云端和企业自托管环境的边界差异，以及 OpenAI、GitHub、Claude、Cursor 的策略覆盖、凭据代理、任务隔离和执行通道对比；
- 容器后端和只做权限提示的工具分别能提供什么边界。
