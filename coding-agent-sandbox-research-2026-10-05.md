# 主流 Coding Agent 跨操作系统沙箱机制调研

调研基准：2026-10-05，Asia/Shanghai。方法：官方资料交叉检查、固定 Git 提交的静态源码阅读；**没有在 macOS、Linux、Windows 上分别运行攻防测试**。

这里的“主流”指有代表性的终端、IDE 和自主开发代理，不是市场份额排名。比较的是 agent 执行命令、访问文件和使用网络的边界，不是 Electron 渲染器沙箱，也不把 Git worktree 当成安全沙箱。

**版本口径：产品文档声明、源码快照中存在的实现、已安装版本真正启用的能力，是三回事。** 本文保留这些区别；默认分支源码不能证明对应能力已进入稳定版。文中的 D/R 编号对应末尾资料索引。

## 1. 核心结论

1. **审批不等于隔离。** “执行前询问”“允许此命令”主要控制是否调用工具；真正的 OS 沙箱在程序启动后继续约束它和子进程。OpenCode 的安全政策直接把权限系统与安全隔离区分开。[R14]
2. **macOS 的本地轻量方案高度集中在 Seatbelt；Linux 集中在 Bubblewrap/namespaces，按产品再叠加 seccomp、Landlock 或网络代理。** 这不是说这些组件会在每个产品里同时启用。[D1、D2、D4、R1、R6]
3. **Windows 不存在统一答案。** 受限令牌/ACL、独立用户/WFP、MXC ProcessContainer，以及 WSL2 中的 Linux 沙箱，是不同路线；也不能把它们都叫成系统自带的 Windows Sandbox 虚拟机。[D1、D5、D6、R4、R5、R7、R13]
4. **必须读当前源码。** Codex 的 Linux 默认实现已是 Bubblewrap；Claude Code 产品文档仍不宣称原生 Windows 沙箱，但公开 SRT 源码已加入 Windows 后端；Gemini 的 Windows 原生后端也不只是“Docker 的另一种写法”。[R1、D2、R7、R10]
5. **开启 sandbox 不等于默认断网、不能读取家目录、具备 VM 级隔离。** 文件读取、写入、网络、IPC、提权和例外机制应分别核查。[D1、D2、D3、D6、R13]

## 2. 产品 × 操作系统总览

表格描述可用路线，不表示全部默认开启。

| 产品/形态 | macOS | Linux | 原生 Windows / WSL2 | 可核查范围 |
|---|---|---|---|---|
| OpenAI Codex | Seatbelt，动态生成策略并调用 `sandbox-exec` | 当前源码默认 Bubblewrap；叠加 seccomp、`no_new_privs`；Landlock 为旧路线且受限 | 原生有 elevated / unelevated 路线；源码另有 MXC 选择；WSL2 走 Linux 后端 | Rust 核心和 OS 后端公开 [D1、R1–R5] |
| Claude Code | Seatbelt，限制命令及子进程 | Bubblewrap + 网络 namespace/代理，另有 seccomp 辅助限制 | 产品文档支持 WSL2，仍称不支持原生 Windows；**SRT 源码已含原生 Windows 实现，但不能据此宣称 Claude Code 已发布支持** | 产品文档 + 公开 `anthropics/sandbox-runtime` [D2、R6、R7] |
| Gemini CLI | Seatbelt；也可 Docker/Podman | Docker/Podman，可显式选择 runsc；源码另含 Bubblewrap 执行器 | 配置代码接受 `windows-native`，也有容器路线；不能把存在于源码等同默认启用 | CLI 包装器、配置、平台执行器公开 [D3、R8–R10] |
| Cursor Agent | Seatbelt | 官方说明为 Landlock，兼容性需要时回退 Bubblewrap | Windows 通过 WSL2 使用 Linux 路线，不是同一套原生 Windows 隔离 | 官方产品/工程说明；未据公开资料重建完整内部调用链 [D4] |
| VS Code Local / Agent Host 自定义终端 | SRT 路线，底层 Seatbelt | SRT 路线，底层 Bubblewrap | 原生 Windows 使用 MXC；WSL2 按 Linux 处理；有预览状态和系统前提 | VS Code 集成层公开；当前源码包名为 `@vscode/sandbox-runtime`；不代表 Agent Host 内建 shell [D5、R11、R12] |
| GitHub Copilot CLI | MXC 的 Seatbelt 后端 | MXC 的 Bubblewrap 后端 | MXC ProcessContainer 的 BaseContainer；不使用 AppContainer 回退，要求相应 Windows 能力 | CLI 本地沙箱整体仍为实验性，且默认关闭；不与 VS Code 集成混为一谈 [D6、R13] |
| OpenCode | 不提供内建 OS 沙箱 | 同左 | 同左 | 安全政策明确写明 No Sandbox；需外置容器/VM [R14] |
| OpenHands | 取决于选择的 workspace/backend | 同左 | 同左；Docker 路线还依赖宿主的容器环境 | `DockerWorkspace` 是容器路线；`LocalWorkspace` 直接操作宿主，不能笼统说“OpenHands 总在 Docker 内” [R15] |

## 3. 按 OS 理解机制

### macOS：同一内核上的 Seatbelt，不是另起一台机器

Codex、Claude/SRT、Gemini、Cursor 等都能看到 Seatbelt 路线。典型做法是生成 SBPL 策略，把命令包装在 `sandbox-exec` 后启动；由系统执行文件、网络等限制。不同产品的差别主要落在策略内容、网络代理、例外和覆盖范围，而不只是 launcher 的名字。[D1–D4、R3、R6]

**不能从“有 Seatbelt”推导出“只能读项目”。** 例如 Gemini 文档中的 `permissive-open` 允许较广泛读取和网络，同时限制写入；Codex/Claude 也需要区分写入边界和敏感文件读取策略。[D1–D3]

### Linux：视图隔离、系统调用约束、网络出口必须分开看

以当前 Codex 为例：Bubblewrap 构建 mount/user/PID 等隔离视图，根文件系统先只读，再把允许写入的目录叠加为可写；网络受限时使用独立 network namespace，代理模式通过受控桥接连到宿主代理；内部阶段再安装 `no_new_privs` 与 seccomp。[R1、R2]

Landlock 与 Bubblewrap 不是同义词。当前 Codex 已不允许依靠旧 Landlock 路径承担需要文件系统隔离的策略；其说明特别指出旧方案不能隔离 app-server 的 Unix socket。Cursor 文档则仍描述 Landlock 优先、Bubblewrap 兼容回退。**不能用某一产品的迁移概括所有 Linux agent。**[R1、D4]

### Windows：四类路线不能混为一谈

| 路线 | 主要边界 | 本次核查的例子 | 需要注意 |
|---|---|---|---|
| Restricted Token + ACL / MIC / Job | 访问令牌、文件权限/完整性级别、进程树生命周期 | Codex 传统 Windows 后端、Gemini 原生后端 | 各组件具体组合不同；Job Object 本身不是通用文件/网络安全边界 [R4、R10] |
| 独立低权限账户 + WFP | 换用户身份，并在 OS 网络层按 SID 限制出口 | Codex elevated 路线、SRT 新 Windows 实现 | 初次安装可能需要管理员权限，但不代表让 agent 以管理员身份执行 [D1、R7] |
| MXC ProcessContainer / PSEC 等 | 策略转换为 Windows 进程安全环境；兼容路径受系统能力影响 | VS Code、Copilot CLI；Codex 源码也有 MXC 分支 | 不是一律使用完整 VM；MXC 当前公开仓库仍有安全边界警告 [R5、R12、R13] |
| WSL2 中的 Linux sandbox | 在 WSL2 的 Linux 环境内执行 Linux 沙箱策略 | Claude、Cursor；Codex 也支持 | 不等同原生 Windows 后端。判断宿主保护时，仍需关注共享目录和跨边界接口 [D1、D2、D4] |

## 4. 源码核查：最值得读的实现

### 4.1 Codex：不要再把 Linux 简写为“Landlock + seccomp”

固定快照：`openai/codex@7f892275e31002f0422477c6219189284560e689`。

源码阅读顺序：

- `codex-rs/linux-sandbox/README.md`：最直接说明当前行为，明确 Bubblewrap 默认、WSL2 正常走 Linux、WSL1 不满足所需 user namespace 条件。[R1]
- `run_main()`：先构建文件系统视图，再进入内部阶段施加 seccomp / `no_new_privs`，最后执行用户程序。类型名仍保留历史上的 `LandlockCommand`，不能只凭名字判定实际机制。[R2]
- `seatbelt.rs`：把权限模型转换为 macOS 启动策略。[R3]
- Windows 的 `token.rs`：实际调用 `CreateRestrictedToken`，并使用 `DISABLE_MAX_PRIVILEGE`、`LUA_TOKEN`、`WRITE_RESTRICTED`；这不是启动一台 Windows VM。[R4]
- `windows_sandbox_config.rs`：区分 elevated、unelevated 与 MXC，另有 `prefer_mxc` 的实际后端选择逻辑。看到代码分支仍不能推断所有已安装版本的默认值。[R5]

Windows 的强度还要区分模式：官方文档将 elevated 描述为独立账户、ACL 与系统级网络限制；unelevated 兼容路径更多依赖受限令牌及较弱的离线配置。不能统一标注为“Windows 已做同等强度断网”。[D1]

### 4.2 Claude / SRT：产品支持矩阵与底层库出现时间差

固定快照：`anthropics/sandbox-runtime@e025055f221021582934e666cac1eeb08310e7b1`。

产品文档描述的是 Claude Code 的 Bash 沙箱：macOS Seatbelt、Linux/WSL2 Bubblewrap；默认写当前目录、按配置控制读取及域名访问。它还存在沙箱外重试/例外机制，不能将一次用户授权后的非沙箱执行视为仍受相同边界保护。[D2]

公开 SRT 的 README 和 `windows-sandbox-utils.ts` 已给出另一条原生 Windows 路线：`srt-win.exe` 创建专用本地账户，按账户 SID 建立 WFP 出口限制，用显式 ACE 表达文件访问，并通过受限令牌子进程执行命令。仓库也带有对应 Rust helper 源码目录。[R6、R7]

**判断：SRT 原生 Windows 后端已经存在；但本次读取的 Claude Code 产品文档仍称原生 Windows 不受支持。** 这应报告为“组件代码与产品声明不同步”，而不是替产品宣布已上线。[D2、R7]

### 4.3 Gemini：旧的整进程包装与新的平台执行器需要一起看

固定快照：`google-gemini/gemini-cli@fb972b2f87fe7d5b06d37eac711490162d98de2c`。

- `sandboxConfig.ts` 的显式 command 包含 Docker、Podman、Seatbelt、runsc、LXC、`windows-native`；runsc 并非自动探测默认项。[R9]
- `createSandboxManager()` 在启用时按平台选择 `WindowsSandboxManager`、`LinuxSandboxManager`、`MacOsSandboxManager`，否则返回 `NoopSandboxManager`。[R8]
- Linux 执行器的 Bubblewrap builder 已有 namespace、只读根挂载、临时目录等逻辑；但 CLI 的公开 command 列表并没有直接把 `bwrap` 当作可选命令。**源码里有 Linux manager，不代表普通用户的 `--sandbox` 就默认选择它。**[R8、R9]
- Windows helper 使用受限令牌、Low Integrity 和 Job Object。官方仓库文档还提醒，写入目录的完整性标签调整可在会话后保留。[D3、R10]

**需要特别保留的静态分析结论：** `GeminiSandbox.cs` 在 `networkAccess=false` 时设置 Job Object 网络速率，`MaxBandwidth` 为 1；设置失败会打印 warning 而不是立即终止。因此，仅凭这个分支**不能证明可靠断网**，更不能把它等同于 WFP 出口阻断或独立网络 namespace。这是对代码保证范围的判断，不是经过实测的漏洞利用结论。[R10]

### 4.4 VS Code 与 Copilot CLI：两个产品集成，不能合并猜测

固定快照：`microsoft/vscode@2dca67a07aba894351849f39d337a921758722e8`。

VS Code 当前 `terminalSandboxEngine.ts` 解析到 `@vscode/sandbox-runtime/dist/cli.js`；Windows 则走独立的 `WindowsMxcTerminalSandboxRuntime`。这描述的是 Local / 自定义终端路线：macOS/Linux 为 VS Code 的 SRT 分支，Windows 使用 MXC，而不是“所有系统都直接调用同一个 Anthropic 包”。Agent Host 默认的 Copilot SDK 内建 shell 是另一条集成路线，其沙箱在各支持平台都标为实验性，网络控制也不支持域名列表。[D5、R11、R12]

Windows wrapper 的 `_createNetworkPolicy()` 只发出整体 `allowOutbound`，并明确说明该集成不提供逐主机策略。因此 macOS/Linux 的域名粒度能力不能直接套用到这个 Windows 分支。VS Code 的产品文档也区分这些行为。[D5、R12]

Copilot CLI 的本地沙箱整体仍属实验性、默认关闭。它使用 MXC，但 Windows 明确只使用 BaseContainer，不采用通用 MXC 中的 AppContainer 回退。其外接代理在 macOS 依靠环境变量、Linux 则通过隔离网络强制路由；这不应被扩大解释为所有网络策略都只依赖环境变量。[D6]

MXC 的 ProcessContainer 指南展示的链路是：SDK 生成配置 → `wxc-exec` → PSEC 描述 → `CreateProcessSecurityEnvironment` → 带安全环境属性的 `CreateProcessW`。这与启动完整 Windows Sandbox VM 不是同一条路径。[R13]

**重要限制：本次固定的 MXC README 明确提示仍是早期预览，存在过宽策略，当前不应把其 profile 当成安全边界。** 本文因此不把“接入 MXC”写成“已获得 VM 等级的安全保证”。[R13]

### 4.5 两个反例：有 permission 或 workspace，不代表有隔离

**OpenCode：** `SECURITY.md` 明确说明 agent 没有被 sandbox，permission 是让用户了解行为的交互机制，而非安全隔离。需要真正隔离时，应另放入容器/VM。这个结论来自维护者的威胁模型，不是对源码“没有搜到 sandbox”的猜测。[R14]

**OpenHands：** 当前架构将很多执行能力放在 software-agent-sdk 中。`DockerWorkspace` 创建运行 agent server 的 Docker 容器，通过远程 workspace 接口操作；`LocalWorkspace` 直接读写宿主并执行命令。当前主仓库 README 也明确警告本地启动方式拥有宿主文件系统访问。因此必须注明具体 backend，不能以产品名推断保护边界。[R15]

**Cursor：** 本文只将官方文档披露的 Seatbelt / Landlock / Bubblewrap / WSL2 路线列为证据。没有可对应本次产品构建的完整公开实现，不能进一步声称已审计它的内部 mount 规则、seccomp filter 或完整逃逸防护。[D4]

## 5. 跨产品比较时最容易遗漏的边界

- **写保护不是读保护。** 项目外不可写，并不推出 SSH key、浏览器配置或环境变量不可读；广泛可读加宽泛网络出口仍然需要评估。[D1–D3]
- **代理配置不是出口强制。** 看的是直接 socket 能否绕过代理、代理策略在哪一层执行，而不只是存在 `HTTPS_PROXY`。[R1、R6、D6]
- **沙箱覆盖范围不是整个应用。** Claude 文档主要描述 Bash 子树；VS Code 文档主要描述 agent 终端并有独立 MCP 设置；远端 MCP、HTTP 工具和外部服务必须另画边界。[D2、D5]
- **例外和降级同样重要。** 是否允许审批后沙箱外运行、依赖缺失是否拒绝执行、管理员策略能否强制启用，都影响最终保证。Copilot CLI 文档对没有可用沙箱时的会话行为和强制策略作了区分。[D2、D6]
- **本地容器不等于“宿主的一切都隔离了”。** Docker Desktop 的 Linux 容器位于 Linux VM 中，但宿主共享目录仍然是明确打开的访问面；OpenHands 的 DockerWorkspace 也允许额外挂载目录。[D7、R15]
- **机制不是完整安全证明。** 产品安装版本、系统内核、Windows build、挂载配置和网络配置不同，实际保证就可能不同。本文不据静态分析为任何产品出具“不可逃逸”保证。

## 6. 如果要选型或实现自己的 Agent

以下是基于上述证据的工程建议，而不是产品安全等级排名：

1. **研究轻量跨平台策略编译：** 优先读 Codex 与 SRT。前者展示统一权限模型如何分派到不同 OS；后者便于独立包装命令和工具进程。[R1–R7]
2. **Windows 需求单独列验收项：** 不要把 WSL2、受限令牌、独立用户/WFP、MXC 当成一个功能勾选框。特别记录是否改变 ACL/完整性标签、是否需要管理员安装、网络限制是否真的强制执行。[D1、R7、R10、R13]
3. **不可信仓库、无人值守、共享服务：** 将“本地便利型原生沙箱”与“隔离运行环境”分层设计。可以考虑单独 VM 或 gVisor 等更强隔离路线，同时最小化挂载和凭据；gVisor 的安全目标也是减少对宿主内核的直接接触，并非宣称零风险。[D8]
4. **权限模型至少拆分：** 文件读、文件写、网络出口、进程/IPC、凭据、沙箱外提权和远端工具。不要只有一个 `allow_shell` 或 `sandbox=true`。

建议验收使用无敏感数据的临时目录、假凭据和自有测试服务：检查项目外读写、符号链接、子进程继承、直接网络连接、宿主 socket/管道访问、后台子进程清理、沙箱依赖失效及审批后边界变化。**这些是后续建议，本文没有执行这些测试。**

## 7. 固定源码快照

以下为本次查询得到的默认分支提交；提交时间已换算为 Asia/Shanghai。它们不是稳定版版本号，也不表示同一秒钟的原子快照。

| 仓库 | 提交 | 提交时间 |
|---|---|---|
| openai/codex | `7f892275e31002f0422477c6219189284560e689` | 2026-10-05 07:07:12 |
| anthropics/sandbox-runtime | `e025055f221021582934e666cac1eeb08310e7b1` | 2026-10-05 02:22:16 |
| google-gemini/gemini-cli | `fb972b2f87fe7d5b06d37eac711490162d98de2c` | 2026-10-02 13:49:39 |
| microsoft/vscode | `2dca67a07aba894351849f39d337a921758722e8` | 2026-10-05 15:34:02 |
| anomalyco/opencode | `907b3bc518fa48e90e8ec24dd327d13eee71c36c` | 2026-10-03 12:55:40 |
| OpenHands/OpenHands | `64f12b3a3294aa78e850c2b0ec32f6bef04ba5fd` | 2026-10-05 15:01:55 |
| microsoft/mxc | `2044eac07ad819319e924ae3d3a5f427a79c9afb` | 2026-10-03 12:38:35 |
| OpenHands/software-agent-sdk | `de30ec0111fc1c1435a1639d4ec27aead297d5b8` | 2026-10-05 15:44:17 |

## 8. 资料与源码索引

源码链接固定到上述提交，便于复查。一个编号可对应多个互补证据；`#L` 为 GitHub 源文件行号。产品文档是调研时访问的在线页面，可能随发布更新。

### 官方资料

- D1 — Codex sandboxing：`https://learn.chatgpt.com/codex/sandboxing`
- D1 — Codex Windows sandbox：`https://learn.chatgpt.com/docs/windows/windows-sandbox`
- D2 — Claude Code sandboxing：`https://code.claude.com/docs/en/sandboxing`
- D3 — Gemini CLI sandbox：`https://geminicli.com/docs/cli/sandbox/`
- D4 — Cursor Run Modes / sandbox：`https://cursor.com/docs/agent/security/run-modes`
- D4 — Cursor 官方实现说明：`https://cursor.com/blog/agent-sandboxing`
- D5 — VS Code agent sandboxing：`https://code.visualstudio.com/docs/agents/run/agent-sandboxing`
- D6 — Copilot CLI local/cloud sandbox：`https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes`
- D7 — Docker Desktop VM / 文件共享架构：`https://docs.docker.com/desktop/features/networking/`
- D7 — Docker Desktop Windows 权限边界：`https://docs.docker.com/desktop/setup/install/windows-permission-requirements/`
- D8 — gVisor security model：`https://gvisor.dev/docs/architecture_guide/security/`

### 固定提交源码

- R1 — Codex Linux 当前行为：`https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/README.md`
- R2 — Linux 入口与两阶段执行：`https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/src/linux_run_main.rs#L167`
- R3 — Seatbelt 策略生成：`https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/sandboxing/src/seatbelt.rs`
- R4 — Windows Restricted Token：`https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/token.rs#L500`
- R4 — Windows WFP：`https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/wfp.rs`
- R5 — Windows 模式与 MXC 选择：`https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/core/src/config/windows_sandbox_config.rs#L32`
- R6 — SRT 跨平台架构：`https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/README.md`
- R7 — SRT Windows 后端：`https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/windows-sandbox-utils.ts`
- R8 — Gemini 平台分派：`https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/services/sandboxManagerFactory.ts#L22`
- R8 — Gemini Bubblewrap builder：`https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/linux/bwrapArgsBuilder.ts#L33`
- R9 — Gemini CLI sandbox 配置：`https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/cli/src/config/sandboxConfig.ts`
- R10 — Gemini Windows helper：`https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/windows/GeminiSandbox.cs#L247`
- R10 — Gemini Windows 网络限速分支：`https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/windows/GeminiSandbox.cs#L292`
- R10 — 仓库内的 Windows 完整性标签说明：`https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/docs/cli/sandbox.md`
- R11 — VS Code SRT 解析入口：`https://github.com/microsoft/vscode/blob/2dca67a07aba894351849f39d337a921758722e8/src/vs/platform/sandbox/common/terminalSandboxEngine.ts#L631`
- R12 — VS Code MXC 集成：`https://github.com/microsoft/vscode/blob/2dca67a07aba894351849f39d337a921758722e8/src/vs/platform/sandbox/common/terminalSandboxMxcRuntime.ts#L41`
- R12 — Windows 网络策略转换：`https://github.com/microsoft/vscode/blob/2dca67a07aba894351849f39d337a921758722e8/src/vs/platform/sandbox/common/terminalSandboxMxcRuntime.ts#L125`
- R13 — MXC 能力及预览安全警告：`https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/README.md`
- R13 — MXC ProcessContainer / PSEC 调用链：`https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/docs/process-container/guide.md`
- R14 — OpenCode 威胁模型：`https://github.com/anomalyco/opencode/blob/907b3bc518fa48e90e8ec24dd327d13eee71c36c/SECURITY.md`
- R15 — OpenHands 当前部署方式：`https://github.com/OpenHands/OpenHands/blob/64f12b3a3294aa78e850c2b0ec32f6bef04ba5fd/README.md`
- R15 — DockerWorkspace：`https://github.com/OpenHands/software-agent-sdk/blob/de30ec0111fc1c1435a1639d4ec27aead297d5b8/openhands-workspace/openhands/workspace/docker/workspace.py#L53`
- R15 — LocalWorkspace：`https://github.com/OpenHands/software-agent-sdk/blob/de30ec0111fc1c1435a1639d4ec27aead297d5b8/openhands-sdk/openhands/sdk/workspace/local.py#L17`
