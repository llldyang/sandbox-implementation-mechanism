# 面向安全使用的 Coding Agent Harness 沙盒设计

## 1. 设计结论

最重要的边界是把 harness 与执行环境拆开。模型调用、策略决策、审批、密钥、审计和恢复状态留在可信控制面；命令、文件修改、依赖安装和测试放进不可信执行面。文件、网络、凭据、MCP、浏览器和 GUI 都默认不可用，再按任务增加必要能力。

权限必须单调收紧。组织、部署环境、仓库、任务和临时审批共同决定最终策略，下面任何一层都不能越过组织上限。长期凭据留在沙箱外，优先使用短期 token、OIDC 或按目标注入凭据的代理。

审批只回答“是否允许这次动作”，不负责隔离。批准一条命令，不等于允许它读取整个家目录、连接任意网络或把权限留给后台进程。沙箱后端、代理、策略编译或审计组件失效时，任务应直接失败，不能回退到宿主用户权限。

## 2. 威胁模型

模型生成的命令、脚本和工具参数不可信；仓库中的构建脚本、测试、Git hooks、插件和文档也不可信。依赖包、安装脚本、远程网页和 MCP 返回内容属于同一类输入。任务启动后出现的子进程、服务、缓存和 artifact 不能因为“由本次任务生成”就自动获得信任。

主要防护目标如下：

| 目标 | 典型风险 |
|---|---|
| 宿主与用户数据 | 读取家目录、SSH key、浏览器配置、keychain、云 CLI 凭据 |
| 仓库完整性 | 修改 `.git`、隐藏生成文件、绕过 review 直接推送主分支 |
| 网络与数据外传 | 把源码、token、环境变量或测试数据上传到未批准地址 |
| 多租户隔离 | 云端任务通过共享目录、缓存、socket 或宿主服务读取其他任务数据 |
| 凭据最小化 | 长期 PAT、云密钥、数据库口令进入进程环境、镜像或日志 |
| 生命周期 | 后台进程、volume、snapshot、ACL/WFP 规则或 token 在任务结束后残留 |
| 决策可追溯 | 无法说明哪条策略允许了命令、谁批准了例外、结果怎样进入仓库 |

这不是内核零日或恶意管理员的完整防御方案。执行节点仍需要常规的补丁、镜像签名、EDR、磁盘加密和基础设施访问控制。

## 3. 总体架构

[OpenAI Sandbox Agents](https://developers.openai.com/api/docs/guides/agents/sandboxes) 将 harness 定义为模型循环、工具路由、审批、追踪、恢复和运行状态所在的控制面，把文件、命令、端口和快照归到 sandbox 计算面。这里沿用这一拆分，但策略模型不绑定 OpenAI API。

```text
┌──────────────────────────── trusted control plane ────────────────────────────┐
│ Identity / repo authorization                                                 │
│          ↓                                                                    │
│ Agent loop → Policy resolver → Approval service → Tool router                 │
│                    │                 │               │                         │
│                    ├─ Audit / trace  │               ├─ host-side MCP          │
│                    ├─ Secret broker  │               └─ sandbox capabilities  │
│                    └─ Artifact policy│                                         │
└──────────────────────────────────────┼─────────────────────────────────────────┘
                                       │ narrow, typed RPC
┌──────────────────────────── untrusted execution plane ────────────────────────┐
│ Sandbox supervisor → OS/container/VM backend → process tree                   │
│          ├─ filesystem policy                                                  │
│          ├─ egress proxy / network namespace                                   │
│          ├─ resource and lifecycle limits                                      │
│          └─ scoped workspace, no long-lived application credential             │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 控制面组件

| 组件 | 责任 | 不应下放给沙箱的内容 |
|---|---|---|
| Identity / repo authorization | 校验用户、服务身份、组织和仓库范围 | 组织级 PAT、管理员身份 |
| Policy resolver | 合并组织、环境、仓库和任务策略，生成不可变 effective policy | 原始管理策略的写权限 |
| Approval service | 判断哪些能力需要谁批准，绑定任务与参数 | 可伪造的“用户已同意”文本 |
| Tool router | 决定工具在 host 还是 sandbox 运行 | 未经过策略检查的任意 shell |
| Secret broker | 签发短期凭据或在代理侧附加凭据 | 长期 secret 明文 |
| Audit / trace | 记录策略版本、命令、审批、网络和交付事件 | 可被任务覆盖的本地日志文件 |
| Artifact service | 验证、扫描和发布任务结果 | 未审查的直接生产发布能力 |

### 3.2 执行面组件

Sandbox supervisor 只接受结构化请求，例如 `run_process`、`read_file`、`apply_patch`、`open_port`。不要把控制面到执行面的 RPC 设计成“传一段 shell 字符串并相信调用方已经检查过”。

每个请求都应携带 `session_id`、`task_id` 和 `principal_id`，同时带上 effective policy 的哈希、过期时间、操作类型、规范化目标和参数摘要。若操作需要审批，请求中还要有与任务绑定的审批票据；其余请求则要给出无需审批的策略依据。幂等键和取消 token 用来处理重试与中止，不能省略。

## 4. 统一策略模型

策略应覆盖部署位置、隔离方式、文件、进程、网络、凭据、工具、审批、生命周期、交付和审计。部署策略决定任务是在本机进程、容器、VM 还是 microVM 中运行；文件策略分别描述可读、可写和明确拒绝的范围；进程策略约束子进程、资源、后台任务和退出回收；网络策略区分离线、受限出口和不受限出口；凭据策略说明 Git、云服务和第三方系统如何获得短期身份。

工具策略不能只写“允许 shell”。内建文件工具、本地与远端 MCP、浏览器、computer use、插件和 Git 写操作都要分别建模。审批策略说明哪些能力可以由用户临时打开，生命周期策略说明 workspace、snapshot、token 和 artifact 在什么时间清理，交付策略则决定结果能否直接进入默认分支。审计记录应位于沙箱外，避免任务自行修改。

### 4.1 策略表示示例

下面的 YAML 只展示策略应表达的核心边界，具体字段可以按产品调整：

```yaml
profile: enterprise-managed-local
deployment:
  isolation: os-sandbox
  fail_if_unavailable: true
filesystem:
  default: deny
  read_write: [workspace, task_temp]
  read_only: [toolchain]
  deny_read: [ssh_keys, cloud_credentials, browser_profiles]
network:
  mode: restricted
  proxy_required: true
  allow: [approved_package_registries, approved_git_service]
credentials:
  raw_secrets: deny
  git: brokered_short_lived
tools:
  mcp: managed_only
  browser: deny
  computer_use: deny
approvals:
  sandbox_bypass: deny
  broaden_scope: enterprise_reviewer
lifecycle:
  kill_process_tree_on_exit: true
  revoke_credentials_on_exit: true
delivery:
  default_branch_push: deny
  draft_pr: require
```

### 4.2 策略合并规则

最终权限由组织策略、部署环境策略、仓库策略、任务 profile 和临时审批共同决定。临时审批只能打开组织策略明确允许临时打开的能力，不能绕过硬性 deny。

| 字段类型 | 合并规则 |
|---|---|
| allowlist | 取交集；下层只能删，不能加 |
| denylist | 取并集；任一来源拒绝即拒绝 |
| 路径读写范围 | 先规范化，再按操作分别求交集 |
| 网络 mode | `offline < restricted < unrestricted`，取更严格值 |
| TTL、CPU、内存、进程数 | 取更小值 |
| 审批强度、审计级别 | 取更强值 |
| 布尔能力 | deny 优先；只有全部上层允许才可开启 |
| 同一管理层的显式 override | 仅限声明为可覆盖的字段，并保留来源记录 |

不能把所有字段都实现成“高优先级覆盖低优先级”。denylist 应取并集，资源上限取最小值，网络和 sandbox 能力保持单调收紧。[OpenAI Agent Security](https://learn.chatgpt.com/docs/enterprise/agent-security) 也区分 Global 编排约束、Local/Codex Cloud 执行差异和字段级合并行为。harness 应为每类策略写清合并语义，并在任务开始前形成不可变的 effective policy；执行后端无法落实其中任何一项时，任务直接失败。

## 5. 五套策略包

一套 harness 至少需要下面五个 profile。它们共享默认拒绝的基线，再根据执行位置和任务风险增加必要能力，仍遵循上一节的单调收紧规则。

### 5.1 `local-interactive`：个人本地开发

适合可信仓库、开发者在场、需要快速修改和运行测试的场景。它保护工作区外文件，但不把个人电脑当作多租户执行节点。

这套本地策略只给 workspace 和任务临时目录写权限，工具链目录保持只读，`.git` 也默认只读。commit、branch 和 push 交给专门的受控工具。请求项目外路径或网络时，界面应显示规范化后的具体目标；批准只作用于当前操作或当前 session。session 结束时，supervisor 统一回收后台进程。

### 5.2 `enterprise-managed-local`：企业受管本地

适合公司工作站、VDI 或受 MDM/组策略管理的开发环境。它保留本地工具链，但不允许用户关闭 sandbox、绕过代理或把个人配置变成更宽的权限。

企业版本应把 policy bundle 作为签名配置分发，harness 启动时验证签名、版本和有效期。MDM 或受管配置中的 hard deny 高于仓库与用户配置；MCP、plugin 和 hook 只能来自组织清单，远端 MCP 与本地 shell 分开审计。Git 写凭据由 broker 按仓库、用户和 TTL 签发，不能暴露 keychain 或 SSH agent。sandbox backend、WFP/代理或日志上报不可用时停止执行。确实需要 break-glass 时，使用单独身份、双人审批和短 TTL，并产生高优先级审计事件。

### 5.3 `cloud-ephemeral-pr`：厂商托管云端

适合后台任务、并行修复、自动测试和生成 draft PR。它把风险从员工终端移到每任务 VM/microVM，但需要严格管理仓库授权、出口、快照和 artifact。

完整生命周期从身份验证和仓库授权开始。组织安装范围与触发用户权限取交集后，控制面为任务创建独立运行环境和短期仓库身份，签出明确的 ref，再配置出口与凭据代理。任务结束后先扫描 diff 和 artifact，只允许生成签名 commit 或 draft PR；随后撤销身份并销毁 runtime。snapshot、日志和 artifact 使用各自的保留策略，不能用“VM 已销毁”代替数据删除证明。

可以为 setup 和 agent run 使用不同网络策略：setup 阶段只允许固定包仓库并生成依赖快照；agent 阶段默认离线或使用更短的域名列表。不要把 setup 获得的 secret、cookie 或 package-manager token 带入 agent 阶段。

### 5.4 `enterprise-self-hosted`：企业自托管或混合执行

适合代码、构建环境或内网服务不能进入厂商托管 VM 的场景。云端可保留模型与编排，企业 worker 通过出站连接接收工具请求。

控制链应保持两份策略并取交集。编排侧负责用户身份、仓库范围、模型、工具和审批；执行侧负责节点身份、文件、进程、网络和凭据。任何一侧拒绝的能力都不能在另一侧重新打开。

[OpenAI self-hosted sandboxes](https://developers.openai.com/api/docs/guides/agents-api/environments/self-hosted) 使用 executor 主动建立出站 WebSocket，并给 executor 一个只能连接 environment 的受限 key；应用 API key 留在沙箱外。本文采用的连接方式也按这个边界设计：企业网络内运行 worker controller，由它为每个任务创建独立 worker；worker 不监听入站端口，只使用一次性 session identity 向 command gateway 发起 mTLS 长连接。连接消息绑定 `task_id`、`environment_id`、策略哈希和过期时间，gateway 只能在该连接上发送结构化工具请求，不能取得节点登录权限。

worker 收到请求后仍要用企业侧策略重新判定一次。云端允许、企业侧拒绝的请求直接返回 `policy_denied`；策略哈希不匹配或本地执行后端无法落实文件、网络限制时，任务进入失败状态。应用 API key、企业 Git 凭据和内网服务凭据都不进入 worker：Git 写操作交给企业 Git broker，内网请求由本地 egress/secret proxy 注入短期身份。断线只允许在原 `environment_id` 和票据有效期内重连，不能换到另一台保留旧 workspace 的机器继续执行。

自托管把运维责任完整地带回企业。基础镜像、内核和 sandbox runtime 需要持续修补，worker 要按用户或任务做一对一调度或强隔离。内网 allowlist、DNS、代理、流量审计、secret broker、短期身份和日志脱敏也由企业维护。任务结束后，workspace、容器、VM、snapshot、缓存和后台进程必须有统一回收流程；发往云端模型的代码片段、终端输出、diff 和 MCP 结果则要按数据分类做审计。

### 5.5 `quarantine-review`：不可信仓库或供应链检查

适合首次打开外部仓库、漏洞复现、恶意样本初筛或运行未知构建脚本。这是最严格的 profile，不追求完整开发体验。

输入仓库只读挂载，结论写到独立输出卷。需要下载依赖时，在另一个受控构建任务中完成并做内容扫描，再把内容寻址的只读依赖快照交给 quarantine 任务；不要给隔离任务临时打开全网。

## 6. 策略选择

| 场景 | 默认 profile | 可以临时增加的能力 | 不应临时增加的能力 |
|---|---|---|---|
| 个人可信仓库、人在场 | `local-interactive` | 单一外部目录、单一域名、一次 Git 写操作 | 整个家目录、浏览器 profile、永久全网 |
| 企业受管工作站/VDI | `enterprise-managed-local` | 组织预批准的仓库和内部服务 | sandbox bypass、未登记 MCP、原始长期 secret |
| 后台自动修复与 PR | `cloud-ephemeral-pr` | 任务级依赖域名、短期 repo token | 默认分支直推、共享可写卷、跨任务凭据 |
| 私网或数据驻留要求 | `enterprise-self-hosted` | 经企业 broker 的内部服务 | 云端策略单方面放宽 executor、长期共享 workspace |
| 外部或疑似恶意仓库 | `quarantine-review` | 内容寻址的只读依赖快照 | 网络、凭据、宿主 socket、GUI、直接交付 |

## 7. 执行后端设计

策略层描述最终边界，执行后端负责在不同操作系统或云环境中落实这些边界，并报告无法保证的能力。

### 7.1 macOS

macOS 上可把策略编译成 Seatbelt/SBPL，再由受约束的启动器创建整个进程树。read、write 和 deny 必须分开生成：先给出默认拒绝，按规范化路径增加 allow，最后覆盖不可绕过的 deny。workspace 的受保护祖先只得到路径遍历能力，不能顺带获得读取或写入权限。Unix socket、Mach service、Apple Events、keychain 和 GUI 都要单独建模。

域名 allowlist 不宜直接翻译成宽泛 socket 权限。更稳妥的做法是只允许进程连接本地受信代理，让代理解析域名并外连。`sandbox-exec` 能启动进程也不代表 policy 完整，运行前仍需编译和自测允许、拒绝样例。

### 7.2 Linux

Linux 不应只依赖 Landlock 或单一容器。文件边界可由 mount namespace/Bubblewrap 提供只读根、可写 workspace 和敏感路径遮罩，进程边界由 PID namespace、subreaper、`no_new_privs` 与 capability drop 处理，网络则使用 network namespace 或强制代理，seccomp 补充危险 syscall 与 socket family 限制。挂载顺序属于安全逻辑：先建立宽泛只读根，再开放必要目录，最后覆盖敏感子路径；顺序错误可能让父挂载遮住细粒度 deny。

### 7.3 Windows

Windows 不能只靠隐藏盘符或 Job Object。执行进程应使用独立低权限用户或 Restricted Token，workspace 通过显式 ACL 开放，其他宿主目录保持不可达。Low/Untrusted Integrity 配合 `no-write-up` 限制写入，Job Object 负责进程树、资源和退出回收，WFP/Firewall 则按 sandbox SID 或独立用户收紧网络，只放行代理。涉及 GUI 时，还需要独立 desktop/window station，避免通过窗口消息和剪贴板跨边界。ACL、mandatory label、WFP provider 和临时账户都是持久状态，必须有崩溃恢复流程。

可以使用 [Microsoft MXC](https://github.com/microsoft/mxc) 的策略接口统一选择后端，但仍应检查当前 OS 能否落实每个字段。`failIfUnavailable: true` 时，策略编译或后端初始化失败必须阻断任务。

### 7.4 云端 VM/microVM

云端 runtime 应有独立的 tenant/workload identity，不能与控制面服务共用云账户权限。基础镜像和依赖层只读并固定摘要，每个任务使用自己的可写 workspace，不挂载 Docker socket、宿主 kubeconfig 或共享 credential volume。网络默认拒绝 instance metadata、link-local、控制平面和其他租户网段，出口代理按任务身份与目标执行 allowlist。

运行环境销毁只是清理的一部分。runtime、snapshot、conversation、log、artifact 和 secret 要分别设置保留期；runtime 销毁后继续撤销 token，并异步确认 volume 与 snapshot 已清理。

[Cursor Cloud Agent Security](https://cursor.com/docs/cloud-agent/security) 公开了每 agent Firecracker microVM、执行环境与生产服务分属不同 AWS 账户、运行磁盘与会话数据分别留存的做法。[GitHub Copilot cloud sandbox](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes) 则采用彼此隔离的临时 Linux session，并把 session 分成 Active、Stopped 和 Deleted 三种状态。本文将这些做法收敛成下面这套云端后端，而不是停留在产品对照上。

### 7.5 每任务 microVM 云端后端

云端部署分为管理账户和执行账户。管理账户运行 identity、policy resolver、scheduler、approval、audit、artifact 与 Git/secret broker；执行账户只运行 provisioner、command gateway、egress proxy 和任务 runtime。控制面通过受限 provisioning role 创建和销毁任务资源，任务 runtime 没有反向调用云控制面的权限，也不能访问实例 metadata、宿主接口或其他租户网段。

每个任务创建一台 microVM；不具备 microVM 条件时，使用一任务一 VM，而不是退回共享容器。microVM 由固定摘要的只读基础镜像、任务专属加密 workspace volume 和内存临时盘组成。宿主的 Docker socket、kubeconfig、云凭据目录和共享可写缓存均不挂载。依赖缓存只能以内容寻址的只读层提供，并在挂载前校验签名与摘要。任务身份与 volume、网络策略、审计流一一绑定，不允许把另一个任务的 snapshot 直接作为当前任务的可写磁盘。

```yaml
runtime:
  isolation: microvm
  tenancy: one_task
  image: signed_read_only_digest
  workspace: encrypted_per_task_volume
  inbound: deny
  metadata_service: deny
network:
  direct_egress: deny
  allowed_paths: [command_gateway, egress_proxy]
identity:
  runtime: task_scoped_oidc
  git: brokered
  long_lived_secret_in_vm: deny
delivery:
  output: patch_and_artifacts
  direct_default_branch_push: deny
```

runtime 不开放入站端口。sandbox supervisor 使用任务证书向 command gateway 建立出站 mTLS 通道，接收结构化的文件和进程请求；普通进程只能访问 egress proxy。安全组或网络策略只放行这两个目标，因此删除代理环境变量、使用裸 IP 或自行解析 DNS 都不能形成直连。确实需要网页或 GUI 的任务另起 browser microVM，使用不同的 workload identity 和网络策略，避免浏览器 cookie、下载文件与代码执行环境混在一起。

环境准备和 agent 执行分成两个阶段。setup runtime 只连接批准的软件源，使用 build-only secret 下载私有依赖，生成经过扫描和签名的依赖层后销毁。agent runtime 从干净镜像启动，只读挂载该依赖层；setup 阶段的 token、shell history、临时文件和网络权限都不会随 snapshot 进入执行阶段。任务确实需要新增依赖时，由 harness 发起新的 setup job，而不是给正在运行的 agent 临时开放全网。

仓库访问也不直接继承到 runtime。任务开始时，repo authorization 计算“组织安装范围、触发用户权限、仓库策略”的交集，Git broker 据此读取指定 repository 和 ref，再把工作树送入 workspace。执行结束后，runtime 只提交 patch、测试结果和 artifact 清单。artifact service 完成 secret、恶意文件、许可证和路径检查，Git broker 再校验 commit parent，把 patch 应用到任务分支，生成签名 commit 和 draft PR。默认分支 push、merge 和 release 始终留给仓库保护规则及人工 review。

第三方访问使用 secret reference。egress proxy 收到请求后同时校验任务身份、目标 host、端口、方法、路径前缀和剩余 TTL，再从 secrets manager 取得短期凭据并附加到请求；runtime 看到的只有 reference。云资源访问优先签发任务级 OIDC，audience、role、repository、environment 和 TTL 都写进条件。无法通过代理或 typed tool 安全封装的协议，默认不开放。

运行状态固定为下面的状态机。任何失败、取消或超时都跳到 `REVOKING`，先撤销 Git、OIDC 和代理 reference，再停止进程和销毁 runtime；资源回收器确认 volume、network interface 和 snapshot 均不存在后，任务才进入 `GC_VERIFIED`。

```text
AUTHORIZED → PROVISIONING → READY → RUNNING → SCANNING → DELIVERED
      └──────── failure / cancel / timeout ───────────────┘
                              ↓
                         REVOKING → DESTROYED → GC_VERIFIED
```

需要跨设备续跑时，可以增加 `STOPPED`，但它不是“保留整台带凭据的 VM”。停止前必须撤销所有凭据、终止进程并清除内存临时盘，只保存加密 workspace snapshot 和最小恢复元数据；恢复时重新解析策略、创建新的 microVM 并签发新身份。`quarantine-review` 和含高敏数据的任务禁止 snapshot。运行磁盘、snapshot、会话记录、artifact 和审计日志分别配置保留期，删除任务时生成逐项清理状态，不能用“microVM 已销毁”概括所有数据已经删除。

## 8. 文件系统边界

### 8.1 所有工具共用同一个授权库

shell 受 OS sandbox 约束，不代表 harness 内建的 `read_file`、`write_file`、patch、搜索和 Git 工具自动受约束。所有文件工具都要复用同一套路径授权逻辑：先规范化目标并在不追随链接的情况下定位父目录，再确认目标仍位于允许根下，最后按 read、write 或 deny 规则决定是否打开。

授权库既要处理 `..`、盘符/UNC、大小写折叠和 8.3 short name，也要防止 symlink、junction、mount point 与 bind mount 跨出工作区。检查路径与真正打开文件之间不能留下 TOCTOU 竞态。`/proc/<pid>/fd`、Unix socket、named pipe 和宿主服务属于间接访问路径，同样要进入策略。`.git/config`、hooks、credential helper 和 remote URL 也应受保护，避免任务通过修改 Git 配置触发宿主行为。

### 8.2 Git 不直接继承用户环境

clone、fetch、创建分支、推送 commit 和建立 draft PR 应封装为受控能力。harness 校验目标仓库、ref、commit parent 和分支保护，再由 Git broker 使用短期身份执行。任务内的普通 `git` 可以读工作树，但不应自动看到用户的 credential helper、SSH agent 或全局 Git 配置。

## 9. 网络与凭据

### 9.1 强制代理需要内核边界

只设置 `HTTP_PROXY`/`HTTPS_PROXY` 不足以形成安全边界，进程可以忽略环境变量。内核网络边界应保证 sandbox 只能连接受信 proxy；proxy 再按任务身份检查协议、主机、端口和请求方法。DNS 层阻止 private、link-local、metadata 地址与重绑定，HTTP 跳转的每一跳也要重新检查目标。

对包管理器要考虑 registry 跳转、CDN 和校验域名，不能为了兼容直接开放整个互联网。DNS 解析结果、SNI/Host、实际连接 IP 和重定向链应进入审计记录。

### 9.2 Secret broker

[OpenAI Sandbox Security](https://developers.openai.com/api/docs/guides/agents-api/environments/security) 建议把应用 key 留在沙箱外，并用 vault/代理为批准的目标请求附加第三方凭据。sandbox 只拿没有实际权限的 secret reference，请求必须经过 egress proxy。proxy 校验任务、目标、方法、有效期和速率限制后，才从 secrets manager 取得短期或动态凭据并附加到外发请求。日志只保存 reference 和目标，任务结束时同时撤销 reference 与下游 token。

若目标协议不能由代理安全注入凭据，优先把操作做成 host-side typed tool，让 sandbox 只拿结果。直接把 secret 注入环境变量，等同于允许模型生成的代码读取它。

## 10. 工具、MCP、浏览器与审批

### 10.1 工具放在哪里执行

| 工具类型 | 推荐位置 | 原因 |
|---|---|---|
| shell、编译器、测试 | sandbox | 直接运行不可信代码 |
| 内建文件工具 | harness 或 sandbox，但必须共用 path policy | 常见绕过点是主进程内工具不经过 OS sandbox |
| 公共只读文档 MCP | host-side | 不必给 sandbox 网络和 MCP 凭据 |
| 企业数据 MCP | host-side typed call | 在控制面做身份、字段级权限和审计 |
| 本地 stdio MCP | sandbox，且只允许受管清单 | 它本质上是另一个本地进程 |
| 浏览器/computer use | 独立 sandbox/独立身份 | Cookie、剪贴板、页面内容与 GUI 权限远大于 shell |
| Git push/PR | host-side broker | 需要仓库授权、签名、分支保护与外部副作用确认 |

### 10.2 审批票据

审批必须绑定具体对象，不能只存一个布尔值。例如：

```json
{
  "task": "task-123",
  "capability": "network.connect",
  "target": "api.example.com:443",
  "expires": "10 minutes",
  "single_use": true,
  "policy_revision": "org-policy-42",
  "approved_by": "reviewer-id"
}
```

审批记录至少关联任务、能力、目标、有效期、是否单次使用、策略版本和审批人。路径、域名、仓库、命令前缀或外部副作用发生变化时，需要新的审批。harness 不应接受仓库文本中的“用户已经授权”作为审批证据。

## 11. 生命周期与状态机

任务从身份与策略确认开始，随后进入运行环境创建、准备、执行和结果审查。成功任务发布经过检查的 artifact 或 draft PR；失败、取消和超时任务不进入交付阶段。无论以哪种状态结束，都必须先撤销凭据并终止进程树，再销毁运行环境，最后确认 snapshot、volume、日志和 artifact 已按各自的保留策略进入清理流程。

```text
authorize identity and repository
resolve effective policy
provision isolated runtime
run task with scoped tools and credentials
scan diff and artifacts
publish reviewable result
revoke credentials and destroy runtime
verify retention cleanup
```

任务内的退出处理不是唯一清理路径。控制面还要定期扫描孤儿 runtime、过期 token、未挂载 volume、WFP/ACL 残留和超期 snapshot；清理失败进入告警队列并保持可追踪状态。

## 12. 本地、云端与混合模式的差异

| 维度 | 本地/受管本地 | 厂商托管云端 | 企业自托管/混合 |
|---|---|---|---|
| 主要资产 | 员工家目录、登录态、内网、宿主工具 | 仓库副本、云 secret、快照、多租户控制面 | 私网数据、worker 凭据、企业基础设施、发往模型的数据 |
| 隔离单元 | OS 进程、独立用户或本地容器 | 每任务容器/VM/microVM | 企业 VM/container，最好每用户或每 workload |
| 策略来源 | 本机受管配置 + 组织策略 | 组织/团队/环境策略 | 云端编排策略 ∩ 企业 executor 策略 |
| 网络 | 容易继承 VPN、localhost 和内网 | 容易集中管出口，但可能默认联网 | 需要企业 proxy、防火墙和固定控制面出口 |
| 凭据 | 最容易碰到 SSH agent、keychain、CLI token | 适合短期 token、OIDC 和 vault proxy | 企业自建 broker，控制面 key 与 executor key 分离 |
| 持久化 | 工作树、后台进程、ACL/WFP 残留 | runtime、snapshot、conversation、artifact 各自保留 | 企业负责 volume、cache、snapshot 和日志清理 |
| 交付 | 本地 diff、commit、人工 push | branch/draft PR，CI 与 CODEOWNERS | 企业 Git broker、签名 commit、内部 review |

不要假设本机 MDM 会约束云端 VM，也不要假设云端 allowlist 会自动下发到企业 worker。部署模式切换时必须重新求 effective policy，并重新执行允许/拒绝测试。

## 13. 审计事件

审计事件写入沙箱外的 append-only 存储，建议使用下面这组稳定的事件名：

| 事件 | 记录内容 |
|---|---|
| `policy.resolved` | 策略来源、revision、hash、backend capability |
| `approval.requested/granted/denied/expired` | 能力、目标、审批人、TTL |
| `process.started/exited/killed` | 可执行文件摘要、argv 摘要、cwd、父进程 |
| `filesystem.denied` | 操作、规范化路径、匹配规则 |
| `network.allowed/denied` | host、IP、port、method、redirect chain |
| `credential.issued/used/revoked` | reference、scope、下游身份，不记录明文 |
| `artifact.created/scanned/published/deleted` | 摘要、类型、保留期 |
| `runtime.provisioned/hibernated/destroyed/gc_verified` | runtime 与垃圾回收状态 |
| `delivery.commit/pr/merge_requested` | 仓库、ref、签名、reviewer |

日志本身也可能包含源码、命令参数和测试数据，需要字段级脱敏、访问控制、驻留与保留策略。

## 14. 验收测试

验收不按产品页面上的开关做，而是按攻击面跑允许和拒绝样例：

| 范围 | 必须验证的行为 |
|---|---|
| 文件系统 | workspace 内普通读写成功；`${HOME}/.ssh`、云凭据和浏览器 profile 读取失败；symlink/junction、`..`、大小写、UNC 和 bind mount 不能跨界；`.git/config`、hooks、credential helper 受保护；内建文件工具与 shell 对同一路径结论一致；Unix socket、named pipe、Docker socket 和 `/proc/*/fd` 不能绕过策略 |
| 进程与权限 | fork bomb、后台 daemon 和孤儿进程受到资源限制并在结束时被杀；setuid、capability、ptrace、namespace 与设备访问符合 policy；MCP、LSP 和构建工具继承约束；backend 不可用时 fail closed；Windows 的 ACL/WFP、临时用户和 mandatory label 可在崩溃后恢复 |
| 网络 | 允许域名可达，未列域名、裸 IP、私网、metadata 和 link-local 不可达；DNS rebinding、CNAME、redirect 和删除代理变量不能绕过；browser、remote MCP、web search 与 shell 分开测试；禁止 full escalation 时不存在备用直连；代理不可用时阻断而非降级 |
| 凭据 | sandbox 内找不到应用 API key、长期 PAT、SSH agent 和 keychain；placeholder 只能用于批准的 host/path/method；token 的 repo scope、TTL、rate limit 和任务绑定有效；secret 不进入 argv、环境 dump、core dump、日志、artifact 或 snapshot；完成、取消、超时和异常退出都会撤销凭据 |
| 云端与多租户 | 任务之间不能借 volume、cache、snapshot、socket、日志或 artifact 读数据；触发用户不能扩大仓库权限；stop、resume、delete 分别验证状态；VM 销毁不替代 snapshot/artifact 删除；控制面、执行账户和宿主 metadata 不可从任务访问；runtime 销毁、token 撤销和 retention GC 都有可验证状态 |

## 15. 参考资料

- OpenAI：[Sandbox Agents](https://developers.openai.com/api/docs/guides/agents/sandboxes)、[Sandbox Security](https://developers.openai.com/api/docs/guides/agents-api/environments/security)、[OpenAI-hosted sandboxes](https://developers.openai.com/api/docs/guides/agents-api/environments/openai-hosted)、[Self-hosted sandboxes](https://developers.openai.com/api/docs/guides/agents-api/environments/self-hosted)、[Agent Security](https://learn.chatgpt.com/docs/enterprise/agent-security)
- Codex 源码：[Linux sandbox](https://github.com/openai/codex/tree/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox)、[Seatbelt policy](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/sandboxing/src/seatbelt.rs)、[Windows sandbox](https://github.com/openai/codex/tree/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs)
- Anthropic：[Sandbox Runtime](https://github.com/anthropics/sandbox-runtime/tree/e025055f221021582934e666cac1eeb08310e7b1)、[Claude Desktop / Local / Cloud / SSH](https://code.claude.com/docs/en/desktop)、[Claude Code in the cloud](https://code.claude.com/docs/en/claude-code-on-the-web)
- Cursor：[Cloud Agent Security](https://cursor.com/docs/cloud-agent/security)、[Secrets & Network](https://cursor.com/docs/cloud-agent/security-network)、[Self-Hosted Machines](https://cursor.com/docs/cloud-agent/self-hosted)
- GitHub / Microsoft：[Cloud and local sandboxes](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes)、[Enterprise managed settings](https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings)、[MXC](https://github.com/microsoft/mxc)
- NVIDIA：[OpenShell sandbox architecture](https://github.com/NVIDIA/OpenShell/blob/main/architecture/sandbox.md)

