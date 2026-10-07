# Sandbox 实现机制：Coding Agent 如何把权限落到操作系统

## 1. 先看共同的实现骨架

这些实现虽然分别使用 Seatbelt、Bubblewrap、Windows Token、WFP 或 MXC，但源码中的控制流大多可以拆成五层：

```text
产品权限配置
  ↓ 归一化
平台无关权限模型（读、写、拒绝、网络、例外）
  ↓ 按 OS 编译
平台策略（SBPL / bwrap argv / ACL+SID / PSEC JSON）
  ↓ 启动包装
sandbox-exec / bwrap / 受限令牌进程 / wxc-exec
  ↓ 继承
用户命令及其子进程
```

真正的差别不在第一层的 `sandbox=true`，而在后三层：

- 文件策略是“默认只读再开放写目录”，还是“默认不可见再挂载可读目录”；
- 网络是独立 namespace、内核防火墙、Seatbelt socket 规则，还是仅设置代理环境变量；
- 子进程是否天然继承约束，后台进程是否会随父进程退出；
- 符号链接、缺失路径、嵌套允许/拒绝目录和 Unix socket 如何处理；
- 平台原语不可用时是拒绝执行、显式降级，还是静默变弱。

## 2. OpenAI Codex

固定快照：`openai/codex@7f892275e31002f0422477c6219189284560e689`。

### 2.1 macOS：把统一权限模型编译为 SBPL

主入口是 [`create_seatbelt_command_args()`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/sandboxing/src/seatbelt.rs#L871)。输入已经不是简单的 `workspace-write` 字符串，而是：

- `FileSystemSandboxPolicy`：可读根、可写根、不可读路径、受保护元数据；
- `NetworkSandboxPolicy`：是否启用网络；
- managed-network 上下文：代理端口、Unix socket allowlist、本地监听能力；
- 当前工作目录和最终命令。

生成过程如下：

1. 解析不可读根与可写根，并规范化 macOS 顶层别名。
2. 对可写根调用 `build_seatbelt_access_policy(Write, ...)`，生成 `(allow file-write* ...)`；文件用 `literal`，目录用 `subpath`。
3. 对只读子路径和 `.git`、`.agents`、`.codex` 等元数据重新生成 deny 规则。源码还保护这些路径的父目录，防止先重命名祖先目录、再绕开基于路径的 carve-out。
4. 对可读根生成 `(allow file-read* ...)`；全盘可读与严格可读采用不同分支。
5. 网络策略由 `dynamic_network_policy_for_network()` 生成：
   - 网络完全允许时开放 inbound/outbound；
   - 代理强制模式只开放指定 localhost 端口；
   - Unix socket 默认按绝对路径 allowlist 生成 `network-bind` / `network-outbound`；
   - 有代理配置但无法解析有效代理端点时返回空授权，按“无网络许可”处理。
6. 最后追加高优先级 deny：app-server daemon socket、`mach-lookup`、不可读 glob、受保护祖先的 `file-write-unlink`，以及可通过只读文件描述符修改文件的 `F_MAKECOMPRESSED` / `F_TRANSFEREXTENTS`。
7. 形成实际参数：`/usr/bin/sandbox-exec -p <完整策略> -DKEY=PATH ... -- <command>`。路径通过 `-D` 参数传入，而不是把所有路径直接拼进策略字符串。

这里有两个关键防护：

- 可执行文件固定为 `/usr/bin/sandbox-exec`，不从 `PATH` 查找，避免仓库内放置同名程序劫持 launcher。
- 对用户可控路径中的中间符号链接默认拒绝；仅 `CODEX_HOME` 有显式 opt-out。这样“今天批准路径 A，执行前把 A 改为指向敏感目录的链接”的攻击面不会被默认放开。

所以 Codex 的 macOS 实现不是静态 profile，而是“权限模型 → 路径规范化 → 动态 SBPL → 固定系统 launcher”。Seatbelt 仍是同内核隔离，不是 VM。

把 [`create_seatbelt_command_args()`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/sandboxing/src/seatbelt.rs#L871) 压缩后，关键次序大致是这样：

```rust
// 伪代码：保留源码里的策略拼装顺序
let profile = [
    base_policy(),
    allow_reads(fs.readable_roots),
    allow_writes(fs.writable_roots),
    protect_metadata_and_ancestors(fs),
    network_rules(network, managed_proxy),
    final_denies(fs.denied, app_server_socket),
].join("\n");

exec("/usr/bin/sandbox-exec", ["-p", profile, "--", command...]);
```

值得注意的不是字符串怎么拼，而是 `final_denies()` 放在最后。父目录已经开放时，敏感子路径仍可用更具体的 deny 压回去。

### 2.2 Linux：Bubblewrap 外层 + seccomp 内层的二阶段启动

当前入口见 [`linux_run_main.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/src/linux_run_main.rs) 和仓库内的 [Linux sandbox README](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/README.md)。核心流程是：

```text
codex-linux-sandbox（外层）
  ├─ 解析 PermissionProfile
  ├─ 构造 bwrap mount / namespace 参数
  ├─ 启动 bwrap
  └─ 在 bwrap 内重新执行自身 --apply-seccomp-then-exec
       ├─ 验证残留 effective/permitted capability 为 0
       ├─ 如为托管代理，建立 namespace 内代理路由
       ├─ PR_SET_NO_NEW_PRIVS + seccomp
       └─ fork/exec 用户命令，并转发信号、回收子进程
```

必须先运行 Bubblewrap、后设置 `no_new_privs`，因为一些系统的 `bwrap` 依赖 setuid；提前设置会令 Bubblewrap 无法建立 namespace。源码用“重新执行自身”的内层阶段解决这个次序问题。

[`linux_run_main.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/src/linux_run_main.rs) 的二阶段结构可以缩成下面这段：

```rust
// 伪代码
if !args.apply_seccomp_then_exec {
    exec_bwrap(reexec_self("--apply-seccomp-then-exec", command));
}

assert!(effective_capabilities().is_empty());
prctl(PR_SET_NO_NEW_PRIVS, 1);
install_seccomp(permission_profile);
exec(command);
```

这不是为了绕一层，而是把“创建 namespace 所需的权限”和“最终命令不能再提权”放在正确的时间点。

#### 文件系统视图

[`bwrap.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/src/bwrap.rs#L408) 中的挂载顺序具有安全语义：

1. 全盘可读时先 `--ro-bind / /`；严格可读时从 `--tmpfs /` 开始，只把批准的可读根以 `--ro-bind` 叠加进去。
2. 用 `--dev /dev` 创建最小设备树，不把宿主 `/dev` 整体暴露进去；必要时单独恢复 `/dev/shm`。
3. 对可写根执行 `--bind <root> <root>`。
4. 在可写根内部，再把 `.git`、`.agents`、`.codex` 及显式只读子路径用 `--ro-bind` 覆盖回只读。
5. 不可读目录以只读 tmpfs 遮蔽，不可读文件通常用 `/dev/null` 或合成挂载目标遮蔽。
6. 重叠规则按路径特异性排序，因此可以表达“父目录可写、子目录不可见、孙目录重新可写”。

不可读 glob 在进入沙箱前展开：优先执行 `rg --files --hidden --no-ignore --glob ...`，没有 `rg` 时用内部 walker；其他扫描失败会中止构造，而不是忽略规则继续运行。对于不存在或路径中含符号链接的受保护目标，会在首个危险组件上挂 `/dev/null`，避免命令在可写父目录下新建该路径后穿透策略。

#### namespace 与进程生命周期

常规参数包括：

- `--unshare-user`：显式新建 user namespace；
- `--unshare-pid`：默认新建 PID namespace；
- `--unshare-ipc`：隔离 SysV/POSIX IPC；
- `--unshare-net`：在断网或代理专用模式启用；
- `--proc /proc`：在新 PID namespace 中挂新 procfs；若宿主容器禁止该挂载，会先做探测并回退到继承 `/proc`，但保留 PID 隔离；
- `--new-session`、`--die-with-parent`、`--cap-drop ALL`：隔离会话、随父进程退出并移除 capability。

WSL2 走同一路线；WSL1 因缺少所需 user namespace 被提前拒绝。受限策略还会遮蔽 `/run/WSL` 和 WSLg 的重复发行版根，避免从 Linux 沙箱调用不受限的 Windows 进程或通过重复根恢复被遮蔽的路径。

#### 网络与 seccomp

`BwrapNetworkMode` 有三种：

- `FullAccess`：继承宿主 network namespace；
- `Isolated`：`--unshare-net`，无外部出口；
- `ProxyOnly`：同样 `--unshare-net`，但 helper 建立 TCP → Unix domain socket → TCP 的受控桥，工具只能到配置的代理端点。

内层 [`landlock.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/src/landlock.rs#L35) 实际承担的是 `no_new_privs` 和 seccomp：

- 断网模式拒绝 `connect`、`accept`、`bind`、`listen`、`sendto` 等，并让 `socket()` / `socketpair()` 只允许 `AF_UNIX`；
- 代理路由模式允许隔离 namespace 内的 IPv4/IPv6 socket，但限制其他 address family，Unix socket 需另行授权；
- 始终阻止可绕开普通 `socket()` 检查创建特殊 socket 的 `io_uring` 系统调用；
- 限制 VM socket，尤其防止 WSL2 通过宿主桥越界；
- 需要时拒绝 `ptrace` 与 `process_vm_readv/writev`。

Landlock 代码仍保留为 legacy 路径，但文件系统受限策略会拒绝使用它，因为它不能隔离 app-server Unix socket，也不能表达新的严格读策略。当前主路径的文件边界是 Bubblewrap mount namespace，不应再概括为“Landlock + seccomp”。

### 2.3 Windows：Restricted Token 与独立账户是两条不同强度的路径

配置层 [`windows_sandbox_config.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/core/src/config/windows_sandbox_config.rs#L20) 将 `elevated`、`unelevated`、`mxc` 转为后端：前两者都进入 Codex 自己的 Windows Restricted Token 实现，但 setup level 不同；`mxc` 进入 `WindowsMxc`。本地 rollout 还可用 `prefer_mxc` 选择 MXC，远端继承的是原始配置而不是本地试验选择。

#### Unelevated / legacy 路线

[`token.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/token.rs#L500) 调用 `CreateRestrictedToken`，flags 为：

- `DISABLE_MAX_PRIVILEGE`：移除最大权限；
- `LUA_TOKEN`：构造类似 UAC 过滤后的 token；
- `WRITE_RESTRICTED`：写访问还必须通过 restricting SID 检查。

restricting SID 列表包含文件能力 SID、额外限制 SID、logon SID 与 Everyone。随后重写 token default DACL，只让本次 logon session 对新建内核对象有完整访问，并只恢复 `SeChangeNotifyPrivilege` 以保证正常路径遍历。

对应的 Win32 调用骨架很短，但语义在 flags 和 SID 列表里：

```rust
// 按 token.rs 调用形状整理
let flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED;
CreateRestrictedToken(
    process_token,
    flags,
    sids_to_disable,
    privileges_to_delete,
    restricting_sids,
    &mut restricted_token,
)?;
```

`WRITE_RESTRICTED` 使写入同时通过普通 DACL 和 restricting SID 两次检查；它并不能独立表达“允许读 A、拒绝读 A/b”。这也是 legacy 后端拒绝严格 `deny-read` 的原因。

[`legacy.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/unified_exec/backends/legacy.rs#L340) 显式拒绝两个它无法可靠表达的功能：严格只读访问和 `deny-read` 覆盖。原因是 `WRITE_RESTRICTED` token 的 restricting SID 只对写入形成权威检查。它通过 capability SID + ACL 表达写根，再把进程放入 Job Object 管理生命周期。这说明兼容后端不是 elevated 后端的等价实现。

#### Elevated 路线

安装阶段创建专门的 offline/online 本地普通用户和本地组。源码在 [`sandbox_users.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/setup_provisioning/sandbox_users.rs#L66) 中：

1. 创建 sandbox users 本地组；
2. 为 offline 和 online 用户生成随机密码；
3. 用 `NetUserAdd` 创建普通本地用户，或用 `NetUserSetInfo` 更新密码；
4. 把密码加密保存（调用 DPAPI），供 runner 以对应身份登录；
5. 按该用户 SID 配置 ACL 与系统网络规则。

运行时 [`elevated.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/unified_exec/backends/elevated.rs#L95) 先把 PermissionProfile 解析为 Windows 权限，准备独立 desktop、ACL、环境和代理限制，再通过 runner transport 在 sandbox 账户的 logon session 中启动命令。单独账户使 agent 进程不再与真实用户共享同一个用户 SID，进程对象、计划任务和用户级资源边界更清晰。

网络限制不是简单清空代理变量。setup 代码通过 Windows Firewall COM API 按 offline 用户 SID 写规则：

- 非 loopback 的 IPv4/IPv6 inbound/outbound 全阻断；
- loopback UDP 阻断；
- loopback TCP 先整体阻断，再仅保留代理端口集合；
- 策略更新按“先安装更严规则，再缩小”执行，失败时倾向 fail closed。

仓库还包含 [`wfp.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/wfp.rs) 的持久 WFP provider/sublayer 与按用户安全描述符匹配的 block filter。当前该文件的静态规则重点阻止 ICMP、DNS 53/853 和 SMB 139/445；它不能单独代表 elevated 路线的全部断网语义，完整规则还要结合 setup firewall 代码判断。

#### MXC 路线

Codex 只在配置和调用处选择 `WindowsMxc`；真正的 ProcessContainer/PSEC 实现属于 MXC。它与 Codex 自己的独立账户后端是并列后端，不是 Restricted Token 内部的一个参数。

## 3. Anthropic Sandbox Runtime（SRT）与 Claude Code

固定快照：`anthropics/sandbox-runtime@e025055f221021582934e666cac1eeb08310e7b1`。

SRT 是可独立使用的策略编译与 launcher。Claude Code 的产品支持范围和 SRT 仓库中已经存在的后端必须分开陈述。

### 3.1 管理层：一份配置，按平台走不同 wrapper

[`sandbox-manager.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/sandbox-manager.ts) 负责：

- 解析 `allowRead` / `denyRead` / `allowWrite` / `denyWrite`；
- 启动 HTTP、SOCKS 或 mux proxy；
- 生成代理认证 token 与环境变量；
- 屏蔽凭据环境变量和敏感文件；
- 按平台调用 `wrapCommandWithSandboxMacOS`、`wrapCommandWithSandboxLinux` 或 Windows 的 argv wrapper；
- 记录 violation，并在 reset 时清理 proxy、临时文件和 Windows ACE。

Windows 强制使用 `wrapWithSandboxArgv()` 并要求调用者 `spawn(..., {shell:false})`，避免不可信命令先被宿主 shell 解析。macOS/Linux 才返回外层 shell 字符串。

### 3.2 macOS：Seatbelt 只放行代理端口，域名判定在代理中

[`macos-sandbox-utils.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/macos-sandbox-utils.ts) 动态构造 SBPL，并用 `sandbox-exec` 启动：

1. 根据 read 配置生成读 allow/deny。读策略支持“先拒绝大区域，再允许工作区”，也会为位于可写根内的不可读路径补充 unlink/rename deny。
2. 写入默认拒绝，只为明确 `allowWrite` 根生成 `file-write*`。
3. 代理运行时，只开放指定 localhost HTTP/SOCKS 端口；未授权 direct socket 被 Seatbelt 拦截。
4. HTTP/HTTPS 与其他 TCP 的域名 allowlist 实际由 host proxy 判定。内核层保证“只能去代理端口”，代理层保证“代理只转发允许域名”。
5. 根据配置开放 PTY、Mach service、Apple Events 或 Unix socket；这些都是显式扩大边界的选项。
6. 把凭据 mask、CA trust、Java agent 和 Git safe-directory 注入命令环境后，再调用用户 shell。

因此“Seatbelt 支持域名白名单”的准确含义是：Seatbelt 对 socket 端点做粗粒度强制，域名语义由受信代理完成。

可以把 macOS 这一层理解为两次判定：

```text
connect(127.0.0.1:代理端口)
  ├─ Seatbelt：端口不在 allowlist → 拒绝
  └─ 代理：目标域名不在 allowlist → 拒绝转发
```

环境变量只告诉常规客户端“代理在哪里”；真正防止绕过的是 Seatbelt 不允许它连接其他地址。

### 3.3 Linux：network namespace + 双向 socat 桥 + 内层 seccomp

[`linux-sandbox-utils.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/linux-sandbox-utils.ts) 的网络路径是：

```text
沙箱内程序
  → localhost:3128 / localhost:1080
  → 沙箱内 socat
  → bind-mounted Unix socket
  → 宿主 socat
  → 宿主 HTTP/SOCKS proxy
  → 允许的目标
```

外层 `bwrap --unshare-net` 令沙箱没有宿主网络；宿主侧 socat 监听临时 Unix socket并转发到 proxy，沙箱侧 socat 再把该 socket 映射为工具熟悉的 localhost TCP 端口。即使程序清掉 `HTTP_PROXY` 并尝试直连，也只能看到隔离 network namespace。

文件策略由 Bubblewrap bind mount 表达：默认根只读，可写根重新 bind，可读/不可读 carve-out 以只读挂载或遮蔽挂载覆盖。构造器还处理缺失路径、符号链接、一个目标只能有一个最终 mount、强制拒绝路径和 `.env` glob 展开。

SRT 对 Unix socket 的额外防护比“只 unshare net”更复杂：

1. 外层 Bubblewrap 建立文件、网络和 PID namespace；
2. socat helper 先在 namespace 中启动，因为它们需要 Unix socket；
3. `apply-seccomp` 再创建嵌套 user/PID/mount namespace，并重新挂载 `/proc`；
4. 内层 PID 1 设置 non-dumpable、负责回收；
5. fork 后给真正用户命令安装 seccomp，阻止新建 `AF_UNIX` socket；
6. 用户命令在 `/proc` 中看不到未安装该 filter 的 socat/bwrap helper，降低通过 ptrace 或 `/proc/<pid>/mem` 操纵 helper 的机会。

若内层 namespace 创建失败，helper 中止而不是在没有这层保护时继续。配置也提供 `enableWeakerNestedSandbox` 等显式兼容开关，因此评估时要检查该开关是否被启用。

按 [`linux-sandbox-utils.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/linux-sandbox-utils.ts) 的职责拆开后，启动器近似这样：

```ts
// 伪代码
const outer = bwrap([
  '--unshare-net', '--unshare-pid',
  ...readonlyMounts, ...writableMounts, ...maskedPaths,
  hostToSandboxUnixSocket,
]);

outer.start(socatHelpers);
outer.exec(applySeccomp({ denyAddressFamily: 'AF_UNIX' }, userCommand));
```

先启动 `socat`、后禁止用户命令新建 Unix socket 是刻意安排的。顺序倒过来，代理 helper 自己也无法工作；不做内层过滤，用户命令又可能直接利用已挂入的 socket。

### 3.4 Windows：独立用户 + WFP 出口栅栏 + 临时 ACE

[`windows-sandbox-utils.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/windows-sandbox-utils.ts) 是 `srt-win.exe` 的 JS wrapper。其注释给出的真实启动链是：

```text
JS broker
  → CreateProcessWithLogonW(srt-sandbox runner)
  → runner 创建 restricted-token child
  → 用户命令
```

安装阶段创建 `srt-sandbox` 本地账户，并按该账户 SID 安装机器级 WFP `ALE_AUTH_CONNECT` 规则：默认阻断所有 outbound，只允许配置的 loopback proxy 端口范围。会话初始化时还做行为探测：在允许端口范围之外开一个本地监听端口，让 sandbox 用户尝试连接；如果连接成功，说明 WFP 栅栏失效，初始化失败关闭，而不是假设安装状态仍然有效。

文件访问通过显式 ACE 实现：

- `acl grant` 给 allowRead/allowWrite 路径添加 `(OI)(CI)` ALLOW ACE；
- `acl stamp` 给 denyRead/denyWrite 目标添加 DENY ACE，并在父目录增加 `FILE_DELETE_CHILD` deny，防止通过删除/重命名父项绕过；
- ACE 以 holder PID 引用计数，多会话共享时不会在一个会话 reset 时误删另一个会话仍依赖的 ACE；
- `acl restore/revoke` 在引用计数归零时移除，失败会保留逐路径结果供日志与后续清理。

子进程使用 sandbox 用户的新 profile 环境，而不是继承真实用户完整环境；wrapper 只通过 `--env` 传 PATH、代理、CA、mask sentinel 和 Git 配置。最终 argv 要求 `shell:false`，内部 shell 在 sandbox 身份下才解析用户命令。

Windows wrapper 的边界也可以用几行伪代码说明：

```ts
// 宿主 Node.js 进程只传 argv，不解析用户 shell 字符串
spawn(srtWinExe, ['run', '--env', safeEnv, '--', ...command], {
  shell: false,
});
// srt-win: CreateProcessWithLogonW(sandboxUser) → restricted-token child
```

`shell:false` 防的是命令先在宿主身份下被 `cmd.exe` 展开。真正需要的 shell 会在 sandbox 用户进程中启动。

这条原生 Windows 路线已经存在于 SRT 固定提交，但不自动证明当时 Claude Code 产品已经把它作为受支持平台发布。

## 4. Gemini CLI：旧的整进程容器包装与新的逐命令 Manager 并存

固定快照：`google-gemini/gemini-cli@fb972b2f87fe7d5b06d37eac711490162d98de2c`。

### 4.1 两套入口不能混为一个默认行为

旧入口 [`sandboxConfig.ts`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/cli/src/config/sandboxConfig.ts) 选择整个 CLI 的包装器：`docker`、`podman`、`sandbox-exec`、`runsc`、`lxc`、`windows-native`。自动探测顺序在 macOS 优先 Seatbelt；容器只有显式启用时才选；`runsc` 必须显式指定且本质是 Docker 的 `--runtime=runsc`。

新入口 [`createSandboxManager()`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/services/sandboxManagerFactory.ts#L22) 则在 `sandbox.enabled` 时按 `os.platform()` 返回 Windows、Linux 或 macOS manager，否则返回 `NoopSandboxManager`。它是“每次工具命令先 `prepareCommand()`”的架构。

源码同时存在这两套路径，只能说明迁移/并存，不能从某个 manager 的存在推出普通用户的 `--sandbox` 一定默认进入它。

### 4.2 Linux Manager：Bubblewrap + 只拒绝 ptrace 的 seccomp BPF

[`LinuxSandboxManager.prepareCommand()`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/linux/LinuxSandboxManager.ts#L210) 先合并模式配置、持久批准与单次请求权限，再解析路径和清理环境。

[`buildBwrapArgs()`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/linux/bwrapArgsBuilder.ts#L33) 生成：

- `--unshare-all --new-session --die-with-parent`；
- 若允许网络，再用 `--share-net` 撤销 `--unshare-all` 的网络隔离；
- `--ro-bind / /`、最小 `/dev`、新 `/proc`、独立 `/tmp`；
- 工作区按 readonly/yolo/批准结果选择 `--ro-bind-try` 或 `--bind-try`；
- `.git` 等 governance 文件重新只读，除非明确允许；
- forbidden 目录用只读 tmpfs，文件用 `/dev/null`；
- 深度 3 扫描 `.env`/`.env.*`，用 mode 000 的空文件 bind 覆盖。

mount 按目标路径长度排序，保证父挂载先于子挂载。bwrap 参数写入 mode 0600 的 NUL 分隔临时文件，再用 `bwrap --args 8` 从 fd 8 读取，避免超长命令行和 shell quoting 问题。

manager 另在 fd 9 传 seccomp BPF。该 filter 的实际内容很窄：校验 CPU architecture，不匹配则 kill；对 `ptrace` 返回 `EPERM`；其余 syscall 允许。因此不能把它描述为 Codex/SRT 那种完整网络 socket filter。断网主要来自 network namespace。

等价逻辑只有三条分支：

```c
// 按 bwrapArgsBuilder.ts 生成的 BPF 逻辑改写
if (seccomp_data.arch != NATIVE_ARCH) return KILL_PROCESS;
if (seccomp_data.nr == __NR_ptrace) return ERRNO(EPERM);
return ALLOW;
```

这里没有 `socket`、`connect` 或 `sendto` 规则。看到“启用了 seccomp”不能直接推断网络由 seccomp 管。

### 4.3 macOS Manager：严格 allowlist profile

[`MacOsSandboxManager`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/macos/MacOsSandboxManager.ts#L46) 把 profile 写到 mode 0600 临时文件，再运行：

```text
/usr/bin/sandbox-exec -f <profile> -- <command> <args...>
```

[`buildSeatbeltProfile()`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/macos/seatbeltArgsBuilder.ts#L85) 的策略是：

- 允许读取工作区原路径与 realpath；按批准结果决定是否允许写；
- 允许临时目录、Node 根目录、PATH 中工具目录的读取；
- `allowedPaths` 和 include dirs 当前被赋予读写；
- governance 文件在更宽的工作区允许之后追加 deny；
- `.env` 用锚定到工作区/允许根的正则 deny；
- 额外 read/write 逐条编译为 literal 或 subpath；
- 最后追加 forbidden deny；
- 只有 `networkAccess=true` 才拼入网络 profile。

这里的策略次序本身是实现的一部分，因为后追加的精细 deny 用来覆盖更早的宽泛 allow。

### 4.4 Windows Manager：Low Integrity、ACL 与 Job Object

TypeScript manager 先生成两个 manifest：

- forbidden：敏感/禁止路径；
- allowed：工作区和额外可写根。

它拒绝将 UNC 路径加入 allow manifest，避免凭据泄漏或把网络路径当本地写根；不存在的额外路径只有位于既有允许根下时才接受。随后启动 C# helper `GeminiSandbox.exe <network:0|1> <cwd> ...`。

[`GeminiSandbox.cs`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/windows/GeminiSandbox.cs#L247) 的步骤是：

1. 对 forbidden 目标给 Low Integrity SID `S-1-16-4096` 添加 `FullControl DENY`。
2. 对 allowed 目标添加 Low Integrity SID 的 `Modify ALLOW`，并写 mandatory label `S:(ML;...;NW;;;LW)`，让低完整性进程可写。
3. `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`。
4. `SetTokenInformation(TokenIntegrityLevel)` 把进程 token 降为 Low Integrity。
5. 创建 Job Object，设置 `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION`。
6. 以 suspended 状态 `CreateProcessAsUser`，先 `AssignProcessToJobObject`，再 `ResumeThread`，避免进程在被纳入 Job 前运行。

关键调用顺序如下；`CREATE_SUSPENDED` 用来关闭“子进程先跑一小段、随后才进 Job”的竞态窗口：

```csharp
var token = CreateRestrictedToken(DISABLE_MAX_PRIVILEGE);
SetTokenInformation(token, TokenIntegrityLevel, LowIntegritySid);
var job = CreateJobObject(KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION);

var child = CreateProcessAsUser(token, CREATE_SUSPENDED);
AssignProcessToJobObject(job, child.Process);
ResumeThread(child.Thread);
```

两个实现限制很重要：

- ACL/mandatory label 是写在宿主文件上的持久元数据；helper 此处没有对本次修改做完整回滚。源码文档因此提醒完整性标签可能在会话后保留。
- `networkAccess=false` 不是 WFP block，而是设置 Job Object `MaxBandwidth=1`。设置失败只打印 warning 并继续。因此静态代码只能证明“尝试把网络限速到极低”，不能证明严格断网。

## 5. Cursor：公开资料说明了后端，但没有可复原的完整源码调用链

[Cursor Run Modes](https://cursor.com/docs/agent/security/run-modes) 说明了用户实际能配置的边界，[Cursor 的工程文章](https://cursor.com/blog/agent-sandboxing) 则给出各平台的实现选择：

- **macOS：** 使用 `sandbox-exec` 调用 Seatbelt。SBPL profile 在运行时按 workspace、管理员策略和 `.cursorignore` 生成，并作用于整个子进程树。文章列出的保护目标包括 `.git/config`、`.git/hooks`、`.vscode`、`.cursorignore` 以及部分 `.cursor` 配置。
- **Linux：** 以 Landlock 限制文件系统、seccomp 拦截危险 syscall，并通过 overlay filesystem 把被忽略的文件覆盖为不可读、不可写。当前产品文档还暴露 `CURSOR_SANDBOX_LANDLOCK_STATUS`：`fully_enforced` 表示 Landlock 路线，`bubblewrap` 表示兼容回退。沙箱会创建 user namespace，进程在 namespace 内可能显示为 UID 0；真实宿主 UID/GID 通过 `CURSOR_ORIG_UID`、`CURSOR_ORIG_GID` 传入。
- **Windows：** 工程文章说明当前将 Linux 沙箱运行在 WSL2 内，并非一套原生 Windows Seatbelt/Landlock 等价实现。

`sandbox.json` 控制网络、附加可读/可写路径、临时目录和共享构建缓存；workspace 级配置优先于用户级配置，但不能削弱团队策略和 Cursor 的硬编码保护。终端命令默认可读写 workspace，网络先阻断，再按所选网络模式和域名列表放行。Read Access 的默认值仍是 `System`；切到 `Workspace` 后，项目外读取才需要审批或命中 read allowlist。

沙箱只覆盖能够进入该路径的 shell 命令。Auto-review 的 allowlist 命令、Fetch、MCP，以及因限制失败后获准在沙箱外重跑的命令，都需要单独看待；官方文档也明确说分类器不是安全边界。

Cursor 没有公开与某个产品构建一一对应的完整沙箱仓库，因此仍无法独立复原 mount 的精确顺序、完整 seccomp 规则、符号链接竞态处理和全部降级分支。这里不套用 Codex 或 SRT 的内部细节。

## 6. VS Code、MXC 与 GitHub Copilot CLI

### 6.1 VS Code：先在引擎层生成配置，再按 OS 选择 runtime

固定快照：`microsoft/vscode@2dca67a07aba894351849f39d337a921758722e8`。

[`TerminalSandboxEngine`](https://github.com/microsoft/vscode/blob/2dca67a07aba894351849f39d337a921758722e8/src/vs/platform/sandbox/common/terminalSandboxEngine.ts#L117) 先收集：

- 工作区/session 写根；
- 宿主必须可读的 runtime 路径；
- 用户配置的 allowRead/allowWrite/denyRead/denyWrite；
- 命令级 read allowlist；
- 允许/拒绝域名与本次命令是否请求网络。

macOS/Linux 会生成 SRT JSON：网络允许时明确 `enabled:false`，否则写域名 allow/deny；文件系统四类路径原样传给 `@vscode/sandbox-runtime`。实际包装命令是 Node/Electron 执行：

```text
@vscode/sandbox-runtime/dist/cli.js --settings <json> -c <command>
```

并把 `rg` 所在目录加入 PATH，把独立 temp dir 传为 `TMPDIR`/`CLAUDE_TMPDIR`。因此 macOS/Linux 的最终 OS 机制复用 SRT：macOS Seatbelt、Linux Bubblewrap + proxy。

Windows 不走这个 CLI，而由 [`WindowsMxcTerminalSandboxRuntime`](https://github.com/microsoft/vscode/blob/2dca67a07aba894351849f39d337a921758722e8/src/vs/platform/sandbox/common/terminalSandboxMxcRuntime.ts#L47) 把路径转为 MXC policy：

- `readwritePaths`、`readonlyPaths`、`deniedPaths`；
- UI 允许窗口、禁止 clipboard、禁止 input injection；
- 网络只有 `allowOutbound: true/false`，没有逐域名策略；
- 构造 payload 后写 JSON，再用 `wxc-exec.exe <config>` 启动。

源码中 `_updateDenyReadPathsWithHome()` 对 Windows 仍留有“deny read on home directory”的 TODO，所以不能假设与 macOS/Linux 一样自动拒绝整个 home。

### 6.2 MXC ProcessContainer：JSON policy → PSEC → Windows 安全环境

固定快照：`microsoft/mxc@2044eac07ad819319e924ae3d3a5f427a79c9afb`。

MXC 对 BaseContainer 的公开调用链在 [`guide.md`](https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/docs/process-container/guide.md#L22) 中写得很明确：

```text
SandboxPolicy
  → SDK createConfigFromPolicy()
  → ContainerConfig JSON
  → wxc-exec 解析
  → BaseContainerRunner 编码 PSEC FlatBuffer
  → processmodel.dll!CreateProcessSecurityEnvironment
  → PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT
  → CreateProcessW
```

PSEC FlatBuffer 是 MXC 与 Windows OS enforcement 的契约。源码 [`secenv.rs`](https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/src/backends/process_container/common/src/secenv.rs) 从 System32 动态加载 `processmodel.dll`，解析 `Create/Query/CloseProcessSecurityEnvironment`，检查所需 feature 是否存在；再用 `UpdateProcThreadAttribute` 把安全环境 handle 放进扩展 startup info。普通 `CreateProcessW` 因带该属性而在 OS 安全环境中创建。

落到 Win32 API 后，PSEC 的关键不是另起一种进程 API，而是给普通进程创建附加一个安全环境属性：

```rust
// 伪代码：对应 secenv.rs 的 FFI 调用顺序
let secenv = CreateProcessSecurityEnvironment(psec_flatbuffer)?;
UpdateProcThreadAttribute(
    startup_info.attribute_list,
    PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT,
    secenv,
)?;
CreateProcessW(command, EXTENDED_STARTUPINFO_PRESENT, startup_info)?;
```

如果 `processmodel.dll` 缺少请求的 feature，前面的 capability probe 应当换后端或报错，而不是带着不完整属性继续启动。

后端选择按“当前 OS 能否完整表达本次请求”，而不是只看 schema 版本。如果 BaseContainer 不能表达某项要求，应选择能完整执行的 AppContainer tier 或报错，不能静默丢掉限制。兼容路径可能需要临时修改 DACL；dispatcher 会记录应用失败、回滚和孤儿状态，后续启动再尝试恢复。

网络在支持的 BaseContainer 上由按 container SID 的 WFP 规则实现：默认拒绝，再按 IP/range、protocol、port 放行；如使用代理，还配置 per-container WinHTTP proxy 与代理环境变量，并让 WFP 只放行代理 loopback 端点。环境变量负责兼容不同网络库，WFP 才是禁止绕过代理的边界。

但是该固定提交 README 明确警告：MXC 是 early preview，SDK 生成的某些策略仍过宽，当前 profile 不应被当作安全边界。这个仓库级声明优先于“已经调用了 PSEC/WFP”带来的直觉。

### 6.3 GitHub Copilot CLI

[GitHub Copilot 沙箱文档](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes) 可以确认 CLI 的跨平台后端：macOS 使用 Seatbelt，Linux 使用 Bubblewrap，Windows 使用 MXC ProcessContainer 的 BaseContainer tier。Windows 不采用 MXC 的 AppContainer fallback；如果系统不能提供 BaseContainer，CLI 会报告不支持，而不是换到更弱的 tier。

同一文档还区分了 shell/MCP/LSP 与 CLI 内建文件工具：前一类可以进入 OS sandbox，内建文件工具在 CLI 进程内执行，只能自行检查 policy。远端 MCP 也不在本地 sandbox 内。结合 [MXC 仓库](https://github.com/microsoft/mxc) 可以解释 Windows 的底层机制，但 Copilot CLI 自身没有提供可对应本次版本的完整实现仓库，因此不能独立还原 CLI 怎样把每项设置转换为 MXC policy。

## 7. OpenCode：权限提示直接执行宿主操作，没有 OS enforcement 层

固定快照：`anomalyco/opencode@907b3bc518fa48e90e8ec24dd327d13eee71c36c`。

[`SECURITY.md`](https://github.com/anomalyco/opencode/blob/907b3bc518fa48e90e8ec24dd327d13eee71c36c/SECURITY.md#L9) 给出的威胁模型已经足够明确：permission system 是让用户知情的 UX，agent 获得同意后仍在真实用户权限下执行 shell、文件和 web 操作。实现链是：

```text
agent 请求工具
  → permission 决定是否提示/允许
  → 允许后直接调用宿主 shell / 文件 API
```

这里不存在“策略编译 → OS sandbox launcher”两层。子进程拿到的是宿主用户本来的 token、文件权限与网络能力。真正隔离只能把 OpenCode 整体放入 Docker/VM 等外部边界。

## 8. OpenHands：Workspace 是执行后端抽象，是否隔离取决于实例类型

固定快照：`OpenHands/software-agent-sdk@de30ec0111fc1c1435a1639d4ec27aead297d5b8`。

### 8.1 LocalWorkspace

[`LocalWorkspace.execute_command()`](https://github.com/OpenHands/software-agent-sdk/blob/de30ec0111fc1c1435a1639d4ec27aead297d5b8/openhands-sdk/openhands/sdk/workspace/local.py#L47) 直接调用共享 `execute_command()`，cwd 默认为 `working_dir`。文件上传/下载直接用 `shutil.copy2`。`working_dir` 是默认目录，不是 capability boundary：命令仍可使用绝对路径访问宿主中该用户可访问的其他位置。

### 8.2 DockerWorkspace

[`DockerWorkspace`](https://github.com/OpenHands/software-agent-sdk/blob/de30ec0111fc1c1435a1639d4ec27aead297d5b8/openhands-workspace/openhands/workspace/docker/workspace.py#L53) 的控制流是：

1. 检查 Docker daemon；
2. 从指定镜像启动 agent server；
3. `docker run -d --rm --platform ...`；
4. 只把 server 端口发布到 `127.0.0.1`；
5. host 通过 HTTP API 执行 workspace 操作；
6. context 结束时停止容器，`--rm` 删除容器层。

它不会自动挂载整个宿主工作区；额外宿主访问来自显式 `volumes`，每项直接转换为 `-v`。`forward_env` 同样是明确的数据入口。网络默认采用 Docker 默认网络，只有设置 `network` 时才用指定网络；因此“在容器中”不等于“默认断网”。代码也没有自动追加 `--read-only`、cap drop、seccomp profile 或 `no-new-privileges`，这些安全属性取决于 Docker 默认值和调用者额外配置。

[`DockerWorkspace`](https://github.com/OpenHands/software-agent-sdk/blob/de30ec0111fc1c1435a1639d4ec27aead297d5b8/openhands-workspace/openhands/workspace/docker/workspace.py#L53) 最终构造的命令可以抽象成：

```python
args = [
    "docker", "run", "-d", "--rm",
    "-p", f"127.0.0.1:{host_port}:8000",
    *volume_args,
    *forwarded_env_args,
    image,
]
```

这里最有信息量的是“没有出现什么”：没有默认 `--network none`、`--read-only`、`--cap-drop ALL`。容器提供的是一个后端边界，边界强度仍由调用参数决定。

同一仓库还提供 Apptainer、cloud、remote API 与 agent-sandbox backend。以产品名笼统标成“Docker sandbox”会隐藏真实边界。

## 9. Hermes Agent：可插拔执行后端与整进程包裹

补充核查点：`NousResearch/hermes-agent` 的 `main`，读取于 2026-10-07。本节链接未固定提交；Hermes 更新较快，复查或上线前应把链接换成实际部署版本的 commit。

### 9.1 默认 local，后端工厂决定命令最终在哪里执行

[`config_defaults.py`](https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/config_defaults.py#L291) 把 `terminal.backend` 的默认值设为 `local`。这时 Hermes 仍有审批模式、敏感路径检查和安全写入根目录，但命令本身使用宿主用户的文件与网络权限；这些工具层检查不是 OS sandbox。

非本地模式的关键不是在每个工具里各写一套 Docker 调用，而是先按任务取得共享环境，再让工具通过这个环境执行：

```python
config = get_environment_config()
env = active_environments.get(task_id)

if env is None:
    env = create_environment(backend=config.backend, config=config)
    active_environments[task_id] = env

terminal_result = env.execute(command)
file_ops = ShellFileOperations(env)

if backend != "local":
    code_result = env.execute(build_remote_script(code, language))
```

这段是对 [`file_tools.py`](https://github.com/NousResearch/hermes-agent/blob/main/tools/file_tools.py)、[`code_execution_tool.py`](https://github.com/NousResearch/hermes-agent/blob/main/tools/code_execution_tool.py#L366) 和环境工厂调用关系的压缩。当前 `main` 的非本地 `execute_code` 已复用环境；但 [`SECURITY.md`](https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md) 仍保留了代码执行不受 terminal backend 覆盖的旧说明。这里应视为源码与文档的版本差，不应据 `main` 推断所有已发布版本。

### 9.2 Docker 后端：先启动长期容器，再用 docker exec 复用

[`tools/environments/docker.py`](https://github.com/NousResearch/hermes-agent/blob/main/tools/environments/docker.py) 先拼出容器参数，执行一次 `docker run -d ... sleep infinity`；此后的命令用 `docker exec ... bash` 进入同一容器。开启持久化时，容器和工作状态可以跨会话保留。

```python
security_args = [
    "--cap-drop", "ALL",
    "--cap-add", "DAC_OVERRIDE",
    "--cap-add", "CHOWN",
    "--cap-add", "FOWNER",
    "--security-opt", "no-new-privileges",
    "--tmpfs", "/tmp:rw,nosuid,size=512m",
    "--tmpfs", "/var/tmp:rw,noexec,nosuid,size=256m",
]

if cgroup_limits_supported:
    security_args += ["--pids-limit", "2048", "--cpus", cpus, "--memory", memory]
if not docker_network:
    security_args += ["--network=none"]

run("docker", "run", "-d", *security_args, *mounts,
    *docker_extra_args, image, "sleep", "infinity")
run("docker", "exec", container, "bash", "-lc", command)
```

真实代码还会为 s6 镜像调整 `/run`，在需要切换用户时补 `SETUID` / `SETGID`。安全结论要同时看默认值和参数顺序：

- `docker_network` 默认为 `True`，所以默认不是 `--network=none`；
- `container_persistent` 默认为 `True`，状态不会随单条命令消失；
- 当前源码没有为根文件系统追加 `--read-only`；
- cgroup 探测失败时，CPU、内存和 PID 限制会降级；
- Snap 兼容模式会省略 `no-new-privileges`；
- `docker_extra_args` 最后追加，能够改变前面生成的 Docker 参数。

所以准确说法是“Docker 后端提供可配置的容器边界”，不是“启用后自动得到固定强度、默认断网的沙箱”。

### 9.3 文件护栏和凭据代理解决的是另一层问题

[`agent/file_safety.py`](https://github.com/NousResearch/hermes-agent/blob/main/agent/file_safety.py) 通过 `HERMES_WRITE_SAFE_ROOT` 限制文件工具的写入根，并拒绝常见的 SSH、云凭据和系统敏感路径。它对减少误操作有用，但 local backend 中的 shell 命令可以绕开 Python 文件工具，因此不能代替进程级文件隔离。

Iron Proxy 是可选的 Docker 出口代理：沙箱里只放入不透明 token，宿主代理再替换真实凭据并执行域名策略。它避免把 API key 直接塞进容器，但默认关闭，而且必须配合容器网络限制，才能防止程序绕过代理直接出网。

### 9.4 要覆盖插件、MCP 和 hooks，需要包裹整个 Hermes 进程

只切换 terminal backend，主要覆盖送入该环境的终端、文件和代码执行。Hermes 主进程仍可能在宿主上加载插件、MCP、hooks 和 skills。官方安全说明因此另列“整进程隔离”：使用官方 [`Dockerfile`](https://github.com/NousResearch/hermes-agent/blob/main/Dockerfile) / [`docker-compose.yml`](https://github.com/NousResearch/hermes-agent/blob/main/docker-compose.yml)，或把进程放进 [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell/blob/main/architecture/sandbox.md)。

官方镜像让服务以 UID 10000 的非 root 用户运行，并把可写主目录放到 `/opt/data`。不过当前 Compose 使用 `network_mode: host`，还把 `~/.hermes` 可写挂载到 `/opt/data`，因此默认 Compose 更像方便部署的进程边界，不是严格最小权限配置。

OpenShell 的边界更系统：非 root 且身份不可变、零 capabilities、`no_new_privs`、Landlock、seccomp 和 L7 网络策略一起生效，凭据通过 provider 占位符注入。对于不可信仓库或第三方插件，这类整进程包裹比单独把终端切到 Docker 更完整。

## 10. 实现层横向对照

| 实现 | 文件边界怎样落地 | 网络边界怎样落地 | 子进程/生命周期 | 最重要的例外 |
|---|---|---|---|---|
| Codex macOS | 动态 SBPL，read/write/deny 与受保护祖先 | Seatbelt socket；可只放行本地 proxy | Seatbelt 继承到子树 | 不是 VM；读与写必须分别配置 |
| Codex Linux | bwrap mount namespace，ro 根 + writable overlay + deny mask | net namespace；代理桥；seccomp 限 socket/VM socket | PID namespace、signal forwarding、reaper、die-with-parent | `/proc` 可有兼容回退；legacy Landlock 能力较弱 |
| Codex Windows elevated | 独立用户 SID + ACL + restricted token | 按用户 SID 的 Firewall/WFP 与 proxy 端口 | 独立 logon、desktop、Job/runner | 安装需提权；与 unelevated 保证不同 |
| SRT macOS | 动态 SBPL | Seatbelt 只达 localhost proxy，域名在 proxy 判定 | 约束继承整个命令树 | 显式 Mach/Apple Events/Unix socket 例外会扩大边界 |
| SRT Linux | bwrap bind/mask | `--unshare-net` + 双 socat/UDS proxy | 外层 bwrap + 内层 PID 1/seccomp | weaker nested sandbox 是显式降级点 |
| SRT Windows | 独立用户 + 引用计数 ACE | 按用户 SID 的 WFP，仅 proxy 端口 | 两跳登录 + restricted child | 产品是否暴露该后端需另查 |
| Gemini Linux manager | `--ro-bind / /` + overlay + secret mask | unshare-all；允许网络时 `--share-net` | new session、die-with-parent | seccomp 仅阻止 ptrace，不是网络 filter |
| Gemini Windows manager | Low IL token + 对宿主文件写 ACL/label | Job bandwidth=1 | suspended create → assign Job → resume | 网络失败只 warning；ACL/label 可能残留 |
| VS Code Windows | MXC policy → PSEC / fallback | MXC overall allow/block | `wxc-exec`/ProcessContainer | 无逐域名网络策略；home deny TODO |
| OpenHands Docker | Docker mount namespace，由 `-v` 打开宿主路径 | Docker 网络；默认不等于断网 | 容器 + agent server | 没有自动 `--read-only` / cap drop |
| Hermes Docker backend | 容器文件系统与显式 volumes；文件工具另有 safe-root 检查 | 默认允许 Docker 网络；可选 `--network=none` / Iron Proxy | 长期容器 + `docker exec` | 默认 local 无隔离；持久化和网络默认开启；插件/MCP 需整进程隔离 |
| OpenCode / OpenHands Local | 宿主原权限 | 宿主网络 | 普通宿主进程 | 没有内建 OS 沙箱 |

## 11. 从这些源码可以提炼出的实现原则

### 11.1 策略应保留“读、写、拒绝”的结构直到平台编译层

过早把它们压成“工作区可写”会丢失 `.git` 只读、秘密文件不可读、嵌套 carve-out 等语义。Codex、SRT 和 Gemini 新 manager 都在平台层仍携带分开的路径集合。

### 11.2 mount/规则顺序是安全逻辑，不只是参数排列

典型安全顺序是“宽泛基线 → 开放必要根 → 重新覆盖敏感子路径 → 最后追加不可绕开的 deny”。Bubblewrap 和 Seatbelt 实现都依赖这个顺序。父/子路径排序错误会让宽泛父挂载遮掉精细子挂载。

### 11.3 网络 allowlist 至少需要两层

域名属于应用层语义，namespace/WFP/Seatbelt 属于内核强制。较完整的设计是：

```text
内核边界：程序只能到受信 proxy
              +
代理边界：proxy 只连接允许域名/IP/端口
```

只设置 `HTTPS_PROXY` 没有强制力；只给 namespace 断网则无法提供受控网络。

### 11.4 helper 必须位于被约束进程之外，但又不能被它操纵

SRT 用嵌套 PID namespace 让用户命令看不到未过滤的 socat；Codex 限制 app-server/daemon Unix socket；Windows 独立用户让 surrogate spawn 仍带 sandbox SID。这些代码都在解决同一个问题：代理、runner、broker 本身如果能被不可信命令附加、注入或通过 IPC 调用，沙箱就可能被“借权”。

### 11.5 缺失能力必须显式失败或显式降级

较好的源码证据包括：Codex WSL1 提前拒绝、SRT nested namespace 失败即中止、MXC 请求级 capability probe、Gemini 指定 runtime 不存在时报错。反例是 Gemini Windows 的网络限速设置失败只 warning；调用方若需要严格断网，就不能把该分支视为满足要求。

### 11.6 修改宿主 ACL/完整性标签需要事务与恢复

namespace/Seatbelt 规则通常随进程消失；Windows ACL、mandatory label、WFP provider 和本地账户是持久状态。SRT 用 holder 引用计数与 restore/revoke；MXC 记录孤儿 DACL 状态；Codex 有独立 setup/uninstall 流程。任何自研 Windows 沙箱都需要把“恢复失败”和“进程崩溃后清理”当成主流程，而不是附加脚本。

## 12. 结论

从固定仓库源码看，主流实现大致分为三种工程路线：

1. **本地策略编译器**：Codex、SRT、Gemini 新 manager 把统一权限模型编译成 Seatbelt/Bubblewrap/Windows 原语，启动快、与本地工具兼容，但需要大量平台专用的路径、IPC 和失败处理。
2. **统一执行容器层**：MXC 把策略变成后端配置，并在 Windows 走 PSEC/ProcessContainer，在其他平台接 Bubblewrap/Seatbelt。抽象更统一，但保证取决于后端 capability 和 SDK 成熟度。
3. **外部环境后端**：OpenHands Docker/Apptainer 把 agent server 放入容器；Hermes 可以只把工具调用送入 Docker，也可以包装整个主进程。边界强度由镜像、挂载、网络、凭据与 runtime 参数共同决定。OpenHands LocalWorkspace、Hermes 默认 local 和 OpenCode 则没有 OS 隔离层。

不能用一个“已开启 sandbox”的布尔值比较它们。实际验收至少要分别检查：项目外读取、写入、符号链接、Unix socket/命名管道、直接网络、代理绕过、子进程与后台进程、提权路径、持久 ACL，以及底层能力缺失时的行为。

## 13. 源码索引

- Codex Linux：[README](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/README.md)、[`linux_run_main.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/src/linux_run_main.rs)、[`bwrap.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/src/bwrap.rs)、[`landlock.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/linux-sandbox/src/landlock.rs)
- Codex macOS：[`seatbelt.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/sandboxing/src/seatbelt.rs)
- Codex Windows：[`token.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/token.rs)、[`sandbox_users.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/setup_provisioning/sandbox_users.rs)、[`firewall.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/setup_provisioning/firewall.rs)、[`wfp.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/wfp.rs)、[`legacy.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/unified_exec/backends/legacy.rs)、[`elevated.rs`](https://github.com/openai/codex/blob/7f892275e31002f0422477c6219189284560e689/codex-rs/windows-sandbox-rs/src/unified_exec/backends/elevated.rs)
- SRT：[README](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/README.md)、[`sandbox-manager.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/sandbox-manager.ts)、[`linux-sandbox-utils.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/linux-sandbox-utils.ts)、[`macos-sandbox-utils.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/macos-sandbox-utils.ts)、[`windows-sandbox-utils.ts`](https://github.com/anthropics/sandbox-runtime/blob/e025055f221021582934e666cac1eeb08310e7b1/src/sandbox/windows-sandbox-utils.ts)
- Gemini CLI：[`sandboxManagerFactory.ts`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/services/sandboxManagerFactory.ts)、[`LinuxSandboxManager.ts`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/linux/LinuxSandboxManager.ts)、[`bwrapArgsBuilder.ts`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/linux/bwrapArgsBuilder.ts)、[`seatbeltArgsBuilder.ts`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/macos/seatbeltArgsBuilder.ts)、[`WindowsSandboxManager.ts`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/windows/WindowsSandboxManager.ts)、[`GeminiSandbox.cs`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/core/src/sandbox/windows/GeminiSandbox.cs)、[`sandboxConfig.ts`](https://github.com/google-gemini/gemini-cli/blob/fb972b2f87fe7d5b06d37eac711490162d98de2c/packages/cli/src/config/sandboxConfig.ts)
- VS Code：[`terminalSandboxEngine.ts`](https://github.com/microsoft/vscode/blob/2dca67a07aba894351849f39d337a921758722e8/src/vs/platform/sandbox/common/terminalSandboxEngine.ts)、[`terminalSandboxMxcRuntime.ts`](https://github.com/microsoft/vscode/blob/2dca67a07aba894351849f39d337a921758722e8/src/vs/platform/sandbox/common/terminalSandboxMxcRuntime.ts)
- MXC：[README](https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/README.md)、[ProcessContainer guide](https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/docs/process-container/guide.md)、[networking](https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/docs/process-container/networking.md)、[`secenv.rs`](https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/src/backends/process_container/common/src/secenv.rs)、[`dispatcher.rs`](https://github.com/microsoft/mxc/blob/2044eac07ad819319e924ae3d3a5f427a79c9afb/src/backends/process_container/common/src/dispatcher.rs)
- OpenCode：[`SECURITY.md`](https://github.com/anomalyco/opencode/blob/907b3bc518fa48e90e8ec24dd327d13eee71c36c/SECURITY.md)
- OpenHands：[`DockerWorkspace`](https://github.com/OpenHands/software-agent-sdk/blob/de30ec0111fc1c1435a1639d4ec27aead297d5b8/openhands-workspace/openhands/workspace/docker/workspace.py)、[`LocalWorkspace`](https://github.com/OpenHands/software-agent-sdk/blob/de30ec0111fc1c1435a1639d4ec27aead297d5b8/openhands-sdk/openhands/sdk/workspace/local.py)
- Hermes Agent（2026-10-07 读取 `main`）：[`SECURITY.md`](https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md)、[`config_defaults.py`](https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/config_defaults.py)、[`docker.py`](https://github.com/NousResearch/hermes-agent/blob/main/tools/environments/docker.py)、[`code_execution_tool.py`](https://github.com/NousResearch/hermes-agent/blob/main/tools/code_execution_tool.py)、[`file_tools.py`](https://github.com/NousResearch/hermes-agent/blob/main/tools/file_tools.py)、[`file_safety.py`](https://github.com/NousResearch/hermes-agent/blob/main/agent/file_safety.py)、[`Dockerfile`](https://github.com/NousResearch/hermes-agent/blob/main/Dockerfile)、[`docker-compose.yml`](https://github.com/NousResearch/hermes-agent/blob/main/docker-compose.yml)
- NVIDIA OpenShell：[`architecture/sandbox.md`](https://github.com/NVIDIA/OpenShell/blob/main/architecture/sandbox.md)
