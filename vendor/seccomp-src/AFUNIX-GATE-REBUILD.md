# AF_UNIX 门控 apply-seccomp 重建说明

本目录包含 srt 沙箱自定义 `apply-seccomp` 二进制的源码、产物与重建方法。

## 背景：为什么需要这个二进制

OMP 原生的 `FileLock` 用 **抽象 AF_UNIX socket** 做跨进程文件锁
（`socket(AF_UNIX, SOCK_DGRAM|CLOEXEC)` + `bind("@omp-file-lock-<32hex>")`）。
srt 0.0.78 内嵌的 `vendor/seccomp-src/seccomp-unix-block.c` 生成的 BPF
过滤器在 `socket(AF_UNIX)` 创建处直接返回 EPERM，导致沙箱内
`Session persistence failed: Failed to acquire native file lock`。

修复策略（已验证）：

- **抽象 AF_UNIX 放行**：抽象地址是 netns 私有的，bwrap 用 `--unshare-net`
  隔离后主机端**不可达**（bwrap 实证），OMP 文件锁需要它。
- **路径型 AF_UNIX 一律 EPERM**：主机路径 socket（如
  `/run/user/<uid>/emacs/server`）从沙箱内**可达**（bwrap 实证），
  必须保持封锁以维持原有反逃逸行为。
- **io_uring 保持 EPERM**（沿用原 unix-block 过滤器）。
- **`socket()`/`socketpair()` 放行**：创建时不带地址，无风险。

BPF 无法解引用 `sockaddr` 参数，因此把 `bind`/`connect`/`sendto`/`sendmsg`
四个地址绑定类系统调用路由到 `SECCOMP_RET_USER_NOTIF`，由外层 stub 的
`supervise()` 用 `process_vm_readv` 读取地址做判定：AF_UNIX 且地址首字节
（`sun_path[0]`）为 NUL → 抽象 → 放行；否则 → `resp->error = -EPERM`。
`sendto`/`sendmsg` 必须进门控：未连接的 DGRAM `sendto(path)` 无需
`connect()` 即可投递（逃逸向量已实证），`sendmsg` 的 `msg_name` 同理。

### 判定强化（F2 fail-closed + F3 netns 自检）

上面的"首字节 NUL → 放行"判定有两个弱点，已修复：

- **F2 读失败 fail-closed**：`process_vm_readv` 读 `msg_name`/`sun_family`/
  `sun_path[0]` 任一失败（EFAULT/EPERM），旧代码按"未抽象"处理时会 fail-open
  （`!(-1)==0` → 放行）。现在读失败一律 `resp->error=-EPERM`：读不到
  `msg_name`（`sendmsg`）无法区分"合法 NULL（已连接 socket）"与"恶意不可读
  指针"→ 拒；真实指针读不到 `sun_family` → 无法证明非 AF_UNIX 路径 → 拒。
  真正的 NULL `msg_name`/`addr`（已连接 socket 无地址）仍放行。
- **F3 netns 隔离自检**：抽象地址"主机不可达"的假设**只在
  `--unshare-net` 下成立**。独立运行（无 netns）时门控与主机共享 netns，
  主机可达子进程抽象 socket（v3 探针实证）。门控现在自检子进程是否处于
  新 netns（`/proc/net/dev` 仅 `lo`），只有确认隔离才放行抽象 socket；
  否则 fail-closed 拒绝抽象。自检在**内层 init**（其 `/proc` 可读，外层 stub
  的 `/proc` 被掩码）读取，结果经 `send_fd` 的 dummy 字节传给外层 stub。

判定优先级（外层 stub `supervise()`）：`!addr_known`（读 `msg_name` 失败）
→ 拒；`sa!=0 && fam==-1`（读 family 失败）→ 拒；`fam==AF_UNIX && sa!=0`
→ 需 `abstract_ok && 首字节 NUL` 才放行，否则拒；其余（`fam!=AF_UNIX`、
NULL addr）→ 放行。
## 进程拓扑与握手

进程布局（bwrap 沙箱内部）：

```
bwrap init (PID 1, 外层 PID ns)
└─ bash / socat 等
   └─ apply-seccomp-gate [外层 stub]      ← 永不装过滤器；recv_fd 收监听 fd
      ====================================  PID ns 边界（unshare）
      └─ apply-seccomp-gate [内层 init]   ← 嵌套 userns 里 PID 1，dumpable 到握手完成
         └─ apply-seccomp-gate [worker]   ← PID 2，NO_NEW_PRIVS + 门控过滤器，然后 exec 用户命令
```

两条预 fork 的 socketpair（`main()` 里 `SRT_AUDIT_ARCH != 0` 时创建，
失败 fail-open 置 -1）：

- **`wk`** —— worker ↔ 内层 init 的 marker/ack 通道：
  - worker 写 `"<nfd>\n"` marker 到 `wk[1]`（filter 安装成功后）
  - init 从 `wk[0]` 读 marker → `pidfd_open(worker)` + `pidfd_getfd(pidfd, nfd)`
  - init 写 `"A"` ack 到 `wk[0]` → worker 从 `wk[1]` 读到 → exec
  - 三条失败路径（probe/BPF/NEW_LISTENER 失败）：worker 写 `"E"` 到 `wk[1]`
    后 `_exit(1)`
  - **不能复用 `sp` 走这条通道**：worker fork 自 init，继承 `sp[1]` 的第二份
    副本；写 `sp[1]` 会送到 `sp[0]`（外层 stub）而非 init，marker 会污染
    stub 的 `recv_fd`。
- **`sp`** —— 只承载 init → stub 的 SCM_RIGHTS fd（`send_fd`：1 字节
  dummy + SCM_RIGHTS）。stub 端 `recv_fd(sp[0])` 看到的必须是干净的
  1 字节 + fd 负载，所以 `sp` 上**永远没有 marker/ack 字节**。

关键内核事实（均已实测）：

1. **`NEW_LISTENER` fd 是 CLOEXEC**：`seccomp(SET_MODE_FILTER,
   NEW_LISTENER)` 返回的 fd 自带 close-on-exec；worker `execvp` 后自动关闭。
   监听对象在 exec 后仍存活，因为 init（`pidfd_getfd` 副本）和 stub
   （`recv_fd` 副本）各持一份引用。
2. **`pidfd_getfd` 要求调用方 dumpable**（内核 ≥5.6 安全检查）：
   本机 yama `ptrace_scope=1` 下，双方都 dumpable → OK；
   父进程 `dumpable=0` → EPERM。因此内层 init 必须把手握期间的
   `PR_SET_DUMPABLE(0)` 推迟到 `pidfd_getfd` 之后。
3. **监听 fd 关闭不会自动放行冻在 trapped syscall 里的子进程**：
   必须持续服务。外层 stub 持有 `recv_fd` 得到的 fd 并 `supervise()`
   直到子进程退出。

失败语义：

- **门控安装失败 → fail-CLOSED**（worker `_exit(1)`）：门控替换了原
  unix-block 过滤器；不装就等于放行路径型 AF_UNIX，不允许无过滤器运行。
- **握手失败（marker 超时 / `"E"` / getfd EPERM / send_fd 失败 /
  wk 创建失败）→ fail-OPEN**：init 不送 fd 就关 `sp[1]` → stub
  `recv_fd` 返回 -1 → 无监听器 → 若门控已装则 trapped syscall 回
  ENOSYS（安全侧），若没装则 workload 无过滤器运行；fd 2 打日志。
- **observe socket 未配置** → stub 不尝试连接，`supervise()` 仍服务
  门控（`out = -1`）。

## 重建

工具链：`gcc` + `strip`（本机 `/run/current-system/sw/bin/`）。
本机 nix store 无静态 glibc，因此**动态**链接 nix glibc（沙箱内 bwrap
绑定 nix store，动态解析正常；seccomp 过滤器跨 exec 粘住，与链接方式无关）。

```bash
cd <本目录>
gcc -O2 -Wall -Wextra -o apply-seccomp-gate apply-seccomp-abstract.c
strip apply-seccomp-gate
```

单文件 `apply-seccomp-abstract.c`（~1200 行），无头文件依赖
（原 `gate-constants.h` 已删除，不要重建）。自包含的兜底宏：
`AUDIT_ARCH_X86_64`/`AARCH64`/`X32`、`__NR_pidfd_open`/`pidfd_getfd`/
`pipe2`/`fchmodat2`。

## 接入 srt

`~/.srt-settings.json`：

```json
"seccomp": {
  "applyPath": "/path/to/apply-seccomp-gate"
}
```

srt 侧逻辑（`generate-seccomp-filter.ts` `getApplySeccompBinaryPath`）：
显式 `applyPath` → `fs.existsSync` 校验 → 原样使用；调试日志
`Using apply-seccomp binary from explicit path: …`。

## 验证清单（全部实测通过）

独立运行：

- `./apply-seccomp-gate bash -c 'exit 7'; echo $?` → 7，68 ms，无 10 s 握手卡顿
- `./apply-seccomp-gate bash -c 'echo HELLO'` → HELLO，rc=0，stderr 干净
- python3 门控探针：
  - `socket(AF_UNIX, SOCK_STREAM).bind("/tmp/x.sock")` → EPERM
  - `connect("/run/user/<uid>/emacs/server")` → EPERM
  - `socket(AF_UNIX, SOCK_DGRAM).bind(b"\0gate-test")` → OK
  - 未连接 DGRAM `sendto(b"/run/user/<uid>/emacs/server", …)` → EPERM
  - 抽象 DGRAM 互发 → OK；socketpair → OK；TCP 127.0.0.1 → OK
- `SRT_OBSERVE_SOCK` 指向监听 socket → JSON 行仍发射
  （`encodedCommand` 头 + `openat` 行），合并过滤器未回归

完整 srt 沙箱（`srt -c` / `srt omp`）：

- 同一探针组结果一致
- `srt omp -p 'Reply with exactly: ALL-OK' --model …`（从 `~`，无
  `--no-session`）→ 应答 + 新 `.jsonl` 落在
  `~/.omp/agent/sessions/--tmp--/`，无 `Session persistence` 告警
- `curl example.com` → `000`（CONNECT 403，网络封锁）
- `cat /tmp/.authinfo-cache` → Permission denied（denyRead）
- `head ~/.mcp.json` → 正常（cwd-scoped masking；从 `~` 可读）
- `srt -d` 日志出现 `Using apply-seccomp binary from explicit path`
- 干净环境新 shell：`env -i HOME=… PATH=… zsh -c "srt omp -p … --no-session"`
  → 应答正确
- 交互式 TUI 从 `~`：启动正常，MCP servers 全部启用

已知无害噪音：omp 从 `~` 启动会 chdir 到 `/tmp`（`applyStartupCwd`
设计行为），pi-mcp-adapter 的 cwd-scoped 逻辑会尝试读 `/tmp/.mcp.json`
并打 EACCES 堆栈（文件不存在），不影响功能；`~/.mcp.json` 从 `~` 直接
读取正常。
