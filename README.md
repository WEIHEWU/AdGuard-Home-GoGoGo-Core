# AdGuard-Home-GoGoGo-Core

专为 **[AdGuard-Home-GoGoGo](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo)**（Android Root 轻量级 DNS + NFQUEUE SNI 双引擎去广告防火墙模块）深度瘦身与针对性调优的专属 Go 核心仓库，上游基于 [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) / `AdguardHome-Mod` 演进。

---

## 核心优化亮点（最强满血瘦身专版 · DNS + NFQUEUE SNI）

| 优化维度 | 原版 `AdguardHome-Mod` (`arm64`) | `AdGuard-Home-GoGoGo-Core` (`android_slim`) | 收益 |
| :--- | :--- | :--- | :--- |
| **静态二进制体积（无 UPX）** | `22.13 MiB` (`23,199,904 B`) | **`11.75 MiB` (`12,320,892 B`)** | **直降 `46.89%`（减少 `10.88 MiB`，完整内置 NFQUEUE SNI）** |
| **持久化写盘（UFS/F2FS 磨损）** | `bbolt` `stats.db` + `sessions.db` + `querylog.json` | **0 磁盘写 I/O（100% 纯内存环形窗口）** | 消除后台刷盘唤醒与闪存写入放大 |
| **后台空转定时器** | `periodicFlush` 每 1 秒唤醒 CPU | **0 秒级轮询（按需惰性按小时滑动）** | 息屏 Doze 深度休眠零干扰 |
| **前端静态资源包** | 内嵌 SolidJS `client_v2`（约 `6 MB`） | **轻量内存引导页（由原生 Flutter Manager 接管）** | 零冗余静态资产驻留 |
| **NFQUEUE SNI 首包阻断** | 默认队列 `7` | **原生内置 NFQUEUE `0` + TLS `ClientHello` 分片重组阻断** | 精准掐灭 HTTPDNS / 硬编码 IP 直连广告 |
| **时区与根证书适配** | 嵌入 `408 KB` `time/tzdata`、缺失 Conscrypt 路径 | **直读 Android Bionic `/apex/com.android.tzdata` 与 Conscrypt CA** | 原生兼容 Android 9 ~ 16+ |
| **指令集与链接参数** | 默认 ARMv8.0 | **`GOARM64=v8.2` LSE 硬件原子指令 + 纯静态链接** | 高并发锁与原子计数开销显著降低 |

### 已安全剥离的冗余模块与重型依赖
通过正交编译标签 `android_slim`（以及可选 `nosni`）按需裁剪，**不改动任何 YAML 配置结构（`schema_version: 34`）与 `/control/*` HTTP API 契约**：
1. **持久化引擎与归档**：`go.etcd.io/bbolt`、`gopkg.in/natefinch/lumberjack.v2`、`encoding/gob`、`archive/tar`、`archive/zip`、`internal/updater`
2. **重型冗余入站/出站协议栈**：`github.com/quic-go/quic-go`（DoQ / HTTP/3）、`github.com/AdguardTeam/dnscrypt`（DNSCrypt Server/Client）
3. **路由器 ipset 操作**：`github.com/digineo/go-ipset/v2`（默认保留 `go-nfqueue/v2` 与 `netlink` 支撑 `AGH_SNI` 首包过滤）
4. **桌面/路由器守护与 Apple 描述文件**：`github.com/kardianos/service`、`internal/ossvc`、`howett.net/plist`、`github.com/fsnotify/fsnotify`
5. **科学计算与测试泄露库**：`gonum.org/v1/gonum`（替换为零分配标准库 `math/rand/v2` 加权无放回采样）、`github.com/google/go-cmp`、`github.com/stretchr/testify`、`yaml/v3`、`github.com/patrickmn/go-cache`
6. **云端硬编码连接**：移除启动时默认实例化的官方云端安全浏览/家长控制 `family.adguard-dns.com` DoH 连接与 `hashprefix` 匹配器，彻底根除后台非预期外连。

---

## 快速构建指南

环境要求：**Go `1.27+`**（无需安装 Node.js / npm）。

```sh
# 1. 默认构建（推荐）：最强满血档位 — DNS + NFQUEUE SNI 双引擎瘦身版（android_slim + GOARM64=v8.2）
make go-build-android

# 2. 可选构建：极简纯 DNS 防火墙档位（android_slim,nosni + GOARM64=v8.2）
make go-build-android-nosni

# 3. 跨架构静态类型与构建标签完整性检查
make go-os-check
```

---

## 关联仓库

- **Magisk / KernelSU / APatch 模块仓库**：[WEIHEWU/AdGuard-Home-GoGoGo](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo)
- **Android 原生控制面板（Manager）**：[WEIHEWU/AdGuard-Home-GoGoGo-Manager](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo-Manager)

## 开源许可

遵循上游 [GNU General Public License v3.0](./LICENSE) 协议开源。
