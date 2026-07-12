# DockerVPNGate 项目维护记忆

最后核对：2026-07-12

本文件是仓库内的长期维护说明。修改架构、端口、持久化格式或任务状态机后，应同步更新本文件。不要在这里记录真实用户名、密码、安全路径、节点地址或其他运行时敏感数据。

## 不可破坏的产品约束

- 容器内固定提供 5 个代理端口：`7928`–`7932`，分别绑定 `tun0`–`tun4`。
- Web 固定使用容器端口 `8787`；外部端口只能通过 Docker 映射调整。
- 每个端口同时支持 HTTP 与 SOCKS5，并拥有独立节点、首选地区、IP 类型和失效策略。
- 五个代理共用一组代理认证凭据。
- 自动模式允许故障切换；固定模式不能偷偷切换到其他节点。
- 地区设为“自动选择”时，五个代理应优先占用当前尚未使用的地区；可用地区不足时再按 Google 204 实测延迟从低到高补足。自动模式判断现有连接是否仍符合配置时必须同时检查地区和 IP 类型；自动切换应优先留在失效节点原地区并选择该地区未被其他代理占用、IP 类型匹配且批量实测延迟最低的节点，所有代理节点 ID 始终不得重复。节点池排序使用同一轮全量 Google 204 测试产生的可比延迟，活动代理每 30 秒取得的实时延迟只更新槽位运行状态，不得覆盖节点池批测延迟。
- 节点延时必须在临时 VPN 隧道内请求 Google `generate_204`，不能使用入口 TCP/Ping 冒充出口延时；204 检测默认 `connect-timeout` 与 `max-time` 均为 5 秒。
- 节点检测使用 8 个工作线程和一个任务队列。批量检测状态机必须是 `queued`（排队中）→ `testing`（检测中）→ `available/unavailable`（可用/不可用），不要再让前端显示“未检测”。重复批量测试请求应丢弃；更新节点必须取消现有测试队列，暂存本地与拉取节点并全量测试，测试完成后才按地区限额提交；如果维护任务结束后仍有 `queued/testing/not_checked` 遗留节点，后台需要走续测缓存池流程，不能等待下一次 API 拉取周期。
- 节点池容量按国家/地区独立计算，默认每地区最多 10 个。地区候选超出上限时，应优先为住宅/移动类型保留不少于地区配额一半（奇数向上取整）的名额；可用住宅/移动节点不足时使用可用数据中心节点补足，超过保留线的节点再按现有新节点轮换与延迟规则竞争。有效新节点先替换超时旧节点，再替换高延迟旧节点；某地区全部超时时仍需优先轮换新节点并尽量保持地区配额。API 空结果、拉取失败或暂存测试异常不得清空原节点池。
- 后台自动维护在排队节点清空后按“当前节点池节点数 × 10 秒”等待；到点后需要拉取合并并全量重测节点池，而不是只补测新增或不可用节点。
- 正在连接并使用的五个代理槽位每 30 秒通过当前代理请求一次 Google `generate_204`。若第一次超时必须立即二次确认；只有连续 5 次 204 超时且槽位策略为自动切换时，才把当前节点标记为不可用并进入自动切换流程。固定选中模式不得偷偷切换。
- 手动单节点检测独立于 8 线程批量队列；连续触发时新请求必须取消旧请求，只有最后一次请求允许写回结果。
- 用户选择的首选国家需要持久化；临时回退其他地区后，首选地区恢复时应自动切回。
- 流量统计只保存在内存：节点切换继续累计，手动清零重新建立网卡基线，容器重启自动清零。
- 管理表单和代理筛选不能被 5 秒状态心跳覆盖。
- 代理 1–5 的节点列表不再维护独立的地区和 IP 类型筛选，必须实时跟随上方代理配置中的地区与 IP 类型。节点仓库和代理节点表格默认按内容自动收紧列宽并在宽屏均匀利用空间；手动列宽通过表头分界线拖动，双击分界线恢复自动宽度。

## 模块职责

| 路径 | 职责 |
| --- | --- |
| `vpngate_manager.py` | 应用入口与编排层：共享运行状态、五代理调度、缓存维护、后台线程和服务启动。 |
| `vpngate_app/config.py` | 环境变量、固定端口、路径和容量边界。 |
| `vpngate_app/storage.py` | 原子 JSON 读写、管理配置迁移、代理槽默认值和节点读取。 |
| `vpngate_app/vpngate_source.py` | VPNGate API 获取、上游代理握手、CSV/配置解析、节点转换与黑名单。 |
| `vpngate_app/openvpn_runtime.py` | OpenVPN 命令构建、进程启动/终止、残留清理与握手等待。 |
| `vpngate_app/policy_routing.py` | 为绑定到 `tunX` 的 socket 建立独立策略路由表，并以固定优先级可靠清理规则。 |
| `vpngate_app/node_testing.py` | 临时测试隧道、Google 204 延时检测、8 线程队列与取消恢复。 |
| `vpngate_app/traffic.py` | `tun0`–`tun4` 每秒采样、今日/累计流量与原子清零。 |
| `vpngate_app/web_api.py` | 登录会话、静态资源和 REST API 路由。通过入口模块注入运行时服务。 |
| `vpngate_app/logging_utils.py` | 结构化 JSON 日志及过期清理。 |
| `vpngate_app/logging_io.py` | 标准输出与文件日志的 Tee。 |
| `vpngate_app/common.py` | 无状态的通用解析与安全文件名工具。 |
| `proxy_server.py` | HTTP/SOCKS5 前端代理及按 TUN 网卡绑定的网络转发。 |
| `vpn_utils.py` | IP 信息补全、网络诊断和 VPN 辅助能力。 |
| `web/index.html` | 页面结构。 |
| `web/styles.css` | 页面视觉和响应式布局。 |
| `web/app.js` | 前端状态、筛选、表单保护和 API 心跳。 |

依赖方向应尽量保持为：`config/common -> storage/logging -> source/runtime/testing/traffic -> manager -> web_api`。底层模块不要反向导入 `vpngate_manager.py`；需要共享运行状态时，使用现有的显式配置函数注入。

## 关键运行流程

### 启动

1. 创建数据目录并迁移 `ui_auth.json`。
2. 清理遗留 OpenVPN 进程和测试配置。
3. 启动五个 HTTP/SOCKS5 监听线程。
4. 启动流量采样、节点维护和代理健康监控线程。
5. Web API 在 `8787` 提供管理界面。

### 节点更新

1. 设置 `node_refresh_pending`。
2. 如有测试任务，清空队列并终止临时测试进程。
3. VPNGate API 只拉取一次快照。
4. 将新节点与本地池去重暂存；此时不能裁剪或覆盖更新前快照。
5. 启动和每次成功拉取后，新旧候选节点全部先写为 `queued` 并进入 Google 204 测试队列；工作线程取到节点后写为 `testing`，完成后写为 `available` 或 `unavailable`。
6. 测试完成后按地区限额提交节点池；异常则恢复更新前快照。拉取失败时只测试并保留本地池。
7. 为五个代理执行 `ensure_proxy_slot()`。

### 代理切换

- `connect_proxy_slot()` 在槽锁和 VPN 操作锁内停止旧隧道、建立新隧道、设置策略路由并保存节点选择。
- 每个槽只能占用一个节点，一个节点不能被多个槽同时使用。
- 停止隧道前必须采样一次流量，避免节点切换丢失最后一段统计。
- 所有受管 OpenVPN 进程必须同时使用 `route-nopull` 与 `route-noexec`，不得修改容器主路由；只有显式绑定到 `tunX` 的代理 socket 才能通过独立策略表进入隧道。

### 流量统计

- Linux sysfs 来源：`/sys/class/net/tunX/statistics/{rx_bytes,tx_bytes}`。
- `rx` 作为下载，`tx` 作为上传。
- `/api/traffic` 是轻量心跳；前端每 2 秒只更新文字，不重绘表单。
- `/api/traffic/reset` 清空全部槽并把当前网卡计数设为新基线。

## 持久化边界

挂载目录默认为 `/var/lib/dockervpngate`，Compose 映射到 `./vpngate_data`。

- `ui_auth.json`：管理凭据、安全路径、代理认证、缓存容量和五槽配置。
- `nodes.json`：节点缓存、检测结果、实测延时和拉取时间。
- `state.json`：维护状态与最近任务信息。
- `ip_cache.json`：IP 地理与线路类型缓存。
- `blacklist.json`：临时黑名单。
- `vpngate.log`、`logs/*.json`：运行日志。

流量统计、登录会话、进程对象、队列和锁禁止写入上述 JSON。

## Web API 摘要

- `GET /api/dashboard`：完整管理状态。
- `GET /api/traffic`：五槽轻量流量状态。
- `POST /api/traffic/reset`：清空流量统计。
- `GET /api/nodes?slot=N`：节点列表及占用状态。
- `POST /api/nodes/refresh`：拉取、合并并测试。
- `POST /api/nodes/test-cache`：只测试缓存池。
- `POST /api/slots/update|connect|disconnect|test`：代理槽操作。
- `GET|POST /api/settings`：读取或保存管理设置。

除登录接口外，API 必须经过安全路径和会话认证。

## 修改后的最低回归检查

```bash
python -m py_compile vpngate_manager.py proxy_server.py vpn_utils.py vpngate_app/*.py
python -m unittest discover -s tests -v
node --check web/app.js
docker compose up -d --build
docker compose ps
docker compose logs --tail 100
```

还应验证：登录、五槽 Dashboard、节点筛选、设置表单不会被心跳重置、节点更新取消测试、固定模式不切换、流量清零后不会回灌历史计数。

## 常见陷阱

- Dockerfile 必须复制 `vpngate_app/` 和整个 `web/`，否则本地编译正常但容器启动失败。
- 新增前端资源时，需要在 `web_api.py` 中增加正确的 MIME 路由。
- 不要把容器内部端口重新暴露为可编辑设置。
- 不要在节点切换时重建整个流量统计器。
- 不要在状态心跳中重新填充正在编辑的输入框或打开的下拉框。
- 修改节点 JSON 时继续使用原子写入，避免并发测试线程写出半文件。
