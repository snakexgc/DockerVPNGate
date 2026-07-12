# DockerVPNGate

DockerVPNGate 是一个基于 VPNGate 的多出口 HTTP/SOCKS5 代理网关。服务在单个 Docker 容器中维护 5 条独立 OpenVPN 隧道，并提供响应式 Web 管理界面。

> 展示名称统一使用 `DockerVPNGate`。Docker 镜像仓库名、Compose 项目/服务名和容器内数据路径仍保留小写 `dockervpngate`，以符合 Docker/Compose 命名约束。

## 功能

- 5 个固定容器代理端口，每个端口对应独立 VPN 节点和 `tun` 网卡。
- 每个端口可以单独选择优先国家/地区和出口 IP 类型。
- 每个代理可独立选择“自动切换”或“固定选中”：自动模式在失效后连接配置范围内延迟最低的节点，固定模式只保留并重连手动选中的节点。
- 优先地区无节点时自动使用其他地区，检测到首选地区恢复后自动切回。
- HTTP 与 SOCKS5 自适应代理协议。
- 五个代理端口共用一组可动态修改的认证凭据。
- 节点有效性通过任务队列和 8 个工作线程并发检测；更新节点可取消当前队列，并在新旧节点全量测试后提交地区节点池。
- 节点延时在 OpenVPN 隧道建立后通过该隧道请求 Google `generate_204` 实测，不使用入口服务器 Ping 冒充出口延时。
- 持久化节点缓存池按国家/地区独立限额，默认每地区最多 10 个节点；更新时先完成新旧节点全量测试，再优先替换超时节点，其次替换实测延迟最高的旧节点。
- API 拉取失败或返回空结果时不会清空本地节点池；测试/更新异常时会恢复更新前快照。
- “更新节点”负责拉取、合并和检测，“连接测试”只检测现有缓存，不会重复请求 VPNGate API。
- 节点地区偏好、后台凭据和运行配置持久化到项目目录 `./vpngate_data`。
- Web 面板提供可筛选、搜索和自动刷新的结构化运行日志。
- 系统状态展示五代理实时速率、今日流量和汇总流量；统计可手动清零，容器重启后自动重新计量。

## 前置条件

- Linux 主机或支持 TUN 的 Linux 容器环境。
- 宿主机存在 `/dev/net/tun`。
- Docker Compose v2。

Linux/macOS Shell：

```bash
test -c /dev/net/tun && echo "TUN is ready"
```

PowerShell：

```powershell
# 这项检查需要在 Linux Docker 主机上执行。
# 如果你正在 Windows 上远程管理 Linux 服务器，请在服务器 Shell 中执行上面的命令。
```

## Docker Compose 启动

Linux/macOS Shell：

```bash
docker compose up -d --build
docker compose ps
docker logs -f DockerVPNGate
```

PowerShell：

```powershell
docker compose up -d --build
docker compose ps
docker logs -f DockerVPNGate
```

访问管理页面需要使用安全路径：

```text
http://服务器IP:8787/安全路径/
```

安全路径可通过下面“查看初始账号”命令中的 `URL path` 获取。DockerVPNGate 不会在根路径自动跳转到安全路径，避免泄露后台入口。

如果访问 `http://服务器IP/` 或域名根路径看到 nginx 欢迎页，这是预期效果；只有访问带安全路径的链接才会进入 DockerVPNGate 登录界面。

## 查看初始账号

Linux/macOS Shell：

```bash
docker exec DockerVPNGate python -c 'import json; c=json.load(open("/var/lib/dockervpngate/ui_auth.json")); print("URL path:", c["secret_path"]); print("username:", c["username"]); print("password:", c["password"])'
```

PowerShell：

```powershell
docker exec DockerVPNGate python -c "import json; c=json.load(open('/var/lib/dockervpngate/ui_auth.json')); print('URL path:', c['secret_path']); print('username:', c['username']); print('password:', c['password'])"
```

如果当前目录已挂载 `./vpngate_data`，也可以在宿主机直接查看。

Linux/macOS Shell：

```bash
python -m json.tool ./vpngate_data/ui_auth.json
```

PowerShell：

```powershell
Get-Content .\vpngate_data\ui_auth.json | ConvertFrom-Json | Select-Object username,password,secret_path
```

## 固定内部端口

容器内部端口不允许在 Web 面板中修改：

| 功能 | 容器端口 | 隧道 |
| --- | --- | --- |
| Web 管理 | `8787` | - |
| 代理 1 | `7928` | `tun0` |
| 代理 2 | `7929` | `tun1` |
| 代理 3 | `7930` | `tun2` |
| 代理 4 | `7931` | `tun3` |
| 代理 5 | `7932` | `tun4` |

每个代理端口同时支持 HTTP 和 SOCKS5，并对应独立的 OpenVPN 隧道。默认 Compose 仅将代理端口映射到宿主机回环地址。

Linux/macOS Shell：

```bash
curl -x http://127.0.0.1:7928 https://api.ipify.org
curl --proxy socks5h://127.0.0.1:7929 https://api.ipify.org
```

PowerShell：

```powershell
curl.exe -x http://127.0.0.1:7928 https://api.ipify.org
curl.exe --proxy socks5h://127.0.0.1:7929 https://api.ipify.org
```

五个端口共用一组代理用户名和密码，可在 Web 面板的“设置”页面修改。

每个代理端口都能独立设置节点失效策略：

- “自动切换”：当前节点失效后，选择地区和 IP 类型范围内实测延迟最低的可用节点。
- “固定选中”：不会切换到其他节点，固定节点恢复可用后仍只重连该节点。

## 节点缓存池

节点缓存池默认对每个国家/地区保留最多 10 个节点，可在 Web 面板的“设置”页面调整（范围 1–200）。各地区独立计算限额，所以日本、韩国等节点较多的地区不会挤占其他地区的名额。总池大小由“实际覆盖地区数 × 每地区上限”动态决定。

更新采用两阶段流程：先把新节点与 `./vpngate_data/nodes.json` 中的旧缓存去重暂存，对全部候选节点完成 Google 204 测试，再按地区落盘。有效新节点先替换超时旧节点；仍有有效新节点时替换延迟最高的旧节点。当前正在使用或固定选中的节点不会被淘汰。

如果某地区的新旧节点全部超时，会优先轮换为本次新抓取节点，并在候选数量足够时仍保留到该地区设置的节点数。VPNGate 拉取失败、返回空列表或检测流程异常时，不会用空结果覆盖原节点池。

- “更新节点”：取消当前测试队列，拉取一份 API 快照，对本地与新节点全量检测，再按地区限额更新缓存池。
- “连接测试”：只测试当前缓存池，不拉取 API，也不改变缓存池成员。

测试期间重复点击“连接测试”会直接忽略；测试期间点击“更新节点”会清空待测队列、终止临时测试隧道，等待拉取和缓存合并完成后再重新入队。

连接测试会先建立节点的临时 OpenVPN 隧道，再通过该隧道访问 `https://www.google.com/generate_204`，页面中的实测延时为该 HTTPS 请求的完整耗时。无法通过隧道取得 HTTP 204 的节点会标记为不可用。

## 修改外部端口

容器内部端口固定，宿主机端口通过 [docker-compose.yml](docker-compose.yml) 的 `ports` 配置修改。只修改左侧的宿主机端口，不要修改右侧容器端口。例如把宿主机 `18001` 映射到代理 1：

```yaml
ports:
  - "127.0.0.1:18001:7928/tcp"
```

如需允许其他设备连接，可将某个映射中的 `127.0.0.1:` 删除。对公网开放前必须在“设置”中启用代理认证，并通过防火墙或云安全组限制来源 IP。

## nginx 反向代理

如果希望通过域名或 `80/443` 访问 Web 管理界面，建议只把安全路径转发到容器映射出的 `8787` 端口，并保留 nginx 根路径的默认欢迎页。

假设 `ui_auth.json` 中的安全路径为 `EJsW2EeBo9lY`，示例：

```nginx
server {
    listen 80;
    server_name your-domain.example.com;

    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
    }

    location /EJsW2EeBo9lY/ {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

配置后访问 `http://your-domain.example.com/` 会进入 nginx 欢迎页；访问 `http://your-domain.example.com/EJsW2EeBo9lY/` 才会进入 DockerVPNGate 登录界面。请把示例中的 `EJsW2EeBo9lY` 替换为你自己的安全路径。

配置完成后重新加载 nginx：

Linux/macOS Shell：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

PowerShell：

```powershell
# 在远程 Linux 服务器上执行：
sudo nginx -t
sudo systemctl reload nginx
```

## 直接使用 Docker

Linux/macOS Shell：

```bash
docker build -t dockervpngate:local .

docker run -d \
  --name DockerVPNGate \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.all.rp_filter=2 \
  --sysctl net.ipv4.conf.default.rp_filter=2 \
  -p 8787:8787 \
  -p 127.0.0.1:7928:7928 \
  -p 127.0.0.1:7929:7929 \
  -p 127.0.0.1:7930:7930 \
  -p 127.0.0.1:7931:7931 \
  -p 127.0.0.1:7932:7932 \
  -v dockervpngate-data:/var/lib/dockervpngate \
  dockervpngate:local
```

PowerShell：

```powershell
docker build -t dockervpngate:local .

docker run -d `
  --name DockerVPNGate `
  --restart unless-stopped `
  --cap-add NET_ADMIN `
  --cap-add NET_RAW `
  --device /dev/net/tun:/dev/net/tun `
  --sysctl net.ipv4.ip_forward=1 `
  --sysctl net.ipv4.conf.all.rp_filter=2 `
  --sysctl net.ipv4.conf.default.rp_filter=2 `
  -p 8787:8787 `
  -p 127.0.0.1:7928:7928 `
  -p 127.0.0.1:7929:7929 `
  -p 127.0.0.1:7930:7930 `
  -p 127.0.0.1:7931:7931 `
  -p 127.0.0.1:7932:7932 `
  -v dockervpngate-data:/var/lib/dockervpngate `
  dockervpngate:local
```

配置、地区偏好、节点缓存和日志绑定挂载在项目的 `./vpngate_data` 目录中，重建容器不会丢失。管理用户名、密码和五个代理配置可在 `./vpngate_data/ui_auth.json` 中查看。

## 维护命令

Linux/macOS Shell：

```bash
docker restart DockerVPNGate
docker logs --tail=200 DockerVPNGate
docker compose down
docker compose up -d --build
```

PowerShell：

```powershell
docker restart DockerVPNGate
docker logs --tail=200 DockerVPNGate
docker compose down
docker compose up -d --build
```

## 安全提示

不要将无认证代理直接暴露到公网。需要远程使用时，请先在 Web 设置中配置代理用户名和密码，并通过防火墙或云安全组限制来源 IP。

## 维护参考

项目模块职责、关键状态机和维护回归清单见 [PROJECT_MEMORY.md](PROJECT_MEMORY.md)。

## License

[MIT](LICENSE)
