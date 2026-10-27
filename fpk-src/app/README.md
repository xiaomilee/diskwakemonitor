# disk-wake-monitor —— 硬盘唤醒归因

**回答一个问题：到底是谁把休眠的外接硬盘弄醒了。**

面向飞牛 fnOS（Debian 12 底子，x86_64）。纯 Python 标准库实现，**零第三方依赖、
零外部 CDN**，不碰系统 Python 环境；由 root 权限的 systemd 服务采集，浏览器面板查看。

```
SMB 访问、容器里的下载器、定时备份、日志落盘、甚至你自己的监控脚本……
硬盘每次被唤醒，这里都会记下：几点、哪块盘、睡了多久、谁干的、置信度多少。
```

---

## 它是怎么知道「谁」唤醒了盘的

三路信号互为补位，避免单一手段的盲区：

| 信号 | 来源 | 作用 |
|---|---|---|
| 唤醒判定 | `/proc/diskstats` 每秒轮询 | 空闲超过阈值后突然出现扇区增量 → 唤醒候选 |
| 电源确认 | `smartctl -n standby`（不惊醒盘） | 读到 standby→active 跃迁、`Start_Stop_Count` 递增 → 高置信确认 |
| 归因 | `fatrace` → 内建 `fanotify` → `block_dump` | 拿到「哪个进程碰了哪个文件」 |

归因数据源按优先级自动选择：

1. **fatrace**（装了就用，最省心）
2. **内建 fanotify**（fatrace 没装时自动顶上）：用 ctypes 直接调 glibc 的
   `fanotify_init/fanotify_mark`，不依赖任何外部包，精度与 fatrace 相同
   （pid + 进程名 + 文件路径）。fnOS 这类 Debian 系系统开箱可用
3. **block_dump**（最后兜底）：仅内核 5.10 以前可用——**5.10 起内核已移除该功能**，
   fnOS 的 6.12 内核上这条链路是死的，只会出现在 `dwmctl probe` 的警告里

唤醒不会立刻定案，而是等 `suspect_lookahead_seconds`（默认 3 秒）走完再归因——
因为硬盘上电有 1~3 秒延迟，**触发唤醒的那次 IO 往往“看起来晚于”唤醒时刻**。
窗口内记录按进程聚合，时间最贴近、命中最多的排前面。

每条记录带三档置信度：

- **SMART 确认**：启停计数递增或电源态跃迁，最可信
- **电源态**：SMART 报告盘当时处于待机
- **推断**：只有「久静后出现 IO」，SMART 不可用时的兜底

另外区分两类现象，别混淆：

- **唤醒**：盘睡着 → 被叫醒。看「唤醒明细」。
- **阻止休眠**：盘根本没睡着，因为有进程每隔几秒碰它一次。看「阻止休眠的元凶」排行。

---

## 安装（飞牛 fnOS）

两种方式，选一种即可。

### 方式 A：应用中心安装 .fpk（推荐）

产物：`dist/diskwakemonitor_<版本>_x86.fpk`（当前为 `diskwakemonitor_1.1.0_x86.fpk`）

文件名遵循 fnOS 规范 `{appname}_{version}_{platform}.fpk`，版本号由构建时自动带入。
`dist/` 顶层只保留当前版本，历史版本自动移到 `dist/archive/`。

1. 飞牛桌面 → **应用中心** → 右上角 **设置** → **手动安装应用**
2. 选择 `diskwakemonitor_<版本>_x86.fpk`
3. 安装向导里选：是否允许局域网访问面板、是否自动装 fatrace/smartmontools、历史保留时长
4. 装完桌面出现「硬盘唤醒归因」图标，点开就是面板；也可以用
   `http://<NAS-IP>:8765/`

装完在应用中心可以「启动 / 停止 / 设置 / 卸载」。卸载**保留**采集历史
（`/var/lib/disk-wake-monitor`），确认不要了再手动删。

用 fpk 安装时数据与配置由飞牛托管：

| 内容 | 位置 |
|---|---|
| 程序 | `target/`（`install_type=root`，落在系统分区，不占你的数据盘） |
| 配置 | `etc/config.json` |
| 日志 | `var/info.log`、`var/probe.log` |
| 采集数据库 | `/var/lib/disk-wake-monitor`（**系统盘**，不会被自己叫醒） |

两个与 fpk 相关的注意点：

- **必须 root 运行**——fatrace（fanotify）、smartctl 电源态、block_dump 都需要特权。
  这是工具性质决定的，不是偷懒。只读采集，不写用户数据、不联网。
- **面板端口固定 8765**（应用中心图标里写死了）。要改端口需同时改
  `target/ui/config` 里的 `port` 与 `etc/config.json` 里的 `port`，
  然后在应用中心点一次「设置」保存以重启生效。

### 方式 B：脚本安装（不用应用中心）

```bash
# 1. 上传到 NAS（scp 或共享目录都行）
scp -r disk-wake-monitor root@<NAS-IP>:/opt/

# 2. 安装并自动装辅助工具（fatrace + smartmontools）
ssh root@<NAS-IP>
cd /opt/disk-wake-monitor
chmod +x install.sh
./install.sh --with-deps
```

`install.sh` 会完成：复制程序到 `/opt/disk-wake-monitor` → 生成
`/etc/disk-wake-monitor/config.json` → 运行一次环境自检 → 注册并启用 systemd 服务。

**强烈建议先看自检输出**，它会逐项列出：Python 版本、root 权限、fatrace 可用性与
输出格式（JSONL / 文本）、smartctl、block_dump、以及识别到的磁盘和未纳入监控的原因。

```bash
systemctl start disk-wake-monitor    # 启动采集
journalctl -u disk-wake-monitor -f   # 跟日志
```

### 让局域网打开面板

默认出于安全只监听 `127.0.0.1`。要远程访问，改
`/etc/disk-wake-monitor/config.json`：

```json
{ "host": "0.0.0.0", "auth_token": "换成长随机串" }
```

然后 `systemctl restart disk-wake-monitor`，浏览器开 `http://<NAS-IP>:8765/`。
暴露到局域网时**建议设置 token**，或前面挂一层带认证的反代。

---

## 日常使用

### 命令行

```bash
dwmctl probe                 # 环境自检（排障第一站）
dwmctl status                # 磁盘与休眠状态一览
dwmctl wakes --hours 24 -v   # 唤醒记录 + 嫌疑进程 + 判定说明
dwmctl top --hours 24        # 谁访问被监控盘最频繁
dwmctl tail                  # 实时跟踪唤醒
dwmctl tail --events         # 实时跟踪原始访问事件
dwmctl clear --dev sda       # 清除某块盘的记录（--keep-access 只清唤醒）
```

### 按盘清除记录

面板磁盘卡片右上角有「清除」按钮（悬停/触屏时出现），点掉该盘的
唤醒事件、访问明细、电源记录与内存归因样本；命令行等价操作是
`dwmctl clear --dev sda`（多盘 `--dev sda,sdb`）。接口为
`POST /api/clear`，设置过 `auth_token` 时同样受令牌保护。
清除不影响正在进行的监控，之后的新事件照常记录。

### 面板

- **概览**：唤醒次数、未归因数、监控盘数、数据源
- **磁盘状态**：每块盘的休眠/活跃状态、24h 唤醒次数、最近一次唤醒
- **唤醒时间线**：按盘分行，蓝色刻度是 IO 密度，红点就是唤醒
- **唤醒明细**：点击行展开嫌疑进程（含容器名、命令行、命中次数）
- **阻止休眠的元凶**：按访问次数排序，进度条直观显示占比
- 右上角可切 1h / 6h / 24h / 7d；新唤醒会实时推送（SSE）+ 右下角弹提示

---

## 配置

优先级：代码默认值 → `/etc/disk-wake-monitor/config.json` → 环境变量 `DWM_*`。

| 字段 | 默认 | 说明 |
|---|---|---|
| `data_dir` | `/var/lib/disk-wake-monitor` | 数据库目录，**放系统盘**，别放被监控盘 |
| `retention_hours` | 168 | 数据保留时长，过期自动清理 |
| `host` / `port` | 127.0.0.1 / 8765 | 面板监听 |
| `auth_token` | 空 | 非空则 API 需带 `X-DWM-Token` |
| `poll_interval` | 1.0 | diskstats 轮询间隔（秒） |
| `idle_threshold_seconds` | 120 | 多久无 IO 视为「已休眠」 |
| `smart_interval` | 60 | SMART 电源态轮询间隔；**别调太短**（见 FAQ） |
| `assume_sleep_on_idle` | false | USB 盒永远回报 active 时的逃生开关 |
| `monitor_only_sleepable` | true | 只盯外接/可移动机械盘 |
| `monitor_devices` | [] | 强制监控，如 `["sdb"]` |
| `exclude_devices` | [] | 显式排除 |
| `fatrace_filter` | "OCW" | 采集的事件类型（O=open R=read W=write C=close） |
| `suspect_lookahead_seconds` | 3.0 | 归因向后窗口 |
| `log_level` | INFO | 日志级别 |

环境变量同名大写加 `DWM_` 前缀，如 `DWM_MONITOR_DEVICES=sdb,sdc`。

---

## FAQ

**Q：为什么总是「未捕获到归因事件」？**
按顺序查三件事：

1. **面板「数据源」一格**：显示 `源名 · N 事件`。`N=0` 说明事件源根本没产出
   （fanotify 不可用/未 root），此时先跑 `dwmctl probe`；
2. **N>0 但未归因也是 0 事件归属**：数据源一格会显示警示——事件收到了但归属不到盘，
   多半是挂载映射问题（fnOS 经 md/DM 挂到 /vol* 的场景 v1.2.0 已修复，
   老版本升级后重启一次采集）；
3. 事件正常产出且归属正常仍无归因：唤醒来自没有文件层痕迹的路径——内核后台任务
   （btrfs scrub、md 校验、fstrim）、SMART 查询、硬盘盒固件自身。这类唤醒归因
   本来就没有答案，能确认「不是用户进程干的」本身也是有效信息。

**Q：SMART 一直读不到 / 状态永远是 active？**
廉价 USB-SATA 桥接盒常见。程序会自动按 `sat → usbjmicron → usbsunplus` 依次重试；
全都不行就设 `"assume_sleep_on_idle": true`，改为纯「久静后 IO」推断模式。

**Q：轮询 SMART 会不会把盘吵醒？**
`smartctl -n standby` 就是为这个场景设计的——盘在待机时直接退出、不发唤醒命令。
但个别盒子的固件收到任何 SCSI 命令都会转盘，所以默认 60 秒一询，别调更短。

**Q：会不会把「自己」记成元凶？**
不会。自身的 PID 与 `ignore_comms`（fatrace/dmesg/smartctl/dwm 等）都排除在外；
数据库默认放系统盘，工具自己的写入不会落在被监控盘上。

**Q：block_dump 模式有什么代价？**
它只作为内核 5.10 以前的最后兜底（fatrace 装不上且 fanotify 不可用时），只有设备名
没有文件路径，而且会往内核日志里刷大量消息，可能触发 printk 限速丢消息。退出时会自动
还原原值。**内核 5.10 起该功能已被移除**，新版内核上不会启用，也不必再装什么来替代——
内建 fanotify 源已经覆盖了这个场景。

---

## 已知局限

- fanotify 的监视点在事件源启动时建立；**新挂载的外接盘会在 30 秒内触发事件源重启**
  来覆盖，极端情况下插入瞬间的前几秒事件可能丢失
- 归因粒度到进程与容器；SMB/NFS 访问显示为 `smbd`/`nfsd`，远程客户端是谁需要另查
- RAID（md/dm）设备本身被跳过，唤醒归因落在底层 sd* 盘上
- 需要root；非 root 时 fanotify 与 block_dump 都不可用

---

## 开发与验证

```bash
python -m unittest discover -s tests -v      # 单元测试（任意平台可跑）

# 没有飞牛机器也能预览面板：
python tools/demo_data.py --data-dir ./demo-data
DWM_DATA_DIR=./demo-data python -m dwm serve   # 打开 http://127.0.0.1:8765/
```

### 打 fpk 包

```bash
bash tools/build_fpk.sh
# → dist/diskwakemonitor_1.1.0_x86.fpk
```

脚本做六件事，顺序不能省：

1. **同步代码**：`dwm/` `web/` `bin/dwmctl` → `fpk-src/app/`
2. **同步版本号**：`tools/sync_version.py` 把 `dwm/__init__.py` 的 `__version__`
   写进 manifest 的 `version` 与 `changelog`，并与 `CHANGELOG.md` 最新一节
   交叉校验，不一致直接构建失败
3. **生成图标**：`tools/gen_fpk_icons.py` 用标准库画 64/256 两版 PNG
   （应用中心要求两个尺寸且必须不透明）
4. **fnpack build**：官方打包器，会校验 manifest 必填字段、
   `config/privilege` 与 `config/resource` 是否合法 JSON、`app/{desktop_uidir}` 是否存在
5. **重命名为规范文件名**：fnpack 只会产出 `diskwakemonitor.fpk`，
   脚本用 `sync_version.py --name` 派生成 `{appname}_{version}_{platform}.fpk`，
   并把 `dist/` 里的旧版本移入 `dist/archive/`
6. **修执行位**：`tools/fix_fpk_perm.py`

第 6 步不是可选项。**在 Windows 上打出来的包，`cmd/*` 和 `bin/dwmctl`
会丢失执行位（变成 0666），装到飞牛上直接启动失败**——这是 fpk 安装故障的头号原因。
脚本在打包后重写 tar 头，把所有脚本改成 0755。

收尾还有一道校验：**文件名里的版本号、包内 manifest 的 `version`、
代码里的 `__version__` 三者必须完全一致**，任一不符即构建失败——
避免出现「文件名写着 1.1.0、里面是旧代码」这种最难排查的情况。

### 版本号管理

版本号**唯一来源**是 `dwm/__init__.py` 的 `__version__`，其余位置
（manifest、面板页头徽标、`dwmctl --version`、`/api/health`）全部从它派生。
发布新版本的固定动作：

```bash
python tools/bump_version.py 1.2.0 "一句话概述"   # 改 __version__ + 写 CHANGELOG
# 然后补充 CHANGELOG.md 里新小节的其余条目
bash tools/build_fpk.sh                           # 打包时自动同步 manifest 并校验
```

规则：

- `CHANGELOG.md` 最新小节的版本号必须与 `__version__` 一致，`sync_version.py`
  会强制校验；手改 manifest 的 `version` 行会在下次打包时被覆盖回去
- 面板页头的版本徽标读的是 `/api/health` 的 `version`（即运行中的代码版本），
  排障时先对比它与应用中心显示的版本是否一致，不一致说明升级没有真正生效
- 安装日志（`/var/packages/diskwakemonitor/var/install.log`）也记录了版本号
- 产物文件名同样派生自 `__version__`（`diskwakemonitor_1.1.0_x86.fpk`），
  所以 bump 之后不需要改任何构建脚本，文件名自动跟着变
- `python tools/sync_version.py --name` 可单独查看当前版本会产出什么文件名

fnpack 需要单独下载（不随仓库提供）：
<https://developer.fnnas.com/docs/cli/fnpack>，放到 `.build/` 或加进 PATH。

```
fpk-src/             fpk 工程源（manifest / cmd / config / wizard / app/ui）
  manifest           应用元信息（appname、版本、端口、install_type=root）
  cmd/main           启停与状态：start 0 / stop 0 / status 3，setsid 起进程组
  cmd/install_init   安装前拦人：没 python3 或版本过低直接中止
  cmd/install_callback  生成配置、按需装 fatrace/smartmontools、跑 --quick 自检
  cmd/config_callback   设置页保存后合并配置并重启采集
  cmd/upgrade_callback  升级复用 install_callback（幂等），再重启
  config/privilege    run-as: root（fanotify 与 SMART 必需）
  config/resource     usr-local-linker: bin/dwmctl → /usr/local/bin/dwmctl
  wizard/install      安装向导：局域网访问 / 依赖安装 / 保留时长 / USB 盒兼容
tools/build_fpk.sh   打包入口
tools/gen_fpk_icons.py 图标生成
tools/fix_fpk_perm.py  包内权限修正
```

```
dwm/
  config.py        配置加载与集中校验（默认值 → JSON → 环境变量）
  errors.py        类型化错误体系
  logging_setup.py 结构化 JSON 日志
  db.py            SQLite 迁移 + 仓储（device / access / wake / power）
  devices.py       /sys 枚举、USB 总线识别、挂载映射
  diskstats.py     /proc/diskstats 解析与空闲追踪（唤醒地面真值）
  power.py         smartctl 电源态探测（-n standby 不惊醒盘）与启停计数
  procfs.py        /proc 进程补全：命令行、父进程链、容器识别
  sources.py       fatrace（JSONL/文本双格式）与 block_dump 事件源
  correlator.py    双向窗口归因引擎
  collector.py     采集编排：轮询、队列、去重、落库、优雅停机
  server.py        只读 API + SSE + 静态托管（严格 CSP）
  cli.py           dwmctl 命令行
web/               面板（原生 HTML/CSS/JS，无框架无 CDN）
tools/demo_data.py 演示数据生成
```

卸载：应用中心卸载（保留历史），或 `sudo ./install.sh --uninstall` 后手动删
`/var/lib/disk-wake-monitor`。
