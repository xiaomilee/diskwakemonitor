"""命令行入口。

dwmctl probe 是排障第一站：它把「环境是否支持」逐项列出来，
不用启动采集就能知道 fatrace / smartctl / 权限 / 挂载识别哪里有问题。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__
from . import db as dbm
from .config import Config, load
from .core_check import probe_environment
from .errors import DwmError
from .logging_setup import setup


# ---------------------------------------------------------------------------
# 格式化
# ---------------------------------------------------------------------------
def fmt_ts(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%m-%d %H:%M:%S", time.localtime(ts))


def fmt_idle(seconds: Optional[float]) -> str:
    if seconds is None:
        return "-"
    seconds = float(seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def fmt_bytes(value: int) -> str:
    size = float(value or 0)
    for unit in ("B", "K", "M", "G", "T", "P"):
        if size < 1024 or unit == "P":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}P"


def conf_label(confidence: str) -> str:
    return {"smart": "SMART确认", "state": "电源态", "inferred": "推断"}.get(
        confidence, confidence
    )


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
def cmd_probe(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    report = probe_environment(cfg, deep=not args.quick)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["summary"]["blocking"] == 0 else 2

    print(f"disk-wake-monitor v{__version__} 环境自检")
    print("=" * 62)
    for item in report["checks"]:
        mark = {"ok": "✔", "warn": "!", "fail": "✘"}.get(item["level"], "?")
        print(f" [{mark}] {item['name']}: {item['detail']}")
        if item.get("hint"):
            print(f"      → {item['hint']}")

    print("-" * 62)
    devices = report.get("devices", [])
    if devices:
        print("块设备识别：")
        for dev in devices:
            flag = "监控" if dev["monitored"] else "跳过"
            print(
                f"  [{flag}] {dev['name']:<8} {dev['transport']:<7} "
                f"{'机械' if dev['rotational'] else '固态'} "
                f"{fmt_bytes(dev['size_bytes']):>7}  {dev['model'][:24]}"
            )
            if dev["mounts"]:
                print(f"           挂载点：{', '.join(dev['mounts'])}")
            if not dev["monitored"]:
                print(f"           原因：{dev['reason']}")
    else:
        print("块设备识别：未发现任何块设备")

    print("-" * 62)
    summary = report["summary"]
    print(
        f"结论：阻塞项 {summary['blocking']} 个，提醒项 {summary['warnings']} 个，"
        f"可监控设备 {summary['monitored_devices']} 个"
    )
    if summary["blocking"]:
        print("存在阻塞项，先按上面的提示修掉再启动采集。")
    elif summary["monitored_devices"] == 0:
        print(
            "环境没问题，但没识别到「会休眠的盘」。"
            "请用 DWM_MONITOR_DEVICES=sdb 之类显式指定要监控的盘。"
        )
    else:
        print("可以直接启动：systemctl start disk-wake-monitor")
    return 0 if summary["blocking"] == 0 else 2


def _open_ro(cfg: Config):
    if not os.path.isfile(cfg.resolved_db_path):
        print(
            f"数据库不存在：{cfg.resolved_db_path}\n"
            "先启动采集：systemctl start disk-wake-monitor 或 dwmctl run",
            file=sys.stderr,
        )
        return None
    return dbm.connect(cfg.resolved_db_path)


def cmd_status(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    conn = _open_ro(cfg)
    if conn is None:
        return 1
    try:
        devices = dbm.DeviceRepo(conn).all()
        wake_repo = dbm.WakeRepo(conn)
        last = wake_repo.last_by_device()
        counts = wake_repo.count_by_device(time.time() - 24 * 3600)
        power = dbm.PowerRepo(conn).latest_by_device()

        print(f"{'设备':<9}{'状态':<9}{'挂载点':<26}{'24h唤醒':>8}  {'最近唤醒'}")
        print("-" * 78)
        for row in devices:
            if not row["monitored"]:
                continue
            name = row["name"]
            power_row = power.get(name)
            state = power_row["state"] if power_row else "unknown"
            state_label = {"active": "活跃", "standby": "休眠", "unknown": "未知"}.get(
                state, state
            )
            mounts = (row["mounts"] or "").replace(",", " ") or "-"
            wake_row = last.get(name)
            print(
                f"{name:<9}{state_label:<9}{mounts[:24]:<26}"
                f"{counts.get(name, 0):>8}  "
                f"{fmt_ts(wake_row['ts']) if wake_row else '-'}"
            )
        missing = [r["name"] for r in devices if not r["monitored"]]
        if missing:
            print(f"\n未监控：{', '.join(missing)}（见 dwmctl probe 的原因说明）")
        unmounted = [
            r["name"] for r in devices if r["monitored"] and not (r["mounts"] or "").strip()
        ]
        if unmounted:
            print(
                f"\n警告：{', '.join(unmounted)} 没有挂载点，"
                "文件级事件无法归属（会全部落进 no_dev）。运行 dwmctl probe 查看挂载点映射。",
                file=sys.stderr,
            )
    finally:
        conn.close()
    return 0


def cmd_wakes(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    conn = _open_ro(cfg)
    if conn is None:
        return 1
    try:
        wake_repo = dbm.WakeRepo(conn)
        rows = wake_repo.recent(hours=args.hours, dev=args.dev, limit=args.limit)
        if not rows:
            print(f"最近 {args.hours:g} 小时内没有捕获到唤醒事件。")
            return 0

        ids = [r["id"] for r in rows]
        suspects = wake_repo.suspects_map(ids)
        print(f"最近 {args.hours:g} 小时唤醒记录（{len(rows)} 条）")
        print("=" * 100)
        for row in rows:
            print(
                f"#{row['id']:<5} {fmt_ts(row['ts'])}  {row['dev']:<7} "
                f"空闲 {fmt_idle(row['idle_seconds']):>7}  "
                f"[{conf_label(row['confidence'])}]"
            )
            items = suspects.get(row["id"], [])
            if not items:
                print("        归因：未捕获到访问事件（看 note 说明）")
            for item in items[: args.suspects]:
                container = f" @{item['container']}" if item["container"] else ""
                tags = []
                keys = item.keys()
                phase = item["phase"] if "phase" in keys else "pre"
                if phase == "post":
                    tags.append("唤醒后涌入")
                elif phase == "block":
                    tags.append("块层证据")
                if "ambiguous" in keys and item["ambiguous"]:
                    tags.append("多盘歧义")
                tag = f"  [{'/'.join(tags)}]" if tags else ""
                print(
                    f"        ├ {item['comm']}({item['pid']}){container}{tag} "
                    f"命中 {item['hits']} 次  "
                    f"{item['sample_path'][:56] or item['cmdline'][:56]}"
                )
            if args.verbose and row["note"]:
                print(f"        └ {row['note']}")
        return 0
    finally:
        conn.close()


def cmd_top(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    conn = _open_ro(cfg)
    if conn is None:
        return 1
    try:
        rows = dbm.AccessRepo(conn).offenders(hours=args.hours, limit=args.limit)
        if not rows:
            print(f"最近 {args.hours:g} 小时没有被监控磁盘的访问记录。")
            return 0
        print(f"最近 {args.hours:g} 小时访问被监控磁盘最多的进程")
        print("=" * 92)
        print(f"{'磁盘':<8}{'进程':<24}{'容器':<22}{'次数':>7}  {'最近一次'}")
        print("-" * 92)
        for row in rows:
            container = (row["container"] or "-")[:20]
            comm = (row["comm"] or "-")[:22]
            print(
                f"{row['dev']:<8}{comm:<24}{container:<22}"
                f"{row['hits']:>7}  {fmt_ts(row['last_ts'])}"
            )
        print(
            "\n提示：如果某个进程的访问密集且间隔小于硬盘休眠时间，"
            "它就是「阻止休眠」的元凶，而不是「唤醒」的元凶。"
        )
        return 0
    finally:
        conn.close()


def cmd_tail(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    conn = _open_ro(cfg)
    if conn is None:
        return 1

    label = "访问事件" if args.events else "唤醒事件"
    print(f"跟踪{label}中，Ctrl+C 退出")
    last_seen = time.time()
    access_repo = dbm.AccessRepo(conn)
    wake_repo = dbm.WakeRepo(conn)

    try:
        while True:
            batch = []
            if args.events:
                batch = [
                    row
                    for row in access_repo.recent(
                        minutes=1, dev=args.dev, limit=200
                    )
                    if row["ts"] > last_seen
                ]
                for row in reversed(batch):
                    print(
                        f"{fmt_ts(row['ts'])}  {row['dev']:<7} {row['op']:<3} "
                        f"{row['comm']}({row['pid']})  {row['path'][:70]}"
                    )
            else:
                batch = [
                    row
                    for row in wake_repo.recent(hours=1, dev=args.dev, limit=100)
                    if row["ts"] > last_seen
                ]
                for row in reversed(batch):
                    print(
                        f"{fmt_ts(row['ts'])}  {row['dev']:<7} "
                        f"空闲 {fmt_idle(row['idle_seconds'])} "
                        f"嫌疑 {row['suspect_count']} 个  "
                        f"[{conf_label(row['confidence'])}]"
                    )
            if batch:
                last_seen = max(row["ts"] for row in batch)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        conn.close()
    return 0


def cmd_clear(args: argparse.Namespace) -> int:
    """按盘清除记录：唤醒事件必清，访问/电源记录按 --keep-access 保留。"""
    cfg = load(args.config)
    if not os.path.isfile(cfg.resolved_db_path):
        print(f"数据库不存在：{cfg.resolved_db_path}", file=sys.stderr)
        return 1

    conn = dbm.connect(cfg.resolved_db_path)
    try:
        wake_repo = dbm.WakeRepo(conn)
        known = {r["name"] for r in dbm.DeviceRepo(conn).all()}
        monitored = set(dbm.DeviceRepo(conn).monitored_names())
        targets = [d.strip() for d in args.dev.split(",") if d.strip()]
        if not targets:
            print("用法示例：dwmctl clear --dev sda   （多盘用逗号：--dev sda,sdb）")
            return 1
        unknown = [d for d in targets if known and d not in known]
        if unknown and not args.force:
            print(
                f"这些设备不在设备表里：{', '.join(unknown)}。\n"
                "确认拼写无误可加 --force 强制执行。",
                file=sys.stderr,
            )
            return 1

        print(f"将删除以下设备的记录：{', '.join(targets)}")
        if args.keep_access:
            print("  唤醒事件：全部删除；访问/电源记录：保留")
        else:
            print("  唤醒事件：全部删除；访问/电源记录：一并删除")
        if not args.yes:
            answer = input("确认删除？输入 yes 继续：").strip().lower()
            if answer not in ("yes", "y"):
                print("已取消")
                return 1

        total = {"wakes": 0, "access": 0, "power": 0}
        for dev in targets:
            total["wakes"] += wake_repo.clear(dev)
            if not args.keep_access:
                total["access"] += dbm.AccessRepo(conn).clear(dev)
                total["power"] += dbm.PowerRepo(conn).clear(dev)
        print(
            f"完成：唤醒 {total['wakes']} 条"
            + ("" if args.keep_access else f"，访问 {total['access']} 条，电源 {total['power']} 条")
        )
        if monitored & set(targets):
            print(
                "注意：这些盘仍在监控中；采集进程内存里的归因样本未清，"
                "重启采集（systemctl restart disk-wake-monitor）可一并清掉。"
            )
        return 0
    finally:
        conn.close()


def cmd_serve(args: argparse.Namespace) -> int:
    """只读模式：不采集，只托管面板读历史数据。"""
    from .server import ApiApp, make_server

    cfg = load(args.config)
    app = ApiApp(cfg)
    server = make_server(cfg, app)
    url = f"http://{cfg.host}:{cfg.port}/"
    print(f"只读面板已启动：{url}")
    print("注意：本模式不采集数据，实时推送不可用。Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        server.server_close()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from .collector import Collector

    cfg = load(args.config)
    setup(cfg.log_level)
    collector = Collector(cfg)

    app = None
    server = None
    if not args.no_web:
        from .server import ApiApp, start_in_thread

        app = ApiApp(
            cfg,
            bus=collector.bus,
            snapshot=collector.snapshot,
            clear_hook=collector.clear_memory,
        )
        server, _thread = start_in_thread(cfg, app)
        print(f"面板地址：http://{cfg.host}:{cfg.port}/")
    else:
        print("仅采集模式，未启动面板")

    try:
        collector.run()
    finally:
        if app is not None:
            app.stopping.set()
        if server is not None:
            server.shutdown()
            server.server_close()
    return 0


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dwmctl",
        description="硬盘唤醒归因工具：查清到底是谁把休眠盘弄醒了。",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config", default=None, help="配置文件路径（默认自动查找 /etc 与当前目录）"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_probe = sub.add_parser("probe", help="环境自检：依赖、权限、设备识别一次性看清")
    p_probe.add_argument("--json", action="store_true", help="输出 JSON")
    p_probe.add_argument("--quick", action="store_true", help="跳过需要 root 的深度检测")
    p_probe.set_defaults(func=cmd_probe)

    p_status = sub.add_parser("status", help="磁盘与休眠状态一览")
    p_status.set_defaults(func=cmd_status)

    p_wakes = sub.add_parser("wakes", help="查看唤醒记录与嫌疑进程")
    p_wakes.add_argument("--hours", type=float, default=24.0)
    p_wakes.add_argument("--dev", default=None, help="只看某个盘，如 sdb")
    p_wakes.add_argument("--limit", type=int, default=30)
    p_wakes.add_argument("--suspects", type=int, default=5, help="每条记录展示几个嫌疑进程")
    p_wakes.add_argument("--verbose", action="store_true", help="显示判定说明")
    p_wakes.set_defaults(func=cmd_wakes)

    p_top = sub.add_parser("top", help="访问被监控磁盘最多的进程排行")
    p_top.add_argument("--hours", type=float, default=24.0)
    p_top.add_argument("--limit", type=int, default=20)
    p_top.set_defaults(func=cmd_top)

    p_tail = sub.add_parser("tail", help="实时跟踪")
    p_tail.add_argument("--events", action="store_true", help="跟踪原始访问事件")
    p_tail.add_argument("--dev", default=None)
    p_tail.add_argument("--interval", type=float, default=2.0)
    p_tail.set_defaults(func=cmd_tail)

    p_clear = sub.add_parser("clear", help="按盘清除唤醒/访问记录（如 --dev sda）")
    p_clear.add_argument("--dev", required=True, help="要清除的盘名，多个用逗号分隔")
    p_clear.add_argument(
        "--keep-access", action="store_true", help="保留访问与电源记录，只清唤醒事件"
    )
    p_clear.add_argument("--yes", action="store_true", help="跳过确认")
    p_clear.add_argument("--force", action="store_true", help="设备不在设备表里也强制执行")
    p_clear.set_defaults(func=cmd_clear)

    p_serve = sub.add_parser("serve", help="只读面板（不采集）")
    p_serve.set_defaults(func=cmd_serve)

    p_run = sub.add_parser("run", help="启动采集 + 面板（systemd 调用的就是这个）")
    p_run.add_argument("--no-web", action="store_true", help="只采集不开面板")
    p_run.set_defaults(func=cmd_run)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except DwmError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        if exc.hint:
            print(f"提示：{exc.hint}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
