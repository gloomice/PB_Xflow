# -*- coding: utf-8 -*-
"""
PB X-Flow 压测脚本：生成大量小文件 + 高队列/多线程，可选 -bfs。
用法:
  python scripts/stress_pb_xflow.py
  python scripts/stress_pb_xflow.py --files 8000 --threads 16 --queue 4000 -bfs
  set PB_XFLOW_EXE=D:\\path\\pb_xflow.exe && python scripts/stress_pb_xflow.py --smoke

退出码: 0=成功, 1=失败, 2=未找到引擎可执行文件
"""
from __future__ import annotations

import argparse
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _default_exe_candidates() -> list[Path]:
    root = _repo_root()
    env = os.environ.get("PB_XFLOW_EXE", "").strip()
    out: list[Path] = []
    if env:
        out.append(Path(env))
    out.append(root / "pb_xflow.exe")
    for sub in (
        root / "Output" / "Release" / "x64" / "FastCopy.exe",
        root / "Output" / "Debug" / "x64" / "FastCopy.exe",
        root / "Output" / "Release" / "Win32" / "FastCopy.exe",
    ):
        out.append(sub)
    return out


def resolve_engine_exe() -> Path | None:
    for p in _default_exe_candidates():
        if p.is_file():
            return p
    return None


def write_random_file(path: Path, size_bytes: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if size_bytes <= 0:
        path.write_bytes(b"")
        return
    chunk = min(256 * 1024, size_bytes)
    remaining = size_bytes
    with open(path, "wb") as f:
        while remaining > 0:
            n = min(chunk, remaining)
            f.write(os.urandom(n))
            remaining -= n


def build_flat_tree(
    src: Path,
    num_files: int,
    size_kb: int,
    subdirs: int,
) -> None:
    """生成 flat + 可选多个子目录均分文件。"""
    if subdirs <= 0:
        for i in range(num_files):
            write_random_file(src / f"stress_{i:07d}.bin", size_kb * 1024)
        return
    per = max(1, num_files // subdirs)
    idx = 0
    for d in range(subdirs):
        sub = src / f"bucket_{d:04d}"
        for _ in range(per):
            if idx >= num_files:
                return
            write_random_file(sub / f"f_{idx:07d}.bin", size_kb * 1024)
            idx += 1
    while idx < num_files:
        write_random_file(src / f"stress_{idx:07d}.bin", size_kb * 1024)
        idx += 1


def count_files_under(p: Path) -> int:
    n = 0
    for _root, _dirs, files in os.walk(p):
        n += len(files)
    return n


def md5_file(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_trees_equal(src: Path, dst: Path, sample: int) -> tuple[bool, str]:
    """抽样比对：随机抽 sample 个文件做 MD5（全量比对应海量文件过慢）。"""
    all_rel: list[Path] = []
    for root, _, files in os.walk(src):
        r = Path(root)
        for name in files:
            all_rel.append((r / name).relative_to(src))
    if not all_rel:
        return False, "源树无文件"
    rng = random.Random(42)
    pick = all_rel if len(all_rel) <= sample else rng.sample(all_rel, sample)
    for rel in pick:
        s, d = src / rel, dst / rel
        if not d.is_file():
            return False, f"目标缺失: {rel}"
        if md5_file(s) != md5_file(d):
            return False, f"MD5 不一致: {rel}"
    return True, f"抽样 {len(pick)}/{len(all_rel)} 文件 MD5 一致"


def run_stress(args: argparse.Namespace) -> int:
    exe = resolve_engine_exe()
    if not exe:
        print(
            "未找到引擎。请设置 PB_XFLOW_EXE 或将 pb_xflow.exe / FastCopy.exe 放在仓库根或 Output\\Release\\x64\\",
            file=sys.stderr,
        )
        return 2

    num_files = max(10, args.files)
    work = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="pb_xflow_stress_"))
    src = work / "src"
    dst = work / "dst"
    if args.clean and work.exists():
        shutil.rmtree(work, ignore_errors=True)
    src.mkdir(parents=True, exist_ok=True)
    dst.mkdir(parents=True, exist_ok=True)

    print(f"引擎: {exe}")
    print(f"工作目录: {work}")
    print(f"生成 {num_files} 个文件 (每文件 {args.size_kb} KB), 子目录数={args.subdirs} ...")
    t0 = time.perf_counter()
    build_flat_tree(src, num_files, args.size_kb, args.subdirs)
    print(f"生成耗时: {time.perf_counter() - t0:.2f}s")

    cmd: list[str] = [
        str(exe),
        "-s",
        str(src),
        "-d",
        str(dst),
        "-t",
        str(args.threads),
        "-Q",
        str(args.queue),
        "-J",
        "-j",
        str(args.iouring_batch),
    ]
    if args.bfs:
        cmd.append("-bfs")
    if args.fast:
        cmd.append("-F")
    if args.verify_xxh:
        cmd.append("-X")
    cmd.extend(args.extra)

    print("命令:", " ".join(cmd))
    timeout = None if args.timeout <= 0 else args.timeout
    t1 = time.perf_counter()
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print("引擎超时（可用 --timeout 0 取消限制）", file=sys.stderr)
        return 1

    elapsed = time.perf_counter() - t1
    print(f"引擎返回码: {r.returncode}, 耗时: {elapsed:.2f}s")
    if r.stdout:
        print("--- stdout (tail) ---")
        lines = r.stdout.strip().splitlines()
        for line in lines[-40:]:
            print(line)
    if r.stderr:
        print("--- stderr (tail) ---")
        lines = r.stderr.strip().splitlines()
        for line in lines[-20:]:
            print(line, file=sys.stderr)

    if r.returncode != 0:
        print("压测失败: 非零退出码", file=sys.stderr)
        return 1

    n_src = count_files_under(src)
    n_dst = count_files_under(dst)
    if n_dst != n_src:
        print(f"文件数不一致: 源={n_src} 目标={n_dst}", file=sys.stderr)
        return 1

    ok, msg = verify_trees_equal(src, dst, args.verify_sample)
    print(msg)
    if not ok:
        return 1

    if args.keep:
        print(f"保留工作目录: {work}")
    else:
        try:
            shutil.rmtree(work, ignore_errors=True)
        except OSError:
            pass
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="PB X-Flow 压力测试（大量小文件 + 高队列）")
    p.add_argument("--files", type=int, default=3000, help="生成文件数量")
    p.add_argument("--size-kb", type=int, default=4, dest="size_kb", help="单文件大小 KB")
    p.add_argument("--subdirs", type=int, default=0, help=">0 时均分到若干子目录（模拟目录扇出）")
    p.add_argument("--threads", "-t", type=int, default=12, help="-t 线程数")
    p.add_argument("--queue", "-Q", type=int, default=2000, help="-Q 队列深度")
    p.add_argument("--iouring-batch", "-j", type=int, default=128, dest="iouring_batch", help="-j IoRing 批大小")
    p.add_argument("--bfs", action="store_true", help="启用 -bfs（BFS 扫描 + 旁路队列压测）")
    p.add_argument("--fast", "-F", action="store_true", help="传递 -F")
    p.add_argument("--verify-xxh", action="store_true", help="传递 -X（更慢）")
    p.add_argument("--verify-sample", type=int, default=80, help="抽样校验文件数")
    p.add_argument("--timeout", type=int, default=600, help="秒；0=不限制")
    p.add_argument("--workdir", type=str, default="", help="固定工作目录（默认临时目录）")
    p.add_argument("--keep", action="store_true", help="不删除临时目录")
    p.add_argument("--clean", action="store_true", help="若 workdir 已存在则先删除")
    p.add_argument("--smoke", action="store_true", help="极小数据量快速冒烟")
    p.add_argument("extra", nargs="*", help="附加传递给引擎的参数")
    args = p.parse_args()
    if args.smoke:
        args.files = 120
        args.queue = min(args.queue, 512)
        args.timeout = min(args.timeout, 120) if args.timeout > 0 else 120
    return run_stress(args)


if __name__ == "__main__":
    sys.exit(main())
