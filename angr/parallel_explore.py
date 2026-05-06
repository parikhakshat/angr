#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from multiprocessing import Queue

import angr
from angr.exploration_techniques import Explorer
from angr.utils.mp import mp_context


def _explore_worker(
    binary_path: str,
    project_kwargs: dict,
    find_addrs: list[int],
    avoid_addrs: list[int],
    warmup_steps: int,
    max_steps: int,
    num_find: int,
    stop_event,
    shared_count,
    count_lock,
    result_queue: Queue,
):
    """
    Each worker creates its own angr Project from binary_path using project_kwargs,
    then runs its own warmup and exploration independently.

    Keeping project creation inside the worker avoids the cross-project state
    mismatch that occurs when states produced by the parent process (tied to the
    parent's Project object) are handed to a child that creates a different Project
    instance.  With fork(), the parent's in-memory objects are copied, but the child
    then creates a *second* Project and attaches the old states to it, which leads to
    stale knowledge-base and loader references.
    """
    project = angr.Project(binary_path, **project_kwargs)
    state = project.factory.entry_state()
    simgr = project.factory.simulation_manager(state, save_unsat=False)

    if warmup_steps > 0:
        simgr.run(n=warmup_steps)

    simgr.use_technique(
        Explorer(
            find=set(find_addrs) if find_addrs else None,
            avoid=set(avoid_addrs) if avoid_addrs else None,
            num_find=num_find,
        )
    )

    for _ in range(max_steps):
        if stop_event.is_set() or not simgr.active:
            break
        simgr.step()
        found = simgr.stashes.get("found", [])
        if not found:
            continue

        reported = 0
        for st in found:
            with count_lock:
                if shared_count.value >= num_find:
                    stop_event.set()
                    break
                shared_count.value += 1
                reported += 1
                result_queue.put({"addr": st.addr, "depth": st.history.depth})
                if shared_count.value >= num_find:
                    stop_event.set()
                    break
        if reported:
            simgr.stashes["found"] = []


def run_multiprocess_explore(
    binary_path: str,
    find_addrs: list[int],
    avoid_addrs: list[int] | None = None,
    num_processes: int = 4,
    warmup_steps: int = 8,
    max_steps: int = 200,
    num_find: int = 1,
    project_kwargs: dict | None = None,
    join_timeout: float | None = None,
) -> list[dict]:
    """
    Spawn num_processes worker processes that each independently explore the binary
    starting from a fresh project + warmup.

    :param binary_path:     Path to the target binary.
    :param find_addrs:      Addresses to find.
    :param avoid_addrs:     Addresses to avoid.
    :param num_processes:   Number of worker processes.
    :param warmup_steps:    Number of steps each worker runs before attaching Explorer.
    :param max_steps:       Maximum exploration steps per worker.
    :param num_find:        Total number of find-state results to collect before stopping.
    :param project_kwargs:  Keyword arguments forwarded to angr.Project in each worker.
                            Defaults to {"auto_load_libs": False}.  Pass custom
                            load_options here for blob binaries or special architectures.
    :param join_timeout:    Seconds to wait for each worker process before terminating it.
                            None means wait indefinitely.
    :returns:               List of result dicts (keys: addr, depth), up to num_find.
    """
    ctx = mp_context()
    avoid_addrs = avoid_addrs or []
    project_kwargs = project_kwargs if project_kwargs is not None else {"auto_load_libs": False}

    stop_event = ctx.Event()
    shared_count = ctx.Value("i", 0)
    count_lock = ctx.Lock()
    result_queue = ctx.Queue()

    procs = []
    for _ in range(num_processes):
        proc = ctx.Process(
            target=_explore_worker,
            args=(
                binary_path,
                project_kwargs,
                find_addrs,
                avoid_addrs,
                warmup_steps,
                max_steps,
                num_find,
                stop_event,
                shared_count,
                count_lock,
                result_queue,
            ),
            daemon=True,
        )
        proc.start()
        procs.append(proc)

    for proc in procs:
        proc.join(timeout=join_timeout)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()

    results = []
    while not result_queue.empty():
        try:
            results.append(result_queue.get_nowait())
        except Exception:
            break
    return results[:num_find]


def run_distributed_server(
    binary_path: str,
    find_addrs: list[int],
    avoid_addrs: list[int] | None = None,
    num_find: int = 1,
    max_workers: int | None = None,
    max_states: int = 10,
    staging_max: int = 10,
) -> list[dict]:
    project = angr.Project(binary_path, auto_load_libs=False)
    found = []
    holder = {}

    def _on_worker_exit(_, stashes):
        found.extend(
            {"addr": s.addr, "depth": s.history.depth}
            for s in stashes.get("found", [])
        )
        if len(found) >= num_find:
            holder["server"].stop()

    server = angr.Server(
        project=project,
        max_workers=max_workers,
        max_states=max_states,
        staging_max=staging_max,
        techniques=[
            Explorer(
                find=set(find_addrs) if find_addrs else None,
                avoid=set(avoid_addrs) if avoid_addrs else None,
                num_find=num_find,
            )
        ],
        worker_exit_callback=_on_worker_exit,
    )
    holder["server"] = server
    server.run()
    return found[:num_find]


def parse_args():
    parser = argparse.ArgumentParser(description="Parallel path exploration helpers.")
    parser.add_argument("binary", help="Path to target binary")
    parser.add_argument("--find", nargs="+", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--avoid", nargs="+", type=lambda x: int(x, 0), default=[])
    parser.add_argument("--mode", choices=("multiprocess", "distributed"), default="multiprocess")
    parser.add_argument("--num-find", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=200)
    parser.add_argument("--processes", type=int, default=4)
    parser.add_argument("--warmup-steps", type=int, default=8)
    parser.add_argument("--max-workers", type=int, default=None)
    parser.add_argument("--join-timeout", type=float, default=None,
                        help="Per-process join timeout in seconds (default: wait indefinitely)")
    return parser.parse_args()


def main():
    args = parse_args()
    binary_path = os.path.abspath(args.binary)
    if args.mode == "multiprocess":
        results = run_multiprocess_explore(
            binary_path=binary_path,
            find_addrs=args.find,
            avoid_addrs=args.avoid,
            num_processes=args.processes,
            warmup_steps=args.warmup_steps,
            max_steps=args.max_steps,
            num_find=args.num_find,
            join_timeout=args.join_timeout,
        )
    else:
        results = run_distributed_server(
            binary_path=binary_path,
            find_addrs=args.find,
            avoid_addrs=args.avoid,
            num_find=args.num_find,
            max_workers=args.max_workers,
        )

    print(f"mode={args.mode} results={len(results)}")
    for i, result in enumerate(results):
        print(f"[{i}] addr={hex(result['addr'])} depth={result['depth']}")


if __name__ == "__main__":
    main()
