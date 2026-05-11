#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import os
import queue
import threading
from collections.abc import Callable, Hashable

import angr
from angr.exploration_techniques import Explorer
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from angr.utils.mp import mp_context


LOCAL_STASH = "thread_local"
_STOP = object()


def _default_dedupe_key(state: SimState) -> Hashable:
    """
    Cheap fingerprint for pruning redundant queue work. Distinct symbolic states can
    share the same key (unsound pruning); pass ``dedupe_key=`` for stricter keys.
    """
    return (state.addr, state.history.block_count)


def _step_batch(
    wsimgr: SimulationManager,
    batch: list[SimState],
    local_stash: str = LOCAL_STASH,
) -> dict:
    """Single symbolic step for ``batch`` on this worker's persistent ``wsimgr`` instance."""
    if not batch:
        return {"found": [], "active": [], "deadended": [], "avoid": [], "errored": []}

    wsimgr._stashes = {local_stash: list(batch)}
    error_list: list = []
    wsimgr.step(stash=local_stash, error_list=error_list)

    return {
        "found": list(wsimgr.stashes.get("found", [])),
        "active": list(wsimgr.stashes.get(local_stash, [])),
        "deadended": list(wsimgr.stashes.get("deadended", [])),
        "avoid": list(wsimgr.stashes.get("avoid", [])),
        "errored": error_list,
    }


def _explore_worker_thread(
    template_simgr: SimulationManager,
    work_q: queue.Queue,
    result_q: queue.Queue,
):
    """
    One ``template_simgr.copy()`` per thread, then step each batch on that copy only.
    """
    wsimgr = template_simgr.copy()
    while True:
        item = work_q.get()
        try:
            if item is _STOP:
                return
            payload = _step_batch(wsimgr, batch=item)
            result_q.put(payload)
        finally:
            work_q.task_done()


def _chunk_frontier(states: list[SimState], max_batches: int) -> list[list[SimState]]:
    if not states:
        return []
    max_batches = max(1, max_batches)
    chunk_sz = math.ceil(len(states) / max_batches)
    return [states[i : i + chunk_sz] for i in range(0, len(states), chunk_sz)]


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
    task_multiplier: int = 4,
    dedupe_key: Callable[[SimState], Hashable] | None = None,
) -> list[dict]:
    """
    Multithreaded exploration: the main thread builds :class:`angr.Project` and
    :class:`angr.SimulationManager`, optional warmup, then attaches :class:`Explorer`.
    Worker threads each call ``simulation_manager.copy()`` once, then step every
    batch on that worker-local copy so states stay tied to the same ``Project``.

    After every symbolic step, the coordinator merges ``found``, ``active``,
    ``deadended``, and ``avoid`` stashes from all workers, records results, and
    schedules only deduplicated active states for the next step. States classified
    as found / deadended / avoid are never re-queued.

    :param num_processes:   Number of worker threads (name kept for CLI compatibility).
    :param task_multiplier: At most ``num_processes * task_multiplier`` batches per step
                            (finer batches improve load balance across threads).
    :param dedupe_key:      Optional ``state -> hashable``; default uses ``(addr, block_count)``
                            (may merge distinct symbolic states).
    :param join_timeout:    Ignored in the threaded implementation (kept for API compatibility).
    """
    del join_timeout  # threading joins are quick; kept for call-site compatibility

    avoid_addrs = avoid_addrs or []
    project_kwargs = project_kwargs if project_kwargs is not None else {"auto_load_libs": False}
    key_fn = dedupe_key or _default_dedupe_key

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

    template_simgr = simgr
    stop_event = threading.Event()
    work_q: queue.Queue = queue.Queue()
    result_q: queue.Queue = queue.Queue()

    workers = [
        threading.Thread(
            target=_explore_worker_thread,
            args=(template_simgr, work_q, result_q),
            daemon=True,
        )
        for _ in range(max(1, num_processes))
    ]
    for t in workers:
        t.start()

    results: list[dict] = []
    reported_found_keys: set[Hashable] = set()
    scheduled_keys: set[Hashable] = set()
    terminal_keys: set[Hashable] = set()

    frontier: list[SimState] = []
    for s in template_simgr.active:
        k = key_fn(s)
        if k in terminal_keys or k in scheduled_keys:
            continue
        scheduled_keys.add(k)
        frontier.append(s)

    try:
        for _ in range(max_steps):
            if stop_event.is_set() or template_simgr.complete() or not frontier:
                break

            frontier = [s for s in frontier if key_fn(s) not in terminal_keys]
            if not frontier:
                break

            max_tasks = min(len(frontier), max(1, num_processes * task_multiplier))
            batches = _chunk_frontier(frontier, max_tasks)

            for batch in batches:
                work_q.put(batch)

            work_q.join()

            merged_found: list[SimState] = []
            merged_active: list[SimState] = []
            merged_dead: list[SimState] = []
            merged_avoid: list[SimState] = []

            for _ in range(len(batches)):
                payload = result_q.get()
                merged_found.extend(payload["found"])
                merged_active.extend(payload["active"])
                merged_dead.extend(payload["deadended"])
                merged_avoid.extend(payload["avoid"])
                template_simgr.errored.extend(payload["errored"])

            for s in merged_dead:
                terminal_keys.add(key_fn(s))
            for s in merged_avoid:
                terminal_keys.add(key_fn(s))

            for s in merged_found:
                fk = key_fn(s)
                terminal_keys.add(fk)
                if fk not in reported_found_keys:
                    reported_found_keys.add(fk)
                    if len(results) < num_find:
                        results.append({"addr": s.addr, "depth": s.history.depth})
                    template_simgr.stashes["found"].append(s)

            if len(results) >= num_find or template_simgr.complete():
                stop_event.set()
                break

            next_frontier: list[SimState] = []
            for s in merged_active:
                k = key_fn(s)
                if k in terminal_keys or k in scheduled_keys:
                    continue
                scheduled_keys.add(k)
                next_frontier.append(s)

            frontier = next_frontier
    finally:
        stop_event.set()
        for _ in workers:
            work_q.put(_STOP)
        for t in workers:
            t.join(timeout=30)

    return results[:num_find]


def _mp_explore_worker(
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
    result_queue,
):
    """
    Each process builds its own :class:`angr.Project` so states are never moved across
    distinct project instances (states are not reliably picklable for shared queues).
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


def run_multiprocessing_explore(
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
    Spawn ``num_processes`` worker processes; each loads the binary with ``project_kwargs``,
    runs warmup, attaches :class:`Explorer`, and steps independently until ``num_find`` hits
    are reported globally or ``max_steps`` is exhausted.
    """
    ctx = mp_context()
    avoid_addrs = avoid_addrs or []
    project_kwargs = project_kwargs if project_kwargs is not None else {"auto_load_libs": False}

    stop_event = ctx.Event()
    shared_count = ctx.Value("i", 0)
    count_lock = ctx.Lock()
    result_queue = ctx.Queue()

    procs = []
    for _ in range(max(1, num_processes)):
        proc = ctx.Process(
            target=_mp_explore_worker,
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
    project_kwargs: dict | None = None,
) -> list[dict]:
    pk = project_kwargs if project_kwargs is not None else {"auto_load_libs": False}
    project = angr.Project(binary_path, **pk)
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
    parser.add_argument("--processes", type=int, default=4, help="Number of exploration worker threads")
    parser.add_argument("--warmup-steps", type=int, default=8)
    parser.add_argument(
        "--task-multiplier",
        type=int,
        default=4,
        help="Up to processes*task_multiplier batches per symbolic step (finer = better load balance)",
    )
    parser.add_argument("--max-workers", type=int, default=None)
    parser.add_argument(
        "--join-timeout",
        type=float,
        default=None,
        help="Unused for threaded mode; reserved for API compatibility",
    )
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
            task_multiplier=args.task_multiplier,
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
