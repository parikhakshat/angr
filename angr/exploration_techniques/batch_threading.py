from __future__ import annotations

import concurrent.futures
import logging
import math

from .base import ExplorationTechnique

l = logging.getLogger(__name__)


class BatchThreading(ExplorationTechnique):
    """
    Multithreaded symbolic execution via batched parallel stepping.

    States in the active stash are grouped into equal-sized batches and stepped
    concurrently across a thread pool.  This is beneficial when stepping involves
    z3 constraint solving because z3 releases the Python GIL, enabling true CPU
    parallelism across OS threads.

    Unlike Threading (one state per thread), BatchThreading groups multiple states
    per task to reduce per-task scheduler overhead when the active state set is
    large.  Setting task_multiplier > 1 creates more tasks than threads, which acts
    as a work-stealing queue: a thread that finishes its batch early picks up the
    next task rather than sitting idle waiting for a slow batch.

    Pipelining: a persistent _pending set carries unfinished futures across step()
    calls. On each entry to step(), already-completed futures are harvested first,
    then new batches are submitted, and the method returns without waiting for all
    outstanding work to finish. This allows newly-ready states to keep advancing
    while slower batches from prior rounds are still in flight.
    """

    def __init__(
        self,
        threads=8,
        local_stash="thread_local",
        task_multiplier=4,
        dedupe_key=None,
        drop_deduped=False,
        wait_timeout=0.1,
    ):
        """
        :param threads:         Number of worker threads.
        :param local_stash:     Name of the per-batch stash used inside each worker simgr.
        :param task_multiplier: Tasks submitted per thread.  Values > 1 give work-stealing
                                behaviour and improve load balance when step times vary.
        :param dedupe_key:      Optional callable(state) -> hashable.  States that map to
                                the same key are deduplicated before stepping.  Default None
                                keeps every state (correct for general exploration).
        :param drop_deduped:    When True and dedupe_key is set, remove the duplicates that
                                were not chosen for stepping from the stash.
        """
        super().__init__()
        self.threads = max(1, int(threads))
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.threads)
        self.local_stash = local_stash
        self.task_multiplier = max(1, int(task_multiplier))
        self.dedupe_key = dedupe_key
        self.drop_deduped = drop_deduped
        self.wait_timeout = wait_timeout

        # Persistent across step() calls.
        # _pending: futures submitted but not yet harvested.
        # _queued:  ids of states currently in-flight, excluded from re-submission.
        self._pending: set[concurrent.futures.Future] = set()
        self._queued: set[int] = set()

    # ------------------------------------------------------------------
    # ExplorationTechnique interface
    # ------------------------------------------------------------------

    def step(self, simgr, stash="active", error_list=None, target_stash=None, **kwargs):
        target_stash = target_stash or stash
        if error_list is not None:
            raise ValueError(
                "Can't pass error_list to step with threading enabled. "
                "Did you install threading twice?"
            )

        l.info("BatchThreading stepping %s of %s", stash, simgr)

        # Harvest any futures that finished since the last step() call.
        self._harvest(simgr, stash, block=False)

        # Exclude states already in-flight from this round.
        candidates = [s for s in simgr.stashes[stash] if id(s) not in self._queued]

        # Optional deduplication: only step one representative per key.
        dropped_keys: set = set()
        if self.dedupe_key is not None:
            seen: dict = {}
            deduped = []
            for state in candidates:
                key = self.dedupe_key(state)
                if key in seen:
                    dropped_keys.add(key)
                    continue
                seen[key] = True
                deduped.append(state)
            candidates = deduped

        if not candidates:
            # Nothing new to submit this round. Keep any unfinished futures alive;
            # they will be harvested in future step() calls.
            return simgr

        l.info(
            "Submitting %d states to thread pool (%d threads, task_multiplier=%d)",
            len(candidates),
            self.threads,
            self.task_multiplier,
        )

        # Split candidates into at most (threads * task_multiplier) batches.
        # More batches than threads = work-stealing: idle threads pick up extras.
        max_tasks = min(len(candidates), self.threads * self.task_multiplier)
        states_per_task = math.ceil(len(candidates) / max_tasks)

        for i in range(0, len(candidates), states_per_task):
            batch = tuple(candidates[i : i + states_per_task])
            tsimgr = simgr.copy()
            tsimgr._stashes = {self.local_stash: list(batch)}
            tsimgr._errored = []
            fut = self.executor.submit(
                self._step_batch, batch, tsimgr, target_stash=target_stash, **kwargs
            )
            self._pending.add(fut)
            self._queued.update(id(s) for s in batch)

        # Do not force a barrier here: leave unfinished futures pending so the
        # next step() call can overlap newer work with slower older batches.
        self._harvest(simgr, stash, block=False)

        # Optionally discard duplicate originals that were skipped during dedupe.
        if self.drop_deduped and dropped_keys:
            simgr.stashes[stash] = [
                s
                for s in simgr.stashes[stash]
                if self.dedupe_key(s) not in dropped_keys
            ]

        return simgr

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _step_batch(self, prev_batch, simgr, **kwargs):
        error_list = []
        simgr.step(stash=self.local_stash, error_list=error_list, **kwargs)
        return prev_batch, error_list, simgr

    def _harvest(self, simgr, stash: str, *, block: bool) -> None:
        """
        Collect finished futures and merge their results back into simgr.

        When block=True, waits until self._pending is fully drained.
        When block=False, only collects futures that are already done.
        """
        if not self._pending:
            return

        timeout = self.wait_timeout if block else 0
        stepped_ids: set[int] = set()

        while self._pending:
            done, self._pending = concurrent.futures.wait(
                self._pending,
                timeout=timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                break

            for fut in done:
                prev_batch, worker_errors, tsimgr = fut.result()
                simgr.absorb(tsimgr)
                simgr.errored.extend(worker_errors)
                ids = {id(s) for s in prev_batch}
                stepped_ids.update(ids)
                self._queued.difference_update(ids)

            # After the first completion, poll without blocking so we drain
            # whatever else finished in the meantime before returning.
            timeout = 0

        if stepped_ids:
            simgr.stashes[stash] = [
                s for s in simgr.stashes[stash] if id(s) not in stepped_ids
            ]
