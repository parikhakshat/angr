from __future__ import annotations

import concurrent.futures
import logging
import math

from .base import ExplorationTechnique

l = logging.getLogger(__name__)


class BatchThreading(ExplorationTechnique):
    """
    Enable multithreading.

    This is only useful in paths where a lot of time is taken inside z3, doing constraint solving.
    This is because of python's GIL, which says that only one thread at a time may be executing python code.
    """

    def __init__(self, threads=8, local_stash="thread_local"):
        super().__init__()
        self.threads = threads
        self.tasks = set()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
        self.local_stash = local_stash

    def step(self, simgr, stash="active", error_list=None, target_stash=None, **kwargs):
        target_stash = target_stash or stash
        if error_list is not None:
            raise ValueError("Can't pass error_list to step with threading enabled. Did you install threading twice?")

        l.info("Thread-stepping %s of %s", stash, simgr)
        simgr_stash = []
        simgr_set = set()
        for state in simgr.stashes[stash]:
            if state.ip not in simgr_set:
                simgr_set.add(state.ip)
                simgr_stash.append(state)
        l.info("Number of states in stash %s", len(simgr_stash))

        states_per_thread = math.ceil(len(simgr_stash) / self.threads)

        for i in range(0, len(simgr_stash), states_per_thread):
            local_stash = simgr_stash[i:i+states_per_thread]
            tsimgr = simgr.copy()
            tsimgr._stashes = {self.local_stash: local_stash}
            tsimgr._errored = []
            self.tasks.add(self.executor.submit(self.inner_step, tuple(local_stash), tsimgr, target_stash=target_stash, **kwargs))

        timeout = None
        while True:
            done, self.tasks = concurrent.futures.wait(
                self.tasks, timeout=timeout, return_when=concurrent.futures.FIRST_COMPLETED
            )
            if not done:
                break

            for done_future in done:
                done_future: concurrent.futures.Future
                prev_stash, error_list, tsimgr = done_future.result()
                simgr.absorb(tsimgr)
                simgr.errored.extend(error_list)
                curr_stashes = {}
                for state in simgr.stashes[stash]:
                    curr_stashes[state.ip] = state
                for state in prev_stash:
                    if state.ip in curr_stashes:
                        simgr.stashes[stash].remove(curr_stashes[state.ip])
            timeout = 0

        return simgr

    def inner_step(self, prev_stash, simgr, **kwargs):
        error_list = []
        simgr.step(stash=self.local_stash, error_list=error_list, **kwargs)
        return prev_stash, error_list, simgr
