#!/usr/bin/env python3

from __future__ import print_function

import argparse
import contextlib
import os
import struct
import time
from dataclasses import dataclass

import angr
from angr.exploration_techniques import BatchThreading

from exploration_technique_logging import configure_exploration_technique_debug, trace_solve_debug_enabled

MAIN_START = 0x4009D4
MAIN_END = 0x00400C18

FLAG_LOCATION = 0x400D80
FLAG_PTR_LOCATION = 0x410EA0


@dataclass
class Phase:
    name: str
    elapsed: float = 0.0
    success: bool = True
    note: str = ""


@contextlib.contextmanager
def profile(phase_name, phases):
    phase = Phase(name=phase_name)
    phases.append(phase)
    started = time.perf_counter()
    try:
        yield phase
    except Exception as exc:
        phase.success = False
        phase.note = str(exc)
        raise
    finally:
        phase.elapsed = time.perf_counter() - started


def print_phase_table(phases):
    col_w = max(len(p.name) for p in phases) + 2
    print("\nProfiling Summary")
    print(f"{'Phase':<{col_w}} {'Time (s)':>10}  Status")
    print("-" * (col_w + 24))
    total = 0.0
    for p in phases:
        status = "OK" if p.success else "FAIL"
        note = f"  <- {p.note}" if p.note else ""
        print(f"{p.name:<{col_w}} {p.elapsed:>10.4f}  {status}{note}")
        total += p.elapsed
    print("-" * (col_w + 24))
    print(f"{'TOTAL':<{col_w}} {total:>10.4f}")


def load_trace():
    res = []
    delay_slots = set()
    with open("./trace_8339a701aae26588966ad9efa0815a0a.log") as f:
        for line in f:
            if line.startswith("[INFO]"):
                addr = int(line[6 : 6 + 8], 16)
                res.append(addr)
                if "move r1, r1" in line:
                    delay_slots.add(addr)
    return res, delay_slots


def main():
    phases = []
    trace_log, delay_slots = load_trace()

    with profile("Binary loading", phases):
        project = angr.Project(
            "./data.bin",
            load_options={
                "main_opts": {
                    "backend": "blob",
                    "base_addr": 0x400770,
                    "arch": "mipsel",
                },
            },
            auto_load_libs=False,
        )

    seed = project.factory.blank_state(addr=MAIN_START)
    seed.memory.store(FLAG_LOCATION, seed.solver.BVS("flag", 8 * 32))
    seed.memory.store(FLAG_PTR_LOCATION, struct.pack("<I", FLAG_LOCATION))

    workers = max(2, min(8, (os.cpu_count() or 2)))

    choices = [seed]

    print("Tracing...")
    with profile("Path exploration", phases):
        for i, addr in enumerate(trace_log):
            if addr in delay_slots:
                continue

            matching = [s for s in choices if s.addr == addr]
            if not matching:
                raise ValueError("couldn't advance to %08x, line %d" % (addr, i + 1))

            state = matching[0]
            if state.addr == MAIN_END:
                break

            num_inst = 2 if (state.addr + 4) in delay_slots else 1
            if len(matching) == 1:
                choices = project.factory.successors(state, num_inst=num_inst).successors
                continue

            # Keep original trace semantics; only parallelize when there are
            # multiple trace-matching states to step.
            simgr = project.factory.simulation_manager(None, save_unsat=False)
            simgr.stashes["active"] = matching
            simgr.use_technique(BatchThreading(threads=workers, task_multiplier=1))
            simgr.step(num_inst=num_inst)
            choices = simgr.active

        state = choices[0]

    print("Running solver...")
    with profile("Constraint solving", phases):
        solution = (
            state.solver.eval(
                state.memory.load(FLAG_LOCATION, 32), cast_to=bytes
            )
            .rstrip(b"\0")
            .decode("ascii")
        )
    print("The flag is", solution)
    return solution, phases


def test():
    assert main()[0] == "0ctf{tr135m1k5l96551s9l5r}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trace-guided solve with angr BatchThreading.")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Log Threading / BatchThreading exploration technique diagnostics to stderr "
        "(or set TRACE_SOLVE_DEBUG=1).",
    )
    args = parser.parse_args()
    configure_exploration_technique_debug(args.debug or trace_solve_debug_enabled())
    started = time.time()
    result, phase_data = main()
    elapsed = time.time() - started
    print("Time elapsed: {}".format(elapsed))
    print_phase_table(phase_data)
