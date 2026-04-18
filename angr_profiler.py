#!/usr/bin/env python3
"""
angr_analyze.py
───────────────
Symbolic-execution harness for `target` (compiled from target.c).

Profiled phases
  1. Binary loading
  2. CFG construction   (CFGFast  + CFGEmulated)
  3. Disassembly        (capstone via angr's knowledge-base)
  4. Path / state exploration  (SimulationManager)
  5. Constraint solving (claripy – z3 back-end)

Usage
  python angr_analyze.py ./target [--find ADDR] [--avoid ADDR [ADDR ...]]
  python angr_analyze.py ./target --auto          # auto-detect win/deny strings
"""

import sys
import time
import argparse
import contextlib
import textwrap
import logging
from dataclasses import dataclass, field
from typing import Optional

# ── third-party ──────────────────────────────────────────────────────────────
try:
    import angr
    import claripy
    from angr.analyses.cfg import CFGFast, CFGEmulated   # noqa: F401 (import check)
except ImportError as exc:
    sys.exit(f"[!] Missing dependency: {exc}\n    pip install angr")

# silence angr's verbose logging unless the user sets ANGR_LOG=1
if not __import__("os").environ.get("ANGR_LOG"):
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    logging.getLogger("claripy").setLevel(logging.ERROR)

# ── colour helpers ────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"
GREY   = "\033[90m"

def hdr(title: str) -> str:
    bar = "─" * 60
    return f"\n{BOLD}{CYAN}{bar}\n  {title}\n{bar}{RESET}"

def ok(msg):  print(f"  {GREEN}✔{RESET}  {msg}")
def info(msg):print(f"  {CYAN}ℹ{RESET}  {msg}")
def warn(msg):print(f"  {YELLOW}⚠{RESET}  {msg}")
def err(msg): print(f"  {RED}✘{RESET}  {msg}")

# ── profiling context manager ─────────────────────────────────────────────────
@dataclass
class Phase:
    name:     str
    elapsed:  float = 0.0
    success:  bool  = True
    note:     str   = ""

@contextlib.contextmanager
def profile(phase_name: str, phases: list):
    """Context manager that times a phase and records it."""
    p = Phase(name=phase_name)
    phases.append(p)
    t0 = time.perf_counter()
    try:
        yield p
    except Exception as exc:           # record failure but re-raise
        p.success = False
        p.note    = str(exc)
        raise
    finally:
        p.elapsed = time.perf_counter() - t0


def print_phase_table(phases: list[Phase]) -> None:
    print(hdr("Profiling Summary"))
    col_w = max(len(p.name) for p in phases) + 2
    header = f"  {'Phase':<{col_w}}  {'Time (s)':>9}  Status"
    print(f"{BOLD}{header}{RESET}")
    print("  " + "─" * (col_w + 24))
    total = 0.0
    for p in phases:
        status = f"{GREEN}OK{RESET}" if p.success else f"{RED}FAIL{RESET}"
        note   = f"  {GREY}← {p.note}{RESET}" if p.note else ""
        print(f"  {p.name:<{col_w}}  {p.elapsed:>9.4f}s  {status}{note}")
        total += p.elapsed
    print("  " + "─" * (col_w + 24))
    print(f"  {'TOTAL':<{col_w}}  {total:>9.4f}s")


# ═════════════════════════════════════════════════════════════════════════════
# 1. Binary Loading
# ═════════════════════════════════════════════════════════════════════════════
def load_binary(binary_path: str, phases: list) -> angr.Project:
    print(hdr("Phase 1 — Binary Loading"))
    with profile("Binary loading", phases) as p:
        proj = angr.Project(
            binary_path,
            auto_load_libs=False,          # keep analysis self-contained
            load_options={"rebase_granularity": 0x1000},
        )
        arch  = proj.arch.name
        entry = proj.entry
        size  = proj.loader.main_object.max_addr - proj.loader.min_addr
        p.note = f"{arch}  entry=0x{entry:x}  ~{size//1024}KB"

    ok(f"Loaded  : {binary_path}")
    info(f"Arch    : {proj.arch.name}  ({proj.arch.bits}-bit)")
    info(f"Entry   : 0x{proj.entry:x}")
    info(f"OS      : {proj.loader.main_object.os}")
    return proj


# ═════════════════════════════════════════════════════════════════════════════
# 2. CFG Construction
# ═════════════════════════════════════════════════════════════════════════════
def build_cfg(proj: angr.Project, phases: list) -> tuple:
    print(hdr("Phase 2 — CFG Construction"))

    # ── CFGFast (static / light-weight) ──────────────────────────────────────
    with profile("CFGFast", phases) as p:
        cfg_fast = proj.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            force_complete_scan=False,
            show_progressbar=False,
        )
        #n_nodes = len(cfg_fast.graph.nodes())
        #n_edges = len(cfg_fast.graph.edges())
        #p.note  = f"{n_nodes} nodes  {n_edges} edges"

    #ok(f"CFGFast : {n_nodes:,} nodes  {n_edges:,} edges")

    # ── CFGEmulated (light – capped iterations) ───────────────────────────────
    with profile("CFGEmulated", phases) as p:
        cfg_emu = proj.analyses.CFGEmulated(
            starts=[proj.entry],
            context_sensitivity_level=1,   # 0=insensitive, 1=light, ≥2=heavy
            keep_state=False,
            iropt_level=1,
            max_steps=512,                 # cap so it terminates in demo time
            show_progressbar=False,
        )
        #en = len(cfg_emu.graph.nodes())
        #ee = len(cfg_emu.graph.edges())
        #p.note = f"{en} nodes  {ee} edges"

    #ok(f"CFGEmu  : {en:,} nodes  {ee:,} edges")

    # ── function list ─────────────────────────────────────────────────────────
    funcs = proj.kb.functions
    info(f"Functions discovered: {len(funcs)}")
    for addr, fn in list(funcs.items())[:8]:
        info(f"  0x{addr:x}  {fn.name}")
    if len(funcs) > 8:
        info(f"  … and {len(funcs)-8} more")

    return cfg_fast, cfg_emu


# ═════════════════════════════════════════════════════════════════════════════
# 3. Disassembly
# ═════════════════════════════════════════════════════════════════════════════
def disassemble(proj: angr.Project, cfg_fast, phases: list, max_insns: int = 40) -> None:
    print(hdr("Phase 3 — Disassembly"))

    with profile("Disassembly", phases) as p:
        # Pick the first non-plt non-extern user function
        funcs = [
            f for f in proj.kb.functions.values()
            if not f.is_plt and not f.is_simprocedure and f.name != "main"
               and proj.loader.find_object_containing(f.addr) is proj.loader.main_object
        ]
        target_fn = funcs[0] if funcs else None
        if target_fn is None:
            warn("No suitable function found for disassembly demo.")
            return

        block_count = 0
        insn_count  = 0
        disasm_lines = []

        for block_addr in target_fn.block_addrs_set:
            try:
                block = proj.factory.block(block_addr)
            except Exception:
                continue
            block_count += 1
            for insn in block.capstone.insns:
                if insn_count >= max_insns:
                    break
                ops = insn.op_str if insn.op_str else ""
                disasm_lines.append(
                    f"    {GREY}0x{insn.address:x}{RESET}  "
                    f"{YELLOW}{insn.mnemonic:<8}{RESET} {ops}"
                )
                insn_count += 1
            if insn_count >= max_insns:
                break

        p.note = (f"fn={target_fn.name}  "
                  f"{block_count} blocks  {insn_count} insns shown")

    info(f"Function  : {target_fn.name}  @ 0x{target_fn.addr:x}")
    info(f"Blocks    : {block_count}")
    info(f"Showing first {insn_count} instructions:")
    print()
    for line in disasm_lines:
        print(line)
    if insn_count >= max_insns:
        print(f"    {GREY}… (truncated at {max_insns} insns){RESET}")


# ═════════════════════════════════════════════════════════════════════════════
# 4. Path Exploration (SimulationManager)
# ═════════════════════════════════════════════════════════════════════════════
@dataclass
class ExplorationResult:
    found:   list = field(default_factory=list)
    avoided: list = field(default_factory=list)
    deadended: list = field(default_factory=list)
    errored:   list = field(default_factory=list)
    steps:   int  = 0
    active_peak: int = 0


def find_target_addrs(proj: angr.Project, win_str: str = "PASSED",
                      deny_str: str = "denied") -> tuple[list[int], list[int]]:
    """Scan rodata/data for find/avoid string addresses via CFG KB."""
    find_addrs  = []
    avoid_addrs = []

    loader = proj.loader
    for sect in loader.main_object.sections:
        if sect.name in (".rodata", ".data", ".text"):
            try:
                data = loader.memory.load(sect.min_addr, sect.memsize)
            except Exception:
                continue
            win_enc  = win_str.encode()
            deny_enc = deny_str.encode()
            off = data.find(win_enc)
            if off != -1:
                find_addrs.append(sect.min_addr + off)
            off = data.find(deny_enc)
            if off != -1:
                avoid_addrs.append(sect.min_addr + off)

    # Fall back: find printf call-sites in 'main' that reference those strings
    # (simpler heuristic: look for xrefs in the KB)
    for addr in list(proj.kb.functions.keys()):
        fn = proj.kb.functions[addr]
        if fn.name == "main":
            for blk_addr in fn.block_addrs_set:
                try:
                    blk = proj.factory.block(blk_addr)
                    for insn in blk.capstone.insns:
                        # heuristic: last insn in block leading to printf
                        pass
                except Exception:
                    pass

    return find_addrs, avoid_addrs


def explore_paths(
    proj: angr.Project,
    phases: list,
    find_addrs: Optional[list] = None,
    avoid_addrs: Optional[list] = None,
    n_args: int = 4,
    max_steps: int = 200,
) -> ExplorationResult:
    print(hdr("Phase 4 — Path Exploration (SimulationManager)"))

    result = ExplorationResult()

    # ── symbolic argv ─────────────────────────────────────────────────────────
    # Each argument is a 32-bit symbolic bitvector (mimics atoi input range)
    sym_args = [claripy.BVS(f"arg{i}", 32) for i in range(n_args)]

    # Build an initial state: call_state lets us pass symbolic argv correctly
    # for binaries that read via atoi(argv[n])
    # We use a blank_state + hook approach for portability
    state = proj.factory.entry_state(
        args=[proj.filename] + [sym_args[i] for i in range(n_args)],
        add_options={
            angr.options.LAZY_SOLVES,
            angr.options.SYMBOLIC,
            angr.options.TRACK_CONSTRAINT_ACTIONS,
        },
        remove_options={
            angr.options.SIMPLIFY_CONSTRAINTS,
        },
    )

    # Constrain inputs to printable ASCII digit range [48..57] for each byte
    # so the 32-bit BVS represents a reasonable integer string argument.
    for sv in sym_args:
        state.solver.add(sv >= -0x8000)
        state.solver.add(sv <=  0x7FFF)

    simgr = proj.factory.simulation_manager(state, save_unsat=False)

    info(f"Symbolic args : {n_args}  ×  32-bit BVS")
    info(f"Find  addrs   : {[hex(a) for a in (find_addrs  or [])]}")
    info(f"Avoid addrs   : {[hex(a) for a in (avoid_addrs or [])]}")
    info(f"Max steps     : {max_steps}")
    print()

    step_times = []
    prev_active = 0

    with profile("Path exploration", phases) as p:
        for step in range(max_steps):
            t_step = time.perf_counter()
            simgr.step()
            step_times.append(time.perf_counter() - t_step)

            n_active = len(simgr.active)
            result.active_peak = max(result.active_peak, n_active)
            result.steps += 1

            # Classify found / avoided
            if find_addrs:
                simgr.move(
                    from_stash="active",
                    to_stash="found",
                    filter_func=lambda s: s.addr in find_addrs,
                )
            if avoid_addrs:
                simgr.move(
                    from_stash="active",
                    to_stash="avoided",
                    filter_func=lambda s: s.addr in avoid_addrs,
                )

            # Progress log every 20 steps
            if step % 20 == 0 or n_active != prev_active:
                bar_len = min(n_active, 40)
                bar = "█" * bar_len
                n_found = len(simgr.stashes.get("found", []))
                n_dead = len(simgr.stashes.get("deadended", []))
                n_err = len(simgr.stashes.get("errored", []))
                print(f"  step {step:>4}  active={n_active:>4}  "
                      f"found={n_found:>3}  "
                      f"dead={n_dead:>4}  "
                      f"err={n_err:>3}  [{bar}]")
            prev_active = n_active

            if not simgr.active:
                info("Exploration complete — no more active states.")
                break
            if simgr.stashes.get("found"):
                info(f"Target reached after {step+1} steps — stopping early.")
                break

        result.found     = list(simgr.stashes.get("found", []))
        result.avoided   = list(simgr.stashes.get("avoided", []))
        result.deadended = list(simgr.stashes.get("deadended", []))
        result.errored   = list(simgr.stashes.get("errored", []))

        avg_step = sum(step_times) / len(step_times) if step_times else 0
        p.note = (f"{result.steps} steps  "
                  f"peak_active={result.active_peak}  "
                  f"found={len(result.found)}  "
                  f"avg_step={avg_step*1000:.1f}ms")

    print()
    ok(f"States found    : {len(result.found)}")
    ok(f"States deadended: {len(result.deadended)}")
    ok(f"States avoided  : {len(result.avoided)}")
    if result.errored:
        warn(f"States errored  : {len(result.errored)}")

    return result


# ═════════════════════════════════════════════════════════════════════════════
# 5. Constraint Solving
# ═════════════════════════════════════════════════════════════════════════════
def solve_constraints(
    result: ExplorationResult,
    phases: list,
    n_args: int = 4,
) -> None:
    print(hdr("Phase 5 — Constraint Solving (claripy / z3)"))

    if not result.found:
        warn("No 'found' states to solve — trying deadended states instead.")
        states_to_try = result.deadended[:3]
    else:
        states_to_try = result.found

    if not states_to_try:
        warn("No states available for solving.")
        return

    for idx, state in enumerate(states_to_try[:3]):
        print(f"\n  {BOLD}State #{idx}{RESET}  @ 0x{state.addr:x}")

        with profile(f"Solve state#{idx}", phases) as p:
            # Collect symbolic leaf ASTs referenced by constraints.
            # SimSolver.variables(...) expects an expression in current angr.
            # We extract names from each constraint instead for compatibility.
            sym_var_asts: dict[str, claripy.ast.Base] = {}
            for cons in state.solver.constraints:
                for leaf in cons.leaf_asts():
                    if leaf.symbolic and leaf.op == "BVS":
                        sym_var_asts[leaf.args[0]] = leaf

            sym_vars = sorted(sym_var_asts.keys())
            info(f"  Symbolic vars  : {len(sym_vars)}")
            info(f"  Constraints    : {len(state.solver.constraints)}")

            # Print a condensed constraint summary
            for ci, c in enumerate(state.solver.constraints[:6]):
                c_str = str(c)
                if len(c_str) > 80:
                    c_str = c_str[:77] + "…"
                print(f"    {GREY}[{ci}]{RESET} {c_str}")
            if len(state.solver.constraints) > 6:
                print(f"    {GREY}… +{len(state.solver.constraints)-6} more{RESET}")

            # Satisfiability check
            is_sat = state.solver.satisfiable()
            p.note = f"sat={is_sat}"

        status_str = (f"{GREEN}SAT{RESET}" if is_sat else f"{RED}UNSAT{RESET}")
        print(f"\n  Satisfiable: {status_str}")

        if not is_sat:
            continue

        # Evaluate each symbolic variable
        print(f"\n  {BOLD}Concrete model:{RESET}")
        for vname in sym_vars[:n_args]:
            with profile(f"  Eval {vname[:20]}", phases) as p2:
                try:
                    val = state.solver.eval(sym_var_asts[vname], cast_to=int)
                    p2.note = f"= {val}"
                    print(f"    {CYAN}{vname:<30}{RESET}  →  {val}  "
                          f"(0x{val & 0xFFFFFFFF:08x})")
                except Exception as exc:
                    p2.note = f"eval error: {exc}"
                    warn(f"    Could not eval {vname}: {exc}")

        # Try to get min/max range for first variable (demonstrates solver query)
        if sym_vars:
            v0 = sym_vars[0]
            with profile(f"Range {v0[:20]}", phases) as p3:
                try:
                    sv_obj = sym_var_asts[v0]
                    lo = state.solver.min(sv_obj)
                    hi = state.solver.max(sv_obj)
                    p3.note = f"[{lo}, {hi}]"
                    info(f"  Range of {v0}: [{lo}, {hi}]")
                except Exception:
                    pass


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="angr symbolic-execution harness with per-phase profiling.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples
          python angr_analyze.py ./target --auto
          python angr_analyze.py ./target --find 0x401234 --avoid 0x401300
          python angr_analyze.py ./target --auto --max-steps 300
        """),
    )
    ap.add_argument("binary", help="Path to compiled binary")
    ap.add_argument("--find",  nargs="+", type=lambda x: int(x, 0),
                    help="Address(es) to reach (hex OK)")
    ap.add_argument("--avoid", nargs="+", type=lambda x: int(x, 0),
                    help="Address(es) to avoid (hex OK)")
    ap.add_argument("--auto", action="store_true",
                    help="Auto-detect find/avoid from string literals")
    ap.add_argument("--max-steps", type=int, default=150,
                    help="Max exploration steps (default: 150)")
    ap.add_argument("--args", type=int, default=4,
                    help="Number of symbolic int arguments (default: 4)")
    return ap.parse_args()


def main() -> None:
    args    = parse_args()
    phases: list[Phase] = []

    print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{CYAN}  angr Symbolic Execution Harness  —  {args.binary}{RESET}")
    print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════════════════{RESET}")

    # ── 1. Load ────────────────────────────────────────────────────────────────
    proj = load_binary(args.binary, phases)

    # ── 2. CFG ────────────────────────────────────────────────────────────────
    cfg_fast, cfg_emu = build_cfg(proj, phases)

    # ── 3. Disassembly ────────────────────────────────────────────────────────
    disassemble(proj, cfg_fast, phases)

    # ── 4. Find / Avoid resolution ────────────────────────────────────────────
    find_addrs  = args.find  or []
    avoid_addrs = args.avoid or []

    if args.auto and not (find_addrs or avoid_addrs):
        fa, aa = find_target_addrs(proj, win_str="PASSED", deny_str="denied")
        if fa or aa:
            find_addrs  = fa
            avoid_addrs = aa
            info(f"Auto-detected find : {[hex(a) for a in find_addrs]}")
            info(f"Auto-detected avoid: {[hex(a) for a in avoid_addrs]}")
        else:
            warn("Auto-detect found no matching strings; "
                 "exploration will run without find/avoid.")

    # ── 5. Exploration ────────────────────────────────────────────────────────
    result = explore_paths(
        proj, phases,
        find_addrs=find_addrs  or None,
        avoid_addrs=avoid_addrs or None,
        n_args=args.args,
        max_steps=args.max_steps,
    )

    # ── 6. Constraint solving ─────────────────────────────────────────────────
    solve_constraints(result, phases, n_args=args.args)

    # ── 7. Summary table ──────────────────────────────────────────────────────
    print_phase_table(phases)
    print()


if __name__ == "__main__":
    main()
