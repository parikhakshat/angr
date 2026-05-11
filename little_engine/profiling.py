from dataclasses import dataclass
import contextlib
import time

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
