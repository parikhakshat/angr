from __future__ import annotations
from angr import engines
from angr.errors import SimError, AngrError, AngrExplorationTechniqueError


class _ConstantAddrCondition:
    """Picklable replacement for a closure that always returns the same value."""

    __slots__ = ("_value",)

    def __init__(self, value):
        self._value = value

    def __call__(self, state):
        return self._value


class _StaticAddrsCondition:
    """Picklable replacement for the nested function used for int/set/list/tuple find/avoid."""

    __slots__ = ("_addrs",)

    def __init__(self, addrs):
        self._addrs = frozenset(addrs)

    def __call__(self, state):
        if state.addr in self._addrs:
            return {state.addr}

        if not isinstance(state.project.factory.default_engine, engines.vex.VEXLifter):
            return False

        try:
            return self._addrs.intersection(set(state.block().instruction_addrs))
        except (AngrError, SimError):
            return False


def condition_to_lambda(condition, default=False):
    """
    Translates an integer, set, list or function into a lambda that checks if state's current basic block matches
    some condition.

    :param condition:   An integer, set, list or lambda to convert to a lambda.
    :param default:     The default return value of the lambda (in case condition is None). Default: false.

    :returns:           A tuple of two items: a lambda that takes a state and returns the set of addresses that it
                        matched from the condition, and a set that contains the normalized set of addresses to stop
                        at, or None if no addresses were provided statically.
    """
    if condition is None:
        condition_function = _ConstantAddrCondition(default)
        static_addrs = set()

    elif isinstance(condition, int):
        return condition_to_lambda((condition,))

    elif isinstance(condition, (tuple, set, list)):
        static_addrs = set(condition)
        condition_function = _StaticAddrsCondition(static_addrs)

    elif callable(condition):
        condition_function = condition
        static_addrs = None
    else:
        raise AngrExplorationTechniqueError(
            f"ExplorationTechnique is unable to convert given type ({condition.__class__}) to a callable condition function."
        )

    return condition_function, static_addrs
