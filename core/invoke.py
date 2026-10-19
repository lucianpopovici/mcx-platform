"""Hook invocation boundary.

Implements PLT-ICD-001 §2.2 and §2.3 in one place, so no call site repeats the
error mapping:

  ICD-GEN-010  every invocation has a deadline
  ICD-GEN-011  deadline expiry fails the session with `hook-timeout`
  ICD-GEN-012  no retry on the establishment path
  ICD-GEN-021  any exception fails the session with `hook-error`; no default
               result is ever substituted
  ICD-GEN-022  exception types are not distinguished
  ICD-GEN-040  every invocation is audited with elapsed time and outcome
  ICD-GEN-041  what the hook returned is recorded in full on that record,
               including a value its POST check refused

FINDING — deadline enforcement is weaker than the ICD states.

ICD-GEN-011 says the core "shall abandon the invocation" on expiry. A synchronous
in-process call cannot be abandoned: Python offers no safe way to interrupt a
running call, and killing the thread would leave profile state inconsistent.

Three honest options:
  (a) MEASURE   run inline, record an overrun, let the call finish  [default]
  (b) ENFORCE   run in a worker thread, abandon the wait on expiry and fail the
                session; the call keeps running detached
  (c) revise ICD-GEN-011 to "measure and fail after the fact"

(b) abandons the WAIT, not the call, so it does not deliver the ICD's wording
either. This is an interface defect to resolve in ICD v0.2 rather than paper
over: the guarantee as written is not implementable in this model.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import math
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, List, Mapping, Optional, Tuple

from .audit import Auditor, RecordType
from .errors import HOOK_ERROR, HOOK_TIMEOUT, HookContractViolation, PlatformError

# PLT-ICD-001 §2.2 ICD-GEN-010 default budgets, in milliseconds.
DEFAULT_BUDGETS_MS: Mapping[str, int] = {
    "IF-IDR": 50,
    "IF-PRI": 5,
    "IF-SES": 5,
    "IF-BER": 10,
    "IF-IWF": 20,
    "IF-ICX": 20,
}


@functools.lru_cache(maxsize=None)
def _core_types() -> Tuple[frozenset, frozenset]:
    """The value classes and enums core/hooks.py defines: the only classes
    whose instances are rendered, since only their behaviour is the core's."""
    from . import hooks
    classes = [c for c in vars(hooks).values()
               if isinstance(c, type) and c.__module__ == hooks.__name__]
    values = frozenset(c for c in classes if issubclass(c, hooks.Value)
                       and c is not hooks.Value)
    enums = frozenset(c for c in classes if issubclass(c, Enum))
    return values, enums


def render(value: Any) -> Tuple[Any, Tuple[str, ...]]:
    """What a hook returned as plain JSON data, every field of it
    (ICD-GEN-041), and what in it could not be rendered.

    Only exact types are rendered: the core's own value classes and enums,
    str, int, bool, None, a finite float, and a dict, FrozenDict, tuple, list
    or frozenset of these (a mapping with str keys; a frozenset sorted, so a
    record is the same every time). A subclass of any of them, or anything
    else, is named rather than rendered: rendering it would run the profile's
    code inside the audit, and what it shows could differ from what the core
    goes on to use. A value holding one cannot be recorded in full, and the
    Invoker refuses it."""
    from .hooks import FrozenDict
    values, enums = _core_types()
    bad: List[str] = []

    def walk(v: Any) -> Any:
        t = type(v)
        if v is None or t in (str, int, bool):
            return v
        if t is float:
            if math.isfinite(v):
                return v
            bad.append(f"float {v!r}")
            return {"unrepresentable": "float"}
        if t in enums:
            return walk(v.value)
        if t in values:
            return {f.name: walk(getattr(v, f.name)) for f in dataclasses.fields(v)}
        if t is dict or t is FrozenDict:
            out = {}
            for k, item in dict.items(v):
                if type(k) is not str:
                    bad.append(f"mapping key of type {type(k).__name__}")
                    return {"unrepresentable": "mapping"}
                out[k] = walk(item)
            return out
        if t is tuple or t is list:
            return [walk(item) for item in v]
        if t is frozenset:
            return sorted((walk(item) for item in v),
                          key=lambda x: json.dumps(x, sort_keys=True))
        bad.append(t.__name__)
        return {"unrepresentable": t.__name__}

    return walk(v=value), tuple(bad)


def plain(value: Any) -> Any:
    """`render`'s data alone."""
    return render(value)[0]


def _recorded(value: Any) -> Tuple[Any, Tuple[str, ...]]:
    """`render`, which never fails the audit (a value nested too deep, say)."""
    try:
        return render(value)
    except Exception:  # noqa: BLE001 — the audit must not fail on a bad value
        return {"unrepresentable": "unreadable"}, ("unreadable",)


class DeadlineMode(Enum):
    MEASURE = "measure"     # run inline, record an overrun (see FINDING above)
    ENFORCE = "enforce"     # run in a worker, abandon the wait on expiry


class HookFailure(PlatformError):
    """A hook invocation failed. `reason_code` is what the session reports."""

    def __init__(self, interface: str, method: str, reason_code: str,
                 detail: str = "") -> None:
        self.interface = interface
        self.method = method
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{interface}.{method} failed: {reason_code}"
                         + (f" ({detail})" if detail else ""))


@dataclass(frozen=True)
class Outcome:
    value: Any
    elapsed_ms: float
    overran: bool


class Invoker:
    """Calls hooks under the ICD's contract. One instance per session context."""

    def __init__(self, auditor: Auditor, correlation_id: str,
                 budgets_ms: Optional[Mapping[str, int]] = None,
                 mode: DeadlineMode = DeadlineMode.MEASURE,
                 executor: Optional[ThreadPoolExecutor] = None) -> None:
        self._auditor = auditor
        self._correlation_id = correlation_id
        self._budgets = dict(DEFAULT_BUDGETS_MS)
        if budgets_ms:
            self._budgets.update(budgets_ms)
        self._mode = mode
        self._executor = executor

    def call(self, interface: str, method: str, fn: Callable[..., Any],
             *args: Any, post: Optional[Callable[[Any], None]] = None,
             **kwargs: Any) -> Any:
        """Invoke a hook under contract.

        `post` is the interface's POST check. It runs INSIDE this boundary so a
        violated postcondition maps to `hook-contract-violation` like any other,
        rather than escaping as a raw exception to the call site.
        """
        budget = self._budgets.get(interface, 0)
        started = time.monotonic()
        recorded: Mapping[str, Any] = {}
        try:
            value = self._run(fn, budget, *args, **kwargs)
            # ICD-GEN-041: recorded in full, or not relied on. A value the
            # audit cannot render exactly is refused before its POST runs.
            data, bad = _recorded(value)
            recorded = {"returned": data}
            if bad:
                raise HookContractViolation(
                    "returned a value the audit cannot record in full "
                    f"(ICD-GEN-041): {', '.join(bad)}")
            if post is not None:
                post(value)
        except FutureTimeout:
            elapsed = (time.monotonic() - started) * 1000
            self._audit(interface, method, elapsed, "timeout", True)
            # ICD-GEN-012: no retry on the establishment path.
            raise HookFailure(interface, method, HOOK_TIMEOUT,
                              f"exceeded {budget} ms budget") from None
        except HookContractViolation as exc:
            elapsed = (time.monotonic() - started) * 1000
            # The value refused, if the hook returned one; a hook that raised
            # the violation itself returned nothing.
            self._audit(interface, method, elapsed, "contract-violation", False,
                        **recorded)
            # Distinguished from hook-error: this indicates a profile defect
            # and should be alertable (PLT-ICD-001 §9).
            raise HookFailure(interface, method, exc.reason_code,
                              str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 — ICD-GEN-022, types not distinguished
            elapsed = (time.monotonic() - started) * 1000
            reason = getattr(exc, "reason_code", HOOK_ERROR)
            # A POST that failed on the value still leaves the value recorded.
            self._audit(interface, method, elapsed, "error", False,
                        error=type(exc).__name__, **recorded)
            # ICD-GEN-021: never substitute a default result.
            raise HookFailure(interface, method, reason, str(exc)) from exc

        elapsed = (time.monotonic() - started) * 1000
        overran = budget > 0 and elapsed > budget
        self._audit(interface, method, elapsed, "ok", overran, **recorded)
        return value

    def _run(self, fn: Callable[..., Any], budget_ms: int,
             *args: Any, **kwargs: Any) -> Any:
        if self._mode is DeadlineMode.MEASURE or budget_ms <= 0:
            return fn(*args, **kwargs)
        executor = self._executor or ThreadPoolExecutor(max_workers=1)
        future = executor.submit(fn, *args, **kwargs)
        try:
            return future.result(timeout=budget_ms / 1000.0)
        finally:
            if self._executor is None:
                executor.shutdown(wait=False)

    def _audit(self, interface: str, method: str, elapsed_ms: float,
               outcome: str, overran: bool, **extra: Any) -> None:
        self._auditor.emit(
            RecordType.HOOK_INVOCATION, self._correlation_id,
            interface=interface, method=method,
            elapsed_ms=round(elapsed_ms, 3), outcome=outcome,
            budget_overrun=overran, **extra)
