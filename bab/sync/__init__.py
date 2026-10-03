"""Tuple sources. A sync computes the desired tuples for its source and reconciles the store."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from bab.store import Store, Tuple

log = logging.getLogger(__name__)


def reconcile(store: Store, desired: Iterable[Tuple], relations: set[str], dry_run: bool = False) -> tuple[list[Tuple], list[Tuple]]:
    """Make the store's tuples for `relations` equal `desired`. Returns (written, deleted).

    A sync owns whole relations (e.g. Okta owns `member`), so anything in those
    relations that the source no longer produces is deleted. Other relations are untouched.
    """
    want = {t for t in desired if t.relation in relations}
    have = {t for t in store.read_all() if t.relation in relations}
    write, delete = sorted(want - have, key=str), sorted(have - want, key=str)
    log.info("reconcile %s: +%d -%d (dry_run=%s)", sorted(relations), len(write), len(delete), dry_run)
    if not dry_run:
        store.write(write)
        store.delete(delete)
    return write, delete
