"""OpenFgaStore.write converges on the wanted tuples: present ones are skipped, a changed
expiry is replaced, new ones are written. OpenFGA itself would 400 on a duplicate."""

from bab.store import OpenFgaStore, Tuple


class _Resp:
    def __init__(self, tuples):
        self.tuples, self.continuation_token = tuples, None


class _Key:
    def __init__(self, t: Tuple):
        self.user, self.relation, self.object = t.user, t.relation, t.object

        class _Cond:
            name, context = "grant_window", {"expires_at": t.expires_at}

        self.condition = _Cond() if t.expires_at else None


class _Row:
    def __init__(self, t: Tuple):
        self.key = _Key(t)


class _FakeClient:
    def __init__(self, existing):
        self.existing, self.written, self.deleted = list(existing), [], []

    def read(self, _key, _opts=None):
        return _Resp([_Row(t) for t in self.existing])

    def write_tuples(self, body):
        self.written += [(b.user, b.relation, b.object) for b in body]

    def delete_tuples(self, body):
        self.deleted += [(b.user, b.relation, b.object) for b in body]


def _store(existing):
    s = OpenFgaStore.__new__(OpenFgaStore)
    s._client = _FakeClient(existing)
    return s


def test_write_skips_present_replaces_changed_and_writes_new():
    room = Tuple("room:kobo", "room", "integration:fubo-it")
    grant_old = Tuple("agent:a", "aws_logs_read", "integration:fubo-it", "2026-11-01T00:00:00Z")
    grant_new = Tuple("agent:a", "aws_logs_read", "integration:fubo-it", "2026-12-01T00:00:00Z")
    ceiling = Tuple("team:sre", "ceiling_aws_logs_read", "integration:fubo-it")
    s = _store([room, grant_old])

    s.write([room, grant_new, ceiling])

    assert s._client.deleted == [grant_old.key]
    assert s._client.written == [ceiling.key, grant_new.key]


def test_write_of_nothing_touches_nothing():
    s = _store([Tuple("room:kobo", "room", "integration:x")])
    s.write([])
    assert s._client.written == [] and s._client.deleted == []
