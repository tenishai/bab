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
    room = Tuple("room:kobo", "room", "integration:aws-audit")
    grant_old = Tuple("agent:a", "aws_logs_read", "integration:aws-audit", "2026-11-01T00:00:00Z")
    grant_new = Tuple("agent:a", "aws_logs_read", "integration:aws-audit", "2026-12-01T00:00:00Z")
    ceiling = Tuple("team:sre", "ceiling_aws_logs_read", "integration:aws-audit")
    s = _store([room, grant_old])

    s.write([room, grant_new, ceiling])

    assert s._client.deleted == [grant_old.key]
    assert s._client.written == [ceiling.key, grant_new.key]


def test_write_of_nothing_touches_nothing():
    s = _store([Tuple("room:kobo", "room", "integration:x")])
    s.write([])
    assert s._client.written == [] and s._client.deleted == []


def test_writes_and_deletes_go_in_batches_of_one_hundred():
    from bab.store import WRITE_BATCH, OpenFgaStore, Tuple

    class Client:
        def __init__(self):
            self.writes, self.deletes = [], []
            self.tuples = []

        def read(self, key, options=None):
            return type("R", (), {"tuples": (), "continuation_token": None})()

        def write_tuples(self, body):
            assert len(body) <= WRITE_BATCH
            self.writes.append(len(body))

        def delete_tuples(self, body):
            assert len(body) <= WRITE_BATCH
            self.deletes.append(len(body))

    client = Client()
    store = OpenFgaStore.__new__(OpenFgaStore)
    store._client = client
    many = [Tuple(f"team:t{i}", "ceiling_x", "integration:a") for i in range(250)]
    store.write(many)
    assert client.writes == [100, 100, 50]
    store.delete(many)
    assert client.deletes == [100, 100, 50]
