"""Pure FORMAT1 metadata codec and inventory records, NOT snapshot verification.

    Reading/authorising manifest paths/checksums and filesystem restoration are
    P5.3b–e. A decoded record alone never authorises a path for restore/delete.
"""


class SnapshotMetadata:
    __slots__ = ('raw', 'rows')

    def __init__(self, raw):
        if not isinstance(raw, bytes):
            raise TypeError('STATE.tsv must be bytes')
        self.raw = raw
        records = raw.split(b'\n')
        if records[-1] == b'':
            records.pop()
        self.rows = tuple(tuple(record.split(b'\t')) for record in records)
        if self.value('FORMAT') != '1':
            raise ValueError('unsupported snapshot FORMAT')

    def value(self, key, default=''):
        """First matching $1, second TAB field only, as legacy state_value awk."""
        wanted = key.encode('utf-8', 'surrogateescape')
        for row in self.rows:
            if row[0] == wanted:
                return row[1].decode('utf-8', 'surrogateescape') if len(row) > 1 else ''
        return default

    @property
    def kind(self):
        return 'nfqws-import' if any(row[0] == b'NFQWS_PRESENT' for row in self.rows) else 'full'

    @property
    def scope(self):
        return None if self.kind == 'nfqws-import' else self.value('SCOPE') or 'integrated'

    def to_bytes(self):
        return self.raw


def parse_state(raw):
    """Lossless decode, including unknown fields, duplicate rows and opaque bytes."""
    return SnapshotMetadata(raw)


def make_state(fields):
    """Canonical LF writer to bytes ONLY. No file opened, version invented or service queried."""
    rows, seen = [], set()
    for key, value in fields:
        if (not isinstance(key, str) or not key or not isinstance(value, str)
                or any(char in key + value for char in '\t\r\n\0')):
            raise ValueError('ambiguous STATE.tsv field')
        if key in seen:
            raise ValueError('duplicate STATE.tsv field')
        seen.add(key)
        rows.append((key + '\t' + value + '\n').encode('utf-8', 'surrogateescape'))
    return SnapshotMetadata(b''.join(rows))


class InventoryEntry:
    """One PRESENT/ABSENT record. Logical path ownership is deliberately unverified here."""
    __slots__ = ('logical_path', 'presence')

    def __init__(self, logical_path, presence):
        if (not isinstance(logical_path, str) or not logical_path
                or any(char in logical_path for char in '|\r\n\0') or presence not in ('PRESENT', 'ABSENT')):
            raise ValueError('invalid inventory record')
        self.logical_path, self.presence = logical_path, presence

    def to_bytes(self):
        return (self.logical_path + '|' + self.presence + '\n').encode('utf-8', 'surrogateescape')
