# device_store.py
"""Listing 28.8 — Python: an executable model of Murmur's client storage stack,
on real SQLCipher 4. It does what the Kotlin and Swift listings do, so the lab
can inspect the bytes:
  · a non-exportable hardware AES-256-GCM key (STAND-IN for the Android
  Keystore/StrongBox key
    or the iOS Keychain + Secure Enclave) wraps the database key and the
    identity private keys;
  · the database is SQLCipher in WAL mode, written in IMMEDIATE transactions;
  · wipe deletes the hardware key FIRST, then the files.
The stand-in keeps its key in a separate directory; real hardware never releases
it at all."""
import json, os, shutil, sqlite3, time
import sqlcipher3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class HardwareKeyStandIn:
    """What the app sees of a Keystore/Secure Enclave key: wrap, unwrap, delete.
    No export."""
    def __init__(self, hw_dir, alias):
        self._path = os.path.join(hw_dir, alias)
        os.makedirs(hw_dir, exist_ok=True)
        if not os.path.exists(self._path):
            with open(self._path, "wb") as f: f.write(AESGCM.generate_key(256))
    def _k(self):
        if not os.path.exists(self._path):
            raise PermissionError(
                "KeyPermanentlyInvalidated: hardware key deleted")
        return AESGCM(open(self._path, "rb").read())
    # label = AAD from the registry (Ch 24)
    def wrap(self, secret, label):
        n = os.urandom(12); return n + self._k().encrypt(n, secret, label)
    def unwrap(self, blob, label):
        return self._k().decrypt(blob[:12], blob[12:], label)
    def delete(self):
        if os.path.exists(self._path): os.remove(self._path)

DB_KEY_LABEL, IK_LABEL = \
    b"murmur/v1/db-key-wrap", b"murmur/v1/identity-key-wrap"

SCHEMA = """
CREATE TABLE IF NOT EXISTS identity (name TEXT PRIMARY KEY, pub BLOB NOT NULL,
    wrapped_priv BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS prekeys (kind TEXT NOT NULL, id INTEGER NOT NULL,
    pub BLOB NOT NULL, priv BLOB NOT NULL,
    created REAL NOT NULL, superseded REAL, PRIMARY KEY (kind, id));
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS session_tokens (name TEXT PRIMARY KEY,
    value TEXT NOT NULL);
"""

class DeviceStore:
    def __init__(self, app_dir, hw_dir):
        self.app_dir, self.db_path = app_dir, os.path.join(app_dir, "core.db")
        os.makedirs(app_dir, exist_ok=True)
        self.hw = HardwareKeyStandIn(hw_dir, "murmur.db.wrap")
        # Android: in noBackupFilesDir
        wrapped_path = os.path.join(app_dir, "dbkey.wrapped")
        if not os.path.exists(wrapped_path):
            with open(wrapped_path, "wb") as f:
                f.write(self.hw.wrap(os.urandom(32), DB_KEY_LABEL))
        db_key = self.hw.unwrap(open(wrapped_path, "rb").read(), DB_KEY_LABEL)
        # explicit transactions only
        self.db = sqlcipher3.connect(self.db_path, isolation_level=None)
        # raw key: no PBKDF2 needed
        self.db.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
        del db_key
        self.db.execute("PRAGMA journal_mode = WAL")
        # deleted keys are overwritten in pages
        self.db.execute("PRAGMA secure_delete = ON")
        self.db.executescript(SCHEMA)

    def tx(self):
        return _Tx(self.db)

    # ── identity keys: wrapped by the hardware key, then stored inside the
    # encrypted DB ──
    def put_identity(self, name, pub, priv):
        with self.tx():
            self.db.execute("INSERT INTO identity VALUES (?,?,?)", (name, pub,
                self.hw.wrap(priv, IK_LABEL + b"/" + name.encode())))
    def identity(self, name):
        row = self.db.execute(
            "SELECT pub, wrapped_priv FROM identity WHERE name=?", (name,
            )).fetchone()
        return row[0], self.hw.unwrap(row[1], IK_LABEL + b"/" + name.encode())

    # ── prekeys: private halves live only in this DB; IDs come from a counter,
    # never reused ──
    def next_id(self, kind):
        with self.tx():
            row = self.db.execute("SELECT v FROM meta WHERE k=?",
                ("next_" + kind,)).fetchone()
            n = int(row[0]) if row else 1
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",
                ("next_" + kind, str(n + 1)))
        return n
    def add_prekeys(self, kind, keys, now):
        with self.tx():
            self.db.executemany(
                "INSERT INTO prekeys (kind,id,pub,priv,created) VALUES "
                "(?,?,?,?,?)",
                [(kind, i, pub, priv, now) for i, pub, priv in keys])
    # delete after use (Ch 18): one transaction
    def take_one_time(self, kind, key_id):
        with self.tx():
            row = self.db.execute(
                "SELECT priv FROM prekeys WHERE kind=? AND id=?", (kind,
                key_id)).fetchone()
            self.db.execute("DELETE FROM prekeys WHERE kind=? AND id=?", (kind,
                key_id))
        return row[0] if row else None
    def get(self, kind, key_id):
        row = self.db.execute("SELECT priv FROM prekeys WHERE kind=? AND id=?",
            (kind, key_id)).fetchone()
        return row[0] if row else None
    def current_signed(self, kind):
        return self.db.execute(
            "SELECT id, created FROM prekeys WHERE kind=? AND superseded IS "
            "NULL ORDER BY id DESC LIMIT 1",
            (kind,)).fetchone()
    def supersede(self, kind, keep_id, now):
        with self.tx():
            self.db.execute(
                "UPDATE prekeys SET superseded=? WHERE kind=? AND id<>? AND "
                "superseded IS NULL", (now, kind, keep_id))
    def next_id_peek(self, kind):
        row = self.db.execute("SELECT v FROM meta WHERE k=?", ("next_" + kind,
            )).fetchone()
        return int(row[0]) if row else 1
    def mark_handed_out(self, kind, max_id, now):
        with self.tx():
            self.db.execute(
                "UPDATE prekeys SET superseded=? WHERE kind=? AND id<=? AND "
                "superseded IS NULL", (now, kind, max_id))
    def purge_superseded(self, kind, older_than):
        with self.tx():
            return self.db.execute(
                "DELETE FROM prekeys WHERE kind=? AND superseded IS NOT NULL "
                "AND superseded < ?",
                (kind, older_than)).rowcount
    def count(self, kind):
        return self.db.execute("SELECT count(*) FROM prekeys WHERE kind=?",
            (kind,)).fetchone()[0]

    def put_token(self, name, value):
        with self.tx():
            self.db.execute(
                "INSERT OR REPLACE INTO session_tokens VALUES (?,?)", (name,
                value))

    # ── wipe: key first, files second. A crash in between leaves only
    # undecryptable bytes. ──
    def wipe(self, crash_after_key=False):
        self.db.close()
        self.hw.delete()
        if crash_after_key: return
        shutil.rmtree(self.app_dir)

class _Tx:
    def __init__(self, db): self.db = db
    # take the write lock up front (Ch 19 §19.9)
    def __enter__(self): self.db.execute("BEGIN IMMEDIATE")
    def __exit__(self, et, *_):
        self.db.execute("COMMIT" if et is None else "ROLLBACK")
