import hashlib
import tempfile
import unittest
from datetime import date
from pathlib import Path

from rules_recertify.archives import (
    prepare_run_archive, purge_expired_archives, restore_archive,
)
from rules_recertify.history.database import Database


class ArchiveTest(unittest.TestCase):
    def test_archive_is_verified_and_can_be_manually_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); run=root/"20260920T010000Z-12345678"; run.mkdir()
            (run/"manifest.json").write_text('{"status":"SUCCESS"}',encoding="utf-8")
            (run/"rules_inventory.csv").write_text("rule_href\n/r/1\n",encoding="utf-8")
            prepared=prepare_run_archive(run,root/"archives")
            self.assertTrue(prepared.path.is_file())
            self.assertEqual(
                prepared.sha256,
                hashlib.sha256(prepared.path.read_bytes()).hexdigest(),
            )
            restored=restore_archive(prepared.path,root/"restored")
            self.assertEqual(
                (restored/"rules_inventory.csv").read_text(),
                (run/"rules_inventory.csv").read_text(),
            )
            self.assertFalse(any((root/"archives").glob("*.tmp")))

    def test_failed_archive_leaves_no_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); run=root/"run"; run.mkdir()
            (run/"data.csv").write_text("x\n1\n",encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"no manifest"):
                prepare_run_archive(run,root/"archives")
            self.assertFalse((root/"archives").exists())

    def test_expired_archive_and_metadata_are_purged(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); archive=root/"archives"/"run.tar.gz"
            archive.parent.mkdir(); archive.write_bytes(b"archive")
            db=Database(root/"state.sqlite"); db.initialize()
            db.record_archive("run","TRAFFIC",str(archive),"abc",7,"2026-01-01")
            self.assertEqual(purge_expired_archives(db,date(2026,1,2)),["run"])
            self.assertFalse(archive.exists())
            with db.connect() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM run_archives").fetchone()[0],0)
