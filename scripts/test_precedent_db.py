"""Isolated database checks for absence and precedent ranking."""
import tempfile
from scripts.test_analyst import db, analyst


def test_absence_is_not_an_attack_edge():
    with tempfile.TemporaryDirectory(prefix='precedent-check-') as tmp:
        db.use_data_dir(tmp)
        db.init_db()
        conn = db.connect()
        try:
            eid = db.insert(conn, 'engagements', {'name': 'live', 'created_at': db.now()})
            subject = db.upsert_entity(conn, eid, 'host', 'live-box')
            fid = db.add_fact(conn, eid, subject, 'writable-by', object_text='agent',
                              stage='observed', polarity='absent')
            assert db.row(conn, 'SELECT polarity FROM facts WHERE id=?', (fid,))['polarity'] == 'absent'
            assert not analyst.correlate.Ctx(conn, eid).facts
        finally:
            conn.close()


def test_empty_precedent():
    with tempfile.TemporaryDirectory() as tmp:
        db.use_data_dir(tmp)
        db.init_db()
        conn = db.connect()
        try:
            eid = db.insert(conn, 'engagements', {'name': 'empty', 'created_at': db.now()})
            assert db.precedent(conn, eid) == []
        finally:
            conn.close()
