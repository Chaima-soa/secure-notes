import base64

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto import decrypt_note, encrypt_note
from app.integrity import compute_hmac, verify_hmac


def test_aes_gcm_roundtrip_and_random_nonce():
    first = encrypt_note("hello world")
    second = encrypt_note("hello world")
    assert first != second                      # fresh nonce each time
    assert "hello world" not in first
    assert decrypt_note(first) == "hello world"


def test_aes_gcm_detects_a_modified_ciphertext():
    raw = bytearray(base64.b64decode(encrypt_note("hello world")))
    raw[-1] ^= 1                                # flip one bit
    with pytest.raises(InvalidTag):
        decrypt_note(base64.b64encode(bytes(raw)).decode())


def test_hmac_accepts_original_and_rejects_changes():
    mac = compute_hmac(1, "title", "ciphertext")
    assert verify_hmac(1, "title", "ciphertext", mac)
    assert not verify_hmac(1, "HACKED", "ciphertext", mac)
    assert not verify_hmac(2, "title", "ciphertext", mac)
    assert not verify_hmac(1, "title", "other-ciphertext", mac)
    assert not verify_hmac(1, "title", "ciphertext", None)


def test_note_is_stored_encrypted_in_the_database(make_user, db_query):
    client = make_user("alice")
    client.post("/notes/create", data={"title": "T", "content": "TOP-SECRET-123"})
    stored = db_query("SELECT encrypted_content FROM notes")[0][0]
    assert "TOP-SECRET-123" not in stored
    assert decrypt_note(stored) == "TOP-SECRET-123"
    assert b"TOP-SECRET-123" in client.get("/notes/").data   # readable through the app


def test_modified_note_is_detected_by_hmac(make_user, db_query, db_exec):
    client = make_user("alice")
    client.post("/notes/create", data={"title": "Original", "content": "my content"})
    note_id = db_query("SELECT id FROM notes")[0][0]
    assert b"my content" in client.get("/notes/").data

    db_exec("UPDATE notes SET title = 'HACKED' WHERE id = ?", (note_id,))   # attack on the database

    assert b"INTEGRITY ERROR" in client.get("/notes/").data
    assert client.get("/notes/" + str(note_id)).status_code == 500
