"""Tests for structured loot extraction and the on-disk LootStore."""

from __future__ import annotations

from domainerator.loot import LootKind, LootStore, extract_loot

# --- extraction ------------------------------------------------------------

def test_extract_cleartext_nxc_style():
    items = extract_loot("SMB 10.0.0.10 [+] CORP\\alice:Summer2024!")
    assert any(i.kind is LootKind.CLEARTEXT and i.value == "CORP\\alice:Summer2024!"
               for i in items)


def test_extract_cleartext_username_password_style():
    items = extract_loot("[+] Found credentials Username: svc_backup Password: Sup3r!")
    assert any(i.kind is LootKind.CLEARTEXT and i.value == "svc_backup:Sup3r!"
               for i in items)


def test_extract_ntlm_hash():
    line = "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    items = extract_loot(line)
    assert any(i.kind is LootKind.NTLM_HASH for i in items)


def test_extract_kerberos_tgs_and_asrep():
    out = "$krb5tgs$23$*svc*CORP*$abcdef\n$krb5asrep$23$user@CORP:deadbeef"
    kinds = {i.kind for i in extract_loot(out)}
    assert LootKind.KERBEROS_TGS in kinds
    assert LootKind.KERBEROS_ASREP in kinds


def test_extract_timeroast():
    items = extract_loot("1000:$sntp-ms$aabbccddeeff")
    assert any(i.kind is LootKind.TIMEROAST for i in items)


def test_extract_dedupes():
    out = "$krb5tgs$23$*svc*$abc\n$krb5tgs$23$*svc*$abc"
    items = [i for i in extract_loot(out) if i.kind is LootKind.KERBEROS_TGS]
    assert len(items) == 1


def test_extract_ignores_benign_output():
    assert extract_loot("SMB 10.0.0.10 445 HOST (signing:True)") == []


# --- LootStore -------------------------------------------------------------

def test_lootstore_writes_per_kind_files(tmp_path):
    store = LootStore(tmp_path / "loot")
    items = extract_loot(
        "SMB [+] CORP\\alice:pw\n"
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    )
    new = store.add(items)
    assert len(new) == 2
    assert (tmp_path / "loot" / "cleartext.txt").exists()
    assert (tmp_path / "loot" / "ntlm_hash.txt").exists()


def test_lootstore_file_has_hashcat_mode_header(tmp_path):
    store = LootStore(tmp_path / "loot")
    store.add(extract_loot("$krb5tgs$23$*svc*$abc"))
    text = (tmp_path / "loot" / "kerberos_tgs.txt").read_text()
    assert "hashcat -m 13100" in text
    assert "$krb5tgs$23$*svc*$abc" in text


def test_lootstore_dedupes_across_adds(tmp_path):
    store = LootStore(tmp_path / "loot")
    items = extract_loot("$krb5tgs$23$*svc*$abc")
    assert len(store.add(items)) == 1
    assert len(store.add(items)) == 0  # same loot not written twice
    # File has exactly one hash line (plus the header).
    lines = [
        ln for ln in (tmp_path / "loot" / "kerberos_tgs.txt").read_text().splitlines()
        if ln and not ln.startswith("#")
    ]
    assert lines == ["$krb5tgs$23$*svc*$abc"]


def test_lootstore_dedupes_against_existing_file(tmp_path):
    # A fresh store pointed at an existing loot dir must not re-add known values.
    d = tmp_path / "loot"
    LootStore(d).add(extract_loot("$krb5tgs$23$*svc*$abc"))
    store2 = LootStore(d)
    assert store2.add(extract_loot("$krb5tgs$23$*svc*$abc")) == []


def test_lootstore_lazy_no_dir_until_write(tmp_path):
    store = LootStore(tmp_path / "loot")
    assert not (tmp_path / "loot").exists()
    store.add([])  # empty add writes nothing
    assert not (tmp_path / "loot").exists()
