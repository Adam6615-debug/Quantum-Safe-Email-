"""
Quantum-Safe Email CLI
=======================
Glues the three team-member modules together behind an `argparse` CLI.

Subcommands:
    setup          - generate fresh RSA + ML-KEM + ML-DSA keypairs
    send           - encrypt+sign a message and send via Gmail SMTP
    receive        - fetch & decrypt+verify recent unread mail
    add-contact    - import a contact's public-key bundle
    list-contacts  - print known contacts (TOFU-imported ones flagged)
    delete-contact - remove a contact
    export-keys    - write your public-key bundle to my_public_keys.json
    threat-report  - print the colour-coded threat analysis
    test           - in-memory end-to-end self-test (no email is sent)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

# Allow running as `python main.py ...` from inside the project directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from member1_crypto.crypto_engine import (   # noqa: E402
    generate_mlkem_keypair, generate_mldsa_keypair, generate_rsa_keypair,
    full_encrypt_and_sign, full_decrypt_and_verify,
)
from member2_keystore.key_store import KeyStore           # noqa: E402
from member2_keystore.threat_analyzer import ThreatAnalyzer  # noqa: E402

try:
    from colorama import init as _ci, Fore, Style
    _ci(autoreset=True)
    OK, ERR, WARN, INFO, BRIGHT = (
        Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.CYAN, Style.BRIGHT
    )
    RESET = Style.RESET_ALL
except Exception:  # pragma: no cover
    OK = ERR = WARN = INFO = BRIGHT = RESET = ""


DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.db")


# =============================================================================
# Helpers
# =============================================================================

def _open_keystore(args) -> KeyStore:
    """Open the keystore at the configured DB path."""
    return KeyStore(getattr(args, "db", None) or DEFAULT_DB)


def _print_banner(text: str) -> None:
    """Print a coloured banner line."""
    print(f"{INFO}{BRIGHT}{'=' * 60}\n  {text}\n{'=' * 60}{RESET}")


def _confirm(prompt: str) -> bool:
    """Prompt the user for a yes/no answer, default to no on EOF."""
    try:
        ans = input(f"{WARN}{prompt} [y/N]: {RESET}").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def _require_email_handler():
    """Lazy-load the email handler so other commands work without .env."""
    from member3_email.email_handler import EmailHandler
    return EmailHandler()


# =============================================================================
# Commands
# =============================================================================

def cmd_setup(args) -> int:
    """Generate the user's three keypairs and persist them to SQLite."""
    _print_banner("Quantum-Safe Email - First-Time Setup")
    with _open_keystore(args) as ks:
        if ks.has_my_keys() and not args.force:
            print(f"{WARN}⚠️  Keypairs already exist.  Use --force to "
                  f"regenerate (existing contacts will not be invalidated, "
                  f"but they will need your new public keys).{RESET}")
            return 1

        print(f"{INFO}Generating ML-KEM-768 keypair (FIPS 203)...{RESET}")
        mlkem_pub, mlkem_priv = generate_mlkem_keypair()
        print(f"{INFO}Generating ML-DSA-65 keypair (FIPS 204)...{RESET}")
        mldsa_pub, mldsa_priv = generate_mldsa_keypair()
        print(f"{INFO}Generating RSA-2048 keypair...{RESET}")
        rsa_pub, rsa_priv = generate_rsa_keypair()

        ks.save_my_keypair(mlkem_pub, mlkem_priv,
                           mldsa_pub, mldsa_priv,
                           rsa_pub, rsa_priv)
    print(f"{OK}✅ Your quantum-safe keypairs generated and stored.{RESET}")
    print(f"{INFO}  DB path : {DEFAULT_DB}{RESET}")
    print(f"{INFO}  Next    : python main.py export-keys "
          f"(send my_public_keys.json to your contacts){RESET}")
    return 0


def cmd_send(args) -> int:
    """Encrypt+sign a message and post it via Gmail."""
    _print_banner("Send Encrypted Email")
    with _open_keystore(args) as ks:
        if not ks.has_my_keys():
            print(f"{ERR}❌ No own keypairs.  Run `python main.py setup` first.{RESET}")
            return 2
        contact = ks.get_contact(args.to)
        if contact is None:
            print(f"{ERR}❌ Recipient '{args.to}' not in your contacts.{RESET}")
            print(f"{INFO}   Add them with `python main.py add-contact "
                  f"--email {args.to} --keys their_keys.json`.{RESET}")
            return 2

        my_keys = ks.load_my_keys()
        public_keys_json = ks.export_my_public_keys()

    print(f"{INFO}Recipient: {args.to}{RESET}")
    print(f"{INFO}Subject  : {args.subject}{RESET}")
    print(f"{INFO}Encrypting with hybrid ML-KEM-768 + RSA-2048 + AES-256-GCM,"
          f" signing with ML-DSA-65...{RESET}")

    package = full_encrypt_and_sign(
        plaintext_str=args.message,
        recipient_mlkem_pubkey=contact["mlkem_public_key"],
        recipient_rsa_pubkey_pem=contact["rsa_public_key"],
        sender_mldsa_privkey=my_keys["mldsa_private"],
    )

    try:
        handler = _require_email_handler()
    except Exception as e:
        print(f"{ERR}❌ Email subsystem not configured: {e}{RESET}")
        return 3

    try:
        handler.send_encrypted_email(
            to_address=args.to,
            subject=args.subject,
            package_dict=package,
            sender_public_keys_json=public_keys_json if not args.no_tofu else None,
        )
    except Exception as e:
        print(f"{ERR}❌ Send failed: {e}{RESET}")
        return 4

    return 0


def cmd_receive(args) -> int:
    """Fetch unread mail and try to decrypt+verify each one."""
    _print_banner("Receive & Decrypt")
    with _open_keystore(args) as ks:
        if not ks.has_my_keys():
            print(f"{ERR}❌ No own keypairs.  Run `python main.py setup` first.{RESET}")
            return 2
        my_keys = ks.load_my_keys()

        try:
            handler = _require_email_handler()
        except Exception as e:
            print(f"{ERR}❌ Email subsystem not configured: {e}{RESET}")
            return 3

        try:
            mails = handler.fetch_encrypted_emails(limit=args.limit)
        except Exception as e:
            print(f"{ERR}❌ Fetch failed: {e}{RESET}")
            return 4

        if not mails:
            print(f"{INFO}(No unread quantum-encrypted emails found.){RESET}")
            return 0

        for i, mail in enumerate(mails, start=1):
            print()
            print(f"{INFO}{BRIGHT}--- Email {i}/{len(mails)} ---{RESET}")
            print(f"{INFO}From    : {mail['from']}{RESET}")
            print(f"{INFO}Subject : {mail['subject']}{RESET}")

            sender_email = (mail["from"] or "").strip().lower()
            contact = ks.get_contact(sender_email) if sender_email else None

            # ---- TOFU import flow --------------------------------------
            if contact is None and mail["tofu_keys"]:
                print(f"{WARN}🔑 New contact detected: {sender_email} - "
                      f"this email includes a public-key bundle.{RESET}")
                if args.auto_tofu or _confirm(
                        f"Import quantum-safe public keys for {sender_email}?"):
                    try:
                        ks.import_contact_from_json(sender_email,
                                                    mail["tofu_keys"], tofu=True)
                        contact = ks.get_contact(sender_email)
                        print(f"{OK}✅ Imported (TOFU){RESET}")
                    except Exception as e:
                        print(f"{ERR}❌ TOFU import failed: {e}{RESET}")

            if contact is None:
                print(f"{WARN}⚠️  Sender unknown - signature cannot be verified."
                      f"  Decrypting WITHOUT verification.{RESET}")
                sender_mldsa_pub = b""
            else:
                sender_mldsa_pub = contact["mldsa_public_key"]

            try:
                plaintext, verified = full_decrypt_and_verify(
                    package_dict=mail["package"],
                    my_mlkem_privkey=my_keys["mlkem_private"],
                    my_rsa_privkey_pem=my_keys["rsa_private"],
                    sender_mldsa_pubkey=sender_mldsa_pub or b"",
                )
            except Exception as e:
                print(f"{ERR}❌ Decryption failed: {e}{RESET}")
                continue

            if verified and contact is not None:
                tag = "QUANTUM-VERIFIED"
                color = OK
                print(f"{color}🔐 [{tag}] From: {sender_email}{RESET}")
            elif contact is None:
                print(f"{WARN}⚠️  [UNVERIFIED] No public key on file for "
                      f"{sender_email}.{RESET}")
            else:
                print(f"{ERR}❌ [SIGNATURE INVALID] message body shown but "
                      f"NOT trusted!{RESET}")
            print(f"{INFO}Body:{RESET}")
            print(plaintext)

    return 0


def cmd_add_contact(args) -> int:
    """Import a contact's public-key bundle JSON file."""
    _print_banner(f"Add Contact: {args.email}")
    try:
        with open(args.keys, "r", encoding="utf-8") as f:
            json_str = f.read()
    except OSError as e:
        print(f"{ERR}❌ Cannot read keys file '{args.keys}': {e}{RESET}")
        return 2

    with _open_keystore(args) as ks:
        try:
            ks.import_contact_from_json(args.email, json_str, tofu=False)
        except Exception as e:
            print(f"{ERR}❌ Import failed: {e}{RESET}")
            return 3
    print(f"{OK}✅ Contact '{args.email}' added.{RESET}")
    return 0


def cmd_list_contacts(args) -> int:
    """Print all known contacts; TOFU-imported ones get a 🔑 [TOFU] tag."""
    _print_banner("Known Contacts")
    with _open_keystore(args) as ks:
        rows = ks.list_contacts_detailed()
    if not rows:
        print(f"{INFO}(No contacts yet.){RESET}")
        return 0
    for row in rows:
        flag = f" {WARN}🔑 [TOFU]{RESET}" if row["tofu_verified"] else ""
        print(f"  {OK}•{RESET} {row['email']}{flag}  "
              f"{INFO}(added {row['added_at']}){RESET}")
    return 0


def cmd_delete_contact(args) -> int:
    """Remove a contact from the keystore."""
    with _open_keystore(args) as ks:
        if ks.delete_contact(args.email):
            print(f"{OK}✅ Deleted contact '{args.email}'.{RESET}")
            return 0
        print(f"{WARN}⚠️  No such contact '{args.email}'.{RESET}")
        return 1


def cmd_export_keys(args) -> int:
    """Write the user's three public keys to my_public_keys.json + stdout."""
    _print_banner("Export Public Keys")
    with _open_keystore(args) as ks:
        if not ks.has_my_keys():
            print(f"{ERR}❌ No keypairs to export.  Run `python main.py setup` "
                  f"first.{RESET}")
            return 2
        bundle = ks.export_my_public_keys()
    out_path = args.output or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "my_public_keys.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(bundle)
    except OSError as e:
        print(f"{ERR}❌ Could not write '{out_path}': {e}{RESET}")
        return 3
    print(bundle)
    print()
    print(f"{OK}✅ Saved bundle to {out_path}{RESET}")
    print(f"{INFO}   Share this file with your contacts so they can encrypt to "
          f"you.{RESET}")
    return 0


def cmd_threat_report(args) -> int:
    """Print the colour-coded threat report."""
    analyzer = ThreatAnalyzer(
        sensitivity=args.sensitivity,
        key_age_days=args.key_age_days,
        algorithm_class=args.algorithm_class,
    )
    analyzer.print_full_report()
    return 0


def cmd_test(args) -> int:
    """Full local end-to-end test (no network, no email)."""
    _print_banner("Local End-to-End Test")
    print(f"{INFO}[1/6] Generating Alice keypairs...{RESET}")
    a_mlkem_pub, a_mlkem_priv = generate_mlkem_keypair()
    a_mldsa_pub, a_mldsa_priv = generate_mldsa_keypair()
    a_rsa_pub,   a_rsa_priv   = generate_rsa_keypair()
    print(f"{OK}✅ Alice keys generated{RESET}")

    print(f"{INFO}[2/6] Generating Bob keypairs...{RESET}")
    b_mlkem_pub, b_mlkem_priv = generate_mlkem_keypair()
    b_mldsa_pub, b_mldsa_priv = generate_mldsa_keypair()
    b_rsa_pub,   b_rsa_priv   = generate_rsa_keypair()
    print(f"{OK}✅ Bob keys generated{RESET}")

    msg = "Top-secret birthday surprise for Bob!  🎂🔐"
    print(f"{INFO}[3/6] Alice encrypts+signs for Bob...{RESET}")
    package = full_encrypt_and_sign(msg, b_mlkem_pub, b_rsa_pub, a_mldsa_priv)
    print(f"{OK}✅ Package built (signature length="
          f"{len(package['signature'])//2} bytes){RESET}")

    print(f"{INFO}[4/6] Bob decrypts+verifies...{RESET}")
    recovered, verified = full_decrypt_and_verify(
        package, b_mlkem_priv, b_rsa_priv, a_mldsa_pub)
    assert recovered == msg, "Plaintext mismatch"
    assert verified is True, "Signature invalid"
    print(f"{OK}✅ Decrypted: {recovered}{RESET}")
    print(f"{OK}✅ Signature verified: {verified}{RESET}")

    print(f"{INFO}[5/6] Tamper test (flip a ciphertext byte)...{RESET}")
    ct = bytearray(bytes.fromhex(package["payload"]["aes_ciphertext"]))
    ct[0] ^= 0xFF
    package["payload"]["aes_ciphertext"] = bytes(ct).hex()
    detected = False
    try:
        full_decrypt_and_verify(package, b_mlkem_priv, b_rsa_priv, a_mldsa_pub)
    except Exception:
        detected = True
    assert detected, "Tampered ciphertext not detected"
    print(f"{OK}✅ Tampering correctly detected (AES-GCM tag check){RESET}")

    print(f"{INFO}[6/6] Wrong-signer test...{RESET}")
    package2 = full_encrypt_and_sign(msg, b_mlkem_pub, b_rsa_pub, a_mldsa_priv)
    _, verified_with_wrong_pubkey = full_decrypt_and_verify(
        package2, b_mlkem_priv, b_rsa_priv, b_mldsa_pub)  # wrong pubkey
    assert verified_with_wrong_pubkey is False
    print(f"{OK}✅ Forged-signer detected (verify=False){RESET}")

    print()
    print(f"{OK}{BRIGHT}🎉 ALL LOCAL TESTS PASSED 🎉{RESET}")
    return 0


# =============================================================================
# CLI plumbing
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse subcommand tree."""
    p = argparse.ArgumentParser(
        prog="quantum-email",
        description="Quantum-Safe Email Client (RSA + ML-KEM + ML-DSA hybrid)",
    )
    p.add_argument("--db", help="Path to SQLite key store (default: keys.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_setup = sub.add_parser("setup", help="Generate your quantum-safe keypairs")
    p_setup.add_argument("--force", action="store_true",
                         help="Overwrite existing keypairs")
    p_setup.set_defaults(func=cmd_setup)

    p_send = sub.add_parser("send", help="Encrypt+sign and send an email")
    p_send.add_argument("--to", required=True, help="Recipient email address")
    p_send.add_argument("--subject", required=True, help="Email subject")
    p_send.add_argument("--message", required=True, help="Plaintext message body")
    p_send.add_argument("--no-tofu", action="store_true",
                        help="Do NOT attach your public keys for TOFU exchange")
    p_send.set_defaults(func=cmd_send)

    p_recv = sub.add_parser("receive", help="Fetch and decrypt unread email")
    p_recv.add_argument("--limit", type=int, default=5, help="Max messages to fetch")
    p_recv.add_argument("--auto-tofu", action="store_true",
                        help="Automatically import unknown sender keys")
    p_recv.set_defaults(func=cmd_receive)

    p_add = sub.add_parser("add-contact", help="Import a contact's public keys")
    p_add.add_argument("--email", required=True)
    p_add.add_argument("--keys", required=True, help="Path to their keys JSON")
    p_add.set_defaults(func=cmd_add_contact)

    p_list = sub.add_parser("list-contacts", help="Print known contacts")
    p_list.set_defaults(func=cmd_list_contacts)

    p_del = sub.add_parser("delete-contact", help="Remove a contact")
    p_del.add_argument("--email", required=True)
    p_del.set_defaults(func=cmd_delete_contact)

    p_exp = sub.add_parser("export-keys",
                           help="Print/save your public-key bundle")
    p_exp.add_argument("--output", help="Output file (default my_public_keys.json)")
    p_exp.set_defaults(func=cmd_export_keys)

    p_thr = sub.add_parser("threat-report", help="Print the threat analysis")
    p_thr.add_argument("--sensitivity", type=int, default=7,
                       help="Data sensitivity 1-10 (default 7)")
    p_thr.add_argument("--key-age-days", type=int, default=0,
                       help="How old your current key is, in days")
    p_thr.add_argument("--algorithm-class",
                       choices=["classical", "pq-only", "hybrid"],
                       default="hybrid")
    p_thr.set_defaults(func=cmd_threat_report)

    p_test = sub.add_parser("test", help="Run a full local self-test")
    p_test.set_defaults(func=cmd_test)

    return p


def main(argv: Optional[list] = None) -> int:
    """CLI entry point - returns a process exit code."""
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(f"\n{WARN}Interrupted.{RESET}")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
