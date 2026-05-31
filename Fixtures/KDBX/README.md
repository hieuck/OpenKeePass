# KDBX fixtures

These fixtures are non-sensitive compatibility samples for automated tests.

- Master password: `openkeepass`
- `password-keyfile.key`: raw 32-byte key file containing bytes `0x00...0x1f`
- KDF rounds are intentionally low so CI can run the compatibility tests quickly.
- `keepassxc-password.kdbx` was created with KeePassXC CLI, target decryption time `100ms`, and contains a single `GitHub` entry.
- `keepassxc-attachment.kdbx` was created with KeePassXC CLI, target decryption time `100ms`, and contains a single `AttachmentEntry` entry with `keepassxc-attachment.txt`.

The fixtures exercise KDBX 3.1 AES-CBC/AES-KDF parsing, password-only unlock, password-plus-key-file unlock, KeePassXC-generated password and attachment databases, and edit/save/reopen behavior. They do not replace the later requirement to verify broad third-party compatibility with representative KeePass/KeePassXC databases.
