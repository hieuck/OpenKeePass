# OpenKeePass MVP Design

## Goal

Build OpenKeePass, a native iOS KeePass-compatible password manager that can replace the basic paid-gated workflows of KeePassium while keeping every shipped feature free. The first milestone targets iOS 15 and newer, produces an installable `.ipa` from GitHub Actions, and focuses on a reliable end-to-end KeePass `.kdbx` workflow before adding advanced convenience features.

## Product Scope

Milestone 1 includes:

- Native SwiftUI iPhone and iPad app targeting iOS 15.0 or newer.
- Open existing KeePass `.kdbx` databases from iOS Files providers, including iCloud Drive and third-party providers exposed through Files.
- Create new `.kdbx` databases.
- Unlock with master password and key-file support for common KeePass key-file forms.
- Browse groups and entries.
- Create, edit, and delete groups and entries.
- Search entries by title, username, URL, and notes.
- Copy username, password, URL, notes, and custom text fields to the clipboard with automatic clearing.
- Generate passwords with configurable length and character classes.
- Protect app access with Face ID or Touch ID through `LocalAuthentication`.
- Auto-lock on backgrounding and after inactivity.
- Provide an AutoFill Credential Provider extension for finding and filling credentials from the selected vault.
- Build and package an `.ipa` artifact in GitHub Actions.
- Ship without subscriptions, in-app purchases, ads, telemetry, feature locks, or paid tiers.

Milestone 1 explicitly excludes:

- App Store distribution.
- Paid sync provider integrations that bypass iOS Files.
- Browser extensions.
- YubiKey challenge-response.
- Passkey/WebAuthn storage.
- Full security audit claims.
- Full feature parity with KeePassium.

These exclusions are not product rejections. They are later milestones after the core database, edit, security, AutoFill, and CI paths are working.

## Architecture

The repository will contain an Xcode workspace with a native iOS app target, an AutoFill extension target, and Swift package modules for shared logic.

Proposed module boundaries:

- `OpenKeePassApp`: SwiftUI app shell, routing, scene lifecycle, document import, settings, and unlocked vault screens.
- `OpenKeePassAutoFill`: Credential provider extension UI and lookup flow.
- `KeePassCore`: KeePass-facing domain model and KDBX load/save adapter.
- `VaultStore`: opened vault state, file coordination, dirty-state tracking, autosave orchestration, and lock/unlock transitions.
- `SecurityKit`: LocalAuthentication, Keychain wrappers, app group access, clipboard timeout, and memory-handling utilities.
- `PasswordTools`: password generator and strength heuristics.
- `SharedUI`: reusable SwiftUI components shared by the app and extension where extension-safe.

The app UI depends on `VaultStore` and domain models, not directly on the KDBX parser. `KeePassCore` hides whether the first implementation uses a vetted dependency, adapted open-source code, or a local parser. This keeps UI work stable if the KDBX engine changes.

## KDBX Strategy

The MVP must support KeePass `.kdbx` as a real file format, not a mock or proprietary substitute. The implementation will start by evaluating the most practical Swift-compatible KDBX path:

1. Use an existing Swift/iOS-compatible implementation if its license and maintenance profile are acceptable.
2. If no acceptable dependency exists, implement the minimum KDBX 4 path required for password-protected and key-file-protected databases first, with clear tests and vectors.
3. Preserve unknown fields and XML data where possible when saving, to avoid data loss during round trips.

KDBX support for the MVP is considered complete only when a database created by OpenKeePass can be reopened by OpenKeePass and a representative KeePass-compatible desktop app, and a representative existing `.kdbx` file can be opened and edited without losing standard fields.

## Data Flow

Opening a vault:

1. User selects a `.kdbx` file through `UIDocumentPickerViewController`.
2. App stores a security-scoped bookmark for the file URL.
3. User enters master password and optionally selects a key file for databases that require one.
4. `VaultStore` asks `KeePassCore` to decrypt and parse the database.
5. The decrypted domain model stays in memory only while unlocked.
6. UI observes `VaultStore` state and renders groups, entries, search, and editor screens.

Saving a vault:

1. UI sends create, edit, delete, or move operations to `VaultStore`.
2. `VaultStore` updates the in-memory model and marks the vault dirty.
3. Save serializes through `KeePassCore`, writes via coordinated file access, and records success or conflict state.
4. If the backing file changed externally, the app avoids silent overwrite and asks the user to reload or save a copy.

AutoFill:

1. Main app writes extension-safe configuration and an encrypted/cached copy of the selected vault into an App Group container when AutoFill is enabled.
2. AutoFill extension asks the user to unlock with biometrics and/or master password.
3. Extension filters entries by associated domains, URLs, and search text.
4. Extension returns `ASPasswordCredential` to the system.

## Security Model

OpenKeePass is local-first. It does not send vault data, secrets, diagnostics, or metadata to a server.

Security requirements for MVP:

- No network calls in the app or extension except those performed by iOS Files providers outside app control.
- Master password is never persisted.
- Biometric unlock uses Keychain-protected material or session reauthentication, not plaintext master password storage.
- Vault contents are cleared from observable app state when locked.
- App locks on backgrounding according to the configured timeout.
- Clipboard writes are cleared after a configurable timeout and should avoid Universal Clipboard when iOS APIs allow local-only expiration.
- Screens are obscured when app lock is active.
- AutoFill uses App Group storage and should assume a tighter memory budget than the main app.

The MVP will not claim formal audit-level security. It will include tests and code structure that make future review realistic.

## User Experience

The first screen is the vault list, not a landing page. Users can add an existing `.kdbx` file, create a new vault, or unlock a recent vault.

Unlocked layout:

- iPhone uses navigation stacks: group list, entry list, entry detail/editor.
- iPad uses a sidebar-style layout when available.
- Primary actions use native toolbar buttons and SF Symbols.
- Search is available from the entry list.
- Entry detail exposes copy buttons for username, password, URL, notes, and custom fields.
- Editing uses native forms with explicit save/cancel where needed.
- Settings include security timeout, biometric lock, clipboard timeout, AutoFill setup status, and app information.

The interface should feel like a utility app: compact, predictable, and optimized for repeated use rather than marketing presentation.

## Error Handling

Important error states get typed errors and user-facing messages:

- Unsupported KDBX version or cipher.
- Wrong password or key file.
- Corrupt database.
- File provider unavailable.
- Security-scoped bookmark expired.
- Save conflict from external file change.
- AutoFill memory or unlock failure.

Errors must not include master passwords, key-file contents, decrypted fields, or raw database bytes.

## Testing And Verification

MVP verification requires:

- Unit tests for password generation.
- Unit tests for vault state transitions: locked, unlocking, unlocked, dirty, saving, failed.
- KDBX round-trip tests with checked-in non-sensitive fixtures.
- Tests that verify unknown/custom fields are preserved when the engine supports preservation.
- UI smoke tests for open/unlock/list/search/edit flows where practical.
- AutoFill extension build verification.
- GitHub Actions workflow that runs tests and uploads an `.ipa` artifact.

The goal is not only to compile. The app must prove the main user workflow works against real `.kdbx` fixtures.

## CI And Packaging

GitHub Actions will use a macOS runner with Xcode. The workflow will:

1. Resolve Swift package dependencies.
2. Build the app and AutoFill extension for iOS.
3. Run unit tests.
4. Archive the app.
5. Export an unsigned or ad-hoc `.ipa` suitable for sideloading/signing workflows.
6. Upload the `.ipa` and logs as artifacts.

Signing will be parameterized so the workflow can work in two modes:

- Public default: build and package as far as possible without private certificates.
- Optional signed mode: use repository secrets for a development or ad-hoc certificate and provisioning profile.

## Milestone Acceptance Criteria

Milestone 1 is accepted when current repository evidence proves:

- The project contains a native Swift iOS app target with deployment target iOS 15.0 or lower.
- The project contains an AutoFill extension target.
- The app opens and creates real `.kdbx` files.
- The app unlocks password-only and password-plus-key-file `.kdbx` files.
- The app can browse, search, create, edit, and delete groups and entries.
- The app can save changes back to `.kdbx`.
- The app provides biometric app protection and auto-lock.
- The app provides clipboard timeout handling.
- The AutoFill extension builds and can return credentials.
- All shipped features are free with no paywall, IAP, ads, telemetry, or subscriptions.
- GitHub Actions defines a workflow that builds/tests and uploads an `.ipa`.
- Tests or fixtures verify the core KeePass compatibility path.

## Later Milestones

Milestone 2:

- TOTP display and copy.
- Attachments.
- Entry history.
- Better custom fields and custom icons.
- Read-only mode.
- Timestamped backups.
- Stronger conflict resolution.

Milestone 3:

- KDBX 3 compatibility if not already covered.
- Wider cipher/KDF coverage.
- Multi-database polish.
- Import/export helpers.
- Security hardening pass.
- Performance work for large vaults and AutoFill memory limits.

Milestone 4:

- YubiKey challenge-response.
- Passkey/WebAuthn-compatible KeePassXC fields.
- Advanced audit tools.
- Optional app distribution hardening.
