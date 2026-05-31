# OpenKeePass

OpenKeePass is a native iOS KeePass-compatible password manager. The project goal is to provide a free replacement for the core KeePassium workflows: no subscriptions, no in-app purchases, no ads, no telemetry, and no feature locks.

## Scope

The MVP targets iOS 15 and newer. It will support real KeePass `.kdbx` vaults, key files, local biometric protection, clipboard timeout, AutoFill, and GitHub Actions `.ipa` artifacts.

## Local Development

Requirements on macOS:

- Xcode 15 or newer
- Swift 5.9 or newer
- XcodeGen 2.42 or newer

Generate and inspect the project:

```bash
xcodegen generate
xcodebuild -list -project OpenKeePass.xcodeproj
```

Run package tests:

```bash
swift test
```

## CI Packaging

GitHub Actions will generate the Xcode project, run tests, build the app and AutoFill extension, archive the app, and upload `.ipa` artifacts. Unsigned public builds and optional ad-hoc signed builds are both planned.

## Free Feature Policy

Any feature merged into this repository must be fully usable without payment. Code that adds StoreKit purchases, subscriptions, paywalls, ads, telemetry, or feature locks is out of scope for this product.
