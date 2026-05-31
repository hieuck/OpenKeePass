# OpenKeePass MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first native iOS OpenKeePass MVP with free KeePass `.kdbx` workflows, iOS 15 support, AutoFill target, and GitHub Actions `.ipa` packaging.

**Architecture:** Use XcodeGen to define an iOS app target, AutoFill extension target, and focused Swift package modules. Keep KDBX parsing behind `KeePassCore` so the UI and vault workflow can stabilize while the real KDBX engine is implemented and verified with fixtures.

**Tech Stack:** Swift 5.9+, SwiftUI, XCTest, LocalAuthentication, AuthenticationServices, Security, UniformTypeIdentifiers, XcodeGen, GitHub Actions macOS runners.

---

## File Structure

- `project.yml`: XcodeGen project definition for the app, extension, packages, tests, entitlements, and iOS 15 deployment target.
- `Package.swift`: Swift package manifest for shared modules and their unit tests.
- `Sources/KeePassCore/`: KeePass domain models, KDBX adapter protocol, fixture-backed round-trip tests, and concrete engine.
- `Sources/VaultStore/`: lock/unlock state, file references, dirty state, save orchestration, and error mapping.
- `Sources/SecurityKit/`: Keychain wrapper, biometric gate, clipboard service, and app group paths.
- `Sources/PasswordTools/`: password generation and strength scoring.
- `Sources/SharedUI/`: shared SwiftUI views that are safe for app and extension.
- `OpenKeePassApp/`: main SwiftUI app target, document picker bridge, vault list, unlock, group list, entry detail, editor, settings.
- `OpenKeePassAutoFill/`: AutoFill credential provider extension.
- `Tests/`: XCTest targets for package modules.
- `Fixtures/KDBX/`: non-sensitive sample `.kdbx` files and expected metadata JSON.
- `.github/workflows/ios.yml`: CI workflow that builds, tests, archives, exports `.ipa`, and uploads artifacts.
- `README.md`: local development and CI signing instructions.

## Task 1: Project And Package Scaffold

**Files:**
- Create: `Package.swift`
- Create: `project.yml`
- Create: `.gitignore`
- Create: `README.md`
- Create: `OpenKeePassApp/Info.plist`
- Create: `OpenKeePassAutoFill/Info.plist`
- Create: `OpenKeePassApp/OpenKeePassApp.entitlements`
- Create: `OpenKeePassAutoFill/OpenKeePassAutoFill.entitlements`

- [ ] **Step 1: Write the package manifest**

Create `Package.swift` with these modules and test targets:

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenKeePassCore",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "KeePassCore", targets: ["KeePassCore"]),
        .library(name: "VaultStore", targets: ["VaultStore"]),
        .library(name: "SecurityKit", targets: ["SecurityKit"]),
        .library(name: "PasswordTools", targets: ["PasswordTools"]),
        .library(name: "SharedUI", targets: ["SharedUI"])
    ],
    targets: [
        .target(name: "KeePassCore"),
        .target(name: "VaultStore", dependencies: ["KeePassCore", "SecurityKit"]),
        .target(name: "SecurityKit"),
        .target(name: "PasswordTools"),
        .target(name: "SharedUI", dependencies: ["KeePassCore", "PasswordTools"]),
        .testTarget(name: "KeePassCoreTests", dependencies: ["KeePassCore"], resources: [.copy("../../Fixtures/KDBX")]),
        .testTarget(name: "VaultStoreTests", dependencies: ["VaultStore"]),
        .testTarget(name: "SecurityKitTests", dependencies: ["SecurityKit"]),
        .testTarget(name: "PasswordToolsTests", dependencies: ["PasswordTools"])
    ]
)
```

- [ ] **Step 2: Write the XcodeGen project definition**

Create `project.yml` with iOS 15 deployment target, app and extension bundle IDs, and package dependencies:

```yaml
name: OpenKeePass
options:
  minimumXcodeGenVersion: 2.42.0
  deploymentTarget:
    iOS: "15.0"
settings:
  base:
    SWIFT_VERSION: "5.9"
    DEVELOPMENT_TEAM: ""
packages:
  OpenKeePassCore:
    path: .
targets:
  OpenKeePass:
    type: application
    platform: iOS
    deploymentTarget: "15.0"
    sources:
      - OpenKeePassApp
    dependencies:
      - package: OpenKeePassCore
        product: KeePassCore
      - package: OpenKeePassCore
        product: VaultStore
      - package: OpenKeePassCore
        product: SecurityKit
      - package: OpenKeePassCore
        product: PasswordTools
      - package: OpenKeePassCore
        product: SharedUI
      - target: OpenKeePassAutoFill
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: dev.openkeepass.app
        INFOPLIST_FILE: OpenKeePassApp/Info.plist
        CODE_SIGN_STYLE: Automatic
    entitlements:
      path: OpenKeePassApp/OpenKeePassApp.entitlements
  OpenKeePassAutoFill:
    type: app-extension
    platform: iOS
    deploymentTarget: "15.0"
    sources:
      - OpenKeePassAutoFill
    dependencies:
      - sdk: AuthenticationServices.framework
      - package: OpenKeePassCore
        product: KeePassCore
      - package: OpenKeePassCore
        product: SecurityKit
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: dev.openkeepass.app.autofill
        INFOPLIST_FILE: OpenKeePassAutoFill/Info.plist
        CODE_SIGN_STYLE: Automatic
    entitlements:
      path: OpenKeePassAutoFill/OpenKeePassAutoFill.entitlements
schemes:
  OpenKeePass:
    build:
      targets:
        OpenKeePass: all
    test:
      gatherCoverageData: true
      targets:
        - OpenKeePassCoreTests
        - VaultStoreTests
        - SecurityKitTests
        - PasswordToolsTests
```

- [ ] **Step 3: Add metadata and entitlements**

Add Info.plist files with display names, extension point identifier `com.apple.authentication-services-credential-provider-ui`, Face ID usage text, document types for `.kdbx`, and app group `group.dev.openkeepass`.

- [ ] **Step 4: Verify scaffold generation**

Run:

```bash
xcodegen generate
xcodebuild -list -project OpenKeePass.xcodeproj
```

Expected: `OpenKeePass` scheme appears, with app and AutoFill targets.

- [ ] **Step 5: Commit**

```bash
git add Package.swift project.yml .gitignore README.md OpenKeePassApp OpenKeePassAutoFill
git commit -m "chore: scaffold iOS project"
```

## Task 2: Password Generator With TDD

**Files:**
- Create: `Sources/PasswordTools/PasswordGenerator.swift`
- Create: `Tests/PasswordToolsTests/PasswordGeneratorTests.swift`

- [ ] **Step 1: Write failing tests**

```swift
import XCTest
@testable import PasswordTools

final class PasswordGeneratorTests: XCTestCase {
    func testGeneratesRequestedLength() {
        let generator = PasswordGenerator(random: .deterministic(seed: 1))
        let password = generator.generate(options: .init(length: 24))
        XCTAssertEqual(password.count, 24)
    }

    func testIncludesEnabledCharacterClasses() {
        let generator = PasswordGenerator(random: .deterministic(seed: 2))
        let password = generator.generate(options: .init(length: 32, includeUppercase: true, includeLowercase: true, includeDigits: true, includeSymbols: true))
        XCTAssertTrue(password.contains(where: { $0.isUppercase }))
        XCTAssertTrue(password.contains(where: { $0.isLowercase }))
        XCTAssertTrue(password.contains(where: { $0.isNumber }))
        XCTAssertTrue(password.contains(where: { "!@#$%^&*()-_=+[]{};:,.?/".contains($0) }))
    }

    func testRejectsEmptyCharacterSet() {
        let generator = PasswordGenerator(random: .deterministic(seed: 3))
        XCTAssertThrowsError(try generator.generateStrict(options: .init(length: 16, includeUppercase: false, includeLowercase: false, includeDigits: false, includeSymbols: false))) { error in
            XCTAssertEqual(error as? PasswordGeneratorError, .emptyCharacterSet)
        }
    }
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
swift test --filter PasswordGeneratorTests
```

Expected: compile fails because `PasswordGenerator` does not exist.

- [ ] **Step 3: Implement generator**

Create `PasswordGenerator.swift` with `PasswordGeneratorOptions`, `PasswordGeneratorError`, deterministic test RNG, secure RNG default, and class coverage enforcement.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
swift test --filter PasswordGeneratorTests
```

Expected: all `PasswordGeneratorTests` pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/PasswordTools Tests/PasswordToolsTests
git commit -m "feat: add password generator"
```

## Task 3: KeePass Domain Model And KDBX Adapter Contract

**Files:**
- Create: `Sources/KeePassCore/VaultModels.swift`
- Create: `Sources/KeePassCore/KDBXEngine.swift`
- Create: `Tests/KeePassCoreTests/VaultModelsTests.swift`

- [ ] **Step 1: Write failing domain tests**

Test that vaults preserve stable UUIDs, entries expose common KeePass fields, and search matches title, username, URL, notes, and custom text fields.

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
swift test --filter VaultModelsTests
```

Expected: compile fails because `KeePassVault`, `KeePassGroup`, and `KeePassEntry` do not exist.

- [ ] **Step 3: Implement models**

Define value models:

```swift
public struct KeePassVault: Equatable, Sendable {
    public var id: UUID
    public var name: String
    public var root: KeePassGroup
}

public struct KeePassGroup: Identifiable, Equatable, Sendable {
    public var id: UUID
    public var title: String
    public var groups: [KeePassGroup]
    public var entries: [KeePassEntry]
}

public struct KeePassEntry: Identifiable, Equatable, Sendable {
    public var id: UUID
    public var title: String
    public var username: String
    public var password: String
    public var url: String
    public var notes: String
    public var customFields: [KeePassField]
}
```

Define `KDBXEngine` with async `open`, `create`, and `save`.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
swift test --filter VaultModelsTests
```

Expected: all `VaultModelsTests` pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/KeePassCore Tests/KeePassCoreTests
git commit -m "feat: add KeePass domain model"
```

## Task 4: Vault Store State Machine

**Files:**
- Create: `Sources/VaultStore/VaultStore.swift`
- Create: `Sources/VaultStore/VaultDocument.swift`
- Create: `Tests/VaultStoreTests/VaultStoreTests.swift`

- [ ] **Step 1: Write failing state tests**

Tests cover locked initial state, successful unlock using an injected fake `KDBXEngine`, dirty state after editing, successful save clearing dirty state, and failed save preserving dirty state.

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
swift test --filter VaultStoreTests
```

Expected: compile fails because `VaultStore` does not exist.

- [ ] **Step 3: Implement minimal store**

Use `ObservableObject` for iOS 15 compatibility:

```swift
@MainActor
public final class VaultStore: ObservableObject {
    @Published public private(set) var state: VaultState = .locked
    private let engine: KDBXEngine
}
```

Add unlock, lock, apply mutation, and save methods.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
swift test --filter VaultStoreTests
```

Expected: all `VaultStoreTests` pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultStore Tests/VaultStoreTests
git commit -m "feat: add vault state store"
```

## Task 5: Security Services

**Files:**
- Create: `Sources/SecurityKit/BiometricGate.swift`
- Create: `Sources/SecurityKit/ClipboardService.swift`
- Create: `Sources/SecurityKit/AppGroupContainer.swift`
- Create: `Tests/SecurityKitTests/ClipboardServiceTests.swift`

- [ ] **Step 1: Write failing clipboard tests**

Tests verify clipboard values expire through an injected pasteboard and scheduler.

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
swift test --filter ClipboardServiceTests
```

Expected: compile fails because `ClipboardService` does not exist.

- [ ] **Step 3: Implement services**

Implement protocols around `LAContext`, `UIPasteboard`, and app group URL lookup. Keep UIKit-dependent types behind conditional imports where package tests require it.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
swift test --filter ClipboardServiceTests
```

Expected: all `ClipboardServiceTests` pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/SecurityKit Tests/SecurityKitTests
git commit -m "feat: add security services"
```

## Task 6: Main App UI

**Files:**
- Create: `OpenKeePassApp/OpenKeePassApp.swift`
- Create: `OpenKeePassApp/AppRootView.swift`
- Create: `OpenKeePassApp/VaultListView.swift`
- Create: `OpenKeePassApp/UnlockView.swift`
- Create: `OpenKeePassApp/GroupListView.swift`
- Create: `OpenKeePassApp/EntryDetailView.swift`
- Create: `OpenKeePassApp/EntryEditorView.swift`
- Create: `OpenKeePassApp/SettingsView.swift`
- Create: `OpenKeePassApp/DocumentPicker.swift`

- [ ] **Step 1: Add UI around existing store APIs**

Wire `@StateObject` root ownership for `VaultStore`, `NavigationView` for iOS 15, document picker sheet, unlock form, group/entry browsing, entry detail, editor, settings, and generator controls.

- [ ] **Step 2: Build app**

Run:

```bash
xcodebuild -project OpenKeePass.xcodeproj -scheme OpenKeePass -destination 'generic/platform=iOS Simulator' build
```

Expected: app and extension compile.

- [ ] **Step 3: Commit**

```bash
git add OpenKeePassApp
git commit -m "feat: add main app UI"
```

## Task 7: AutoFill Extension

**Files:**
- Create: `OpenKeePassAutoFill/CredentialProviderViewController.swift`
- Create: `OpenKeePassAutoFill/AutoFillCredentialStore.swift`
- Modify: `OpenKeePassAutoFill/Info.plist`

- [ ] **Step 1: Implement extension flow**

Implement `ASCredentialProviderViewController`, domain filtering, manual search, biometric gate call, and `ASPasswordCredential` completion.

- [ ] **Step 2: Build extension**

Run:

```bash
xcodebuild -project OpenKeePass.xcodeproj -scheme OpenKeePass -destination 'generic/platform=iOS Simulator' build
```

Expected: AutoFill target builds and is embedded in the app.

- [ ] **Step 3: Commit**

```bash
git add OpenKeePassAutoFill
git commit -m "feat: add AutoFill extension"
```

## Task 8: Real KDBX Compatibility

**Files:**
- Modify: `Sources/KeePassCore/KDBXEngine.swift`
- Create: `Sources/KeePassCore/KDBX4Engine.swift`
- Create: `Sources/KeePassCore/KeyFile.swift`
- Create: `Tests/KeePassCoreTests/KDBXRoundTripTests.swift`
- Create: `Fixtures/KDBX/password-only.kdbx`
- Create: `Fixtures/KDBX/password-keyfile.kdbx`
- Create: `Fixtures/KDBX/password-keyfile.key`

- [ ] **Step 1: Add failing fixture tests**

Tests open password-only and password-plus-key-file databases, assert known entry fields, edit a field, save to temporary data, reopen, and assert the edit persists.

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
swift test --filter KDBXRoundTripTests
```

Expected: fails because `KDBX4Engine` cannot parse fixtures yet.

- [ ] **Step 3: Implement KDBX 4 engine**

Implement header parsing, composite key derivation, AES-KDF or Argon2 path selected by fixture requirements, payload decrypt, XML parse, protected fields, save, and key-file composite key support. Keep unsupported formats as typed `KDBXError.unsupportedFeature`.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
swift test --filter KDBXRoundTripTests
```

Expected: password-only and key-file round trips pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/KeePassCore Tests/KeePassCoreTests Fixtures/KDBX
git commit -m "feat: add KDBX4 compatibility"
```

## Task 9: CI IPA Packaging

**Files:**
- Create: `.github/workflows/ios.yml`
- Create: `ci/export-options-unsigned.plist`
- Create: `ci/export-options-ad-hoc.plist`

- [ ] **Step 1: Write workflow**

The workflow checks out the repo, installs XcodeGen, generates the project, runs `swift test`, builds the iOS scheme, archives, exports an `.ipa` when signing secrets exist, and uploads build products and logs.

- [ ] **Step 2: Run local syntax checks**

Run:

```bash
xcodegen generate
xcodebuild -project OpenKeePass.xcodeproj -scheme OpenKeePass -destination 'generic/platform=iOS Simulator' build
```

Expected: project builds locally on macOS.

- [ ] **Step 3: Commit**

```bash
git add .github ci
git commit -m "ci: build and package iOS ipa"
```

## Task 10: MVP Verification Pass

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-05-31-openkeepass-mvp-design.md` only if implementation evidence changes acceptance wording.

- [ ] **Step 1: Run full verification**

Run:

```bash
swift test
xcodegen generate
xcodebuild -project OpenKeePass.xcodeproj -scheme OpenKeePass -destination 'generic/platform=iOS Simulator' test
xcodebuild -project OpenKeePass.xcodeproj -scheme OpenKeePass -destination 'generic/platform=iOS Simulator' build
```

Expected: tests and builds pass.

- [ ] **Step 2: Verify free-feature invariant**

Run:

```bash
rg -n "StoreKit|InApp|purchase|subscription|paywall|telemetry|analytics|ads" .
```

Expected: no production code implements IAP, subscriptions, ads, telemetry, or feature locks.

- [ ] **Step 3: Document usage**

README must include minimum iOS version, local build steps, GitHub Actions signing secrets, `.ipa` artifact location, and the free-feature policy.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/superpowers/specs/2026-05-31-openkeepass-mvp-design.md
git commit -m "docs: document OpenKeePass MVP usage"
```

## Self-Review

Spec coverage:

- Native iOS 15 SwiftUI app: covered by Tasks 1 and 6.
- AutoFill extension: covered by Tasks 1 and 7.
- Free feature policy: covered by Tasks 1, 9, and 10.
- `.kdbx` open/create/save and key files: covered by Tasks 3, 4, and 8.
- Groups, entries, search, edit, delete: covered by Tasks 3, 4, 6, and 8.
- Password generator: covered by Task 2.
- Face ID/Touch ID, auto-lock, clipboard timeout: covered by Tasks 5 and 6.
- GitHub Actions `.ipa`: covered by Task 9.
- Verification and fixtures: covered by Tasks 8 and 10.

Placeholder scan:

- The plan contains no unresolved placeholder markers or open-ended placeholder steps. KDBX details are scoped to the concrete fixture-driven path required by the MVP.

Type consistency:

- Shared types are introduced before consumers: `KeePassCore` before `VaultStore`, `VaultStore` before app UI, `SecurityKit` before AutoFill and app protection.
