import XCTest

final class FreeFeaturePolicyTests: XCTestCase {
    func testRepositoryDoesNotAddPaidFeatureOrTrackingIntegrations() throws {
        let repositoryRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let allowlist = try FreeFeatureAllowlist.load(
            from: repositoryRoot.appendingPathComponent("ci/free-feature-policy-allowlist.json")
        )
        let scanner = FreeFeaturePolicyScanner(repositoryRoot: repositoryRoot, allowlist: allowlist)

        let violations = try scanner.scan()

        XCTAssertTrue(
            violations.isEmpty,
            "Free-feature policy violations:\n" + violations.map(\.description).joined(separator: "\n")
        )
    }
}

private struct FreeFeatureAllowlist {
    let entriesByPath: [String: Set<String>]

    static func load(from url: URL) throws -> FreeFeatureAllowlist {
        let data = try Data(contentsOf: url)
        let decoded = try JSONDecoder().decode([String: [String]].self, from: data)
        return FreeFeatureAllowlist(entriesByPath: decoded.mapValues(Set.init))
    }

    func allows(ruleID: String, at relativePath: String) -> Bool {
        entriesByPath[relativePath]?.contains(ruleID) == true
    }
}

private struct FreeFeaturePolicyScanner {
    struct Rule {
        let id: String
        let expression: NSRegularExpression

        init(_ id: String, _ pattern: String) {
            self.id = id
            expression = try! NSRegularExpression(
                pattern: pattern,
                options: [.caseInsensitive]
            )
        }
    }

    let repositoryRoot: URL
    let allowlist: FreeFeatureAllowlist

    private let rules = [
        Rule("storekit", #"\bStoreKit\b"#),
        Rule("revenuecat", #"\bRevenueCat\b"#),
        Rule("google-mobile-ads", #"\bGoogleMobileAds\b"#),
        Rule("ad-support", #"\bAdSupport\b"#),
        Rule("app-tracking-transparency", #"\bAppTrackingTransparency\b"#),
        Rule("firebase-analytics", #"\bFirebaseAnalytics\b"#),
        Rule("telemetry-deck", #"\bTelemetryDeck\b"#),
        Rule("paywall", #"\bpaywalls?\b"#),
        Rule("subscription", #"\bsubscriptions?\b"#),
        Rule("in-app-purchase", #"\bin-app purchases?\b"#),
        Rule("feature-lock", #"\bfeature locks?\b"#),
        Rule("telemetry", #"\btelemetry\b"#)
    ]

    func scan() throws -> [Violation] {
        let files = try candidateFiles()
        return try files.flatMap(scanFile)
    }

    private func candidateFiles() throws -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: repositoryRoot,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: []
        ) else {
            return []
        }

        return try enumerator.compactMap { item in
            guard let url = item as? URL else {
                return nil
            }
            if shouldSkipDirectory(url) {
                enumerator.skipDescendants()
                return nil
            }

            let values = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true, isScannedFile(url) else {
                return nil
            }
            return url
        }
    }

    private func scanFile(_ url: URL) throws -> [Violation] {
        let relativePath = url.path
            .replacingOccurrences(of: repositoryRoot.path + "/", with: "")
            .replacingOccurrences(of: "\\", with: "/")
        let contents = try String(contentsOf: url, encoding: .utf8)

        return rules.compactMap { rule in
            let range = NSRange(contents.startIndex..<contents.endIndex, in: contents)
            guard rule.expression.firstMatch(in: contents, range: range) != nil,
                  !allowlist.allows(ruleID: rule.id, at: relativePath) else {
                return nil
            }
            return Violation(relativePath: relativePath, ruleID: rule.id)
        }
    }

    private func shouldSkipDirectory(_ url: URL) -> Bool {
        let skippedDirectories: Set<String> = [
            ".build",
            ".git",
            "docs",
            "Fixtures",
            "Sources/CArgon2",
            "Sources/CMiniz",
            "Tests"
        ]
        let relativePath = url.path
            .replacingOccurrences(of: repositoryRoot.path + "/", with: "")
            .replacingOccurrences(of: "\\", with: "/")
        return skippedDirectories.contains(relativePath)
    }

    private func isScannedFile(_ url: URL) -> Bool {
        let filename = url.lastPathComponent
        if filename == "Package.swift" || filename == "project.yml" || filename == "README.md" {
            return true
        }

        switch url.pathExtension {
        case "swift", "yml", "yaml", "plist":
            return true
        default:
            return false
        }
    }
}

private struct Violation {
    let relativePath: String
    let ruleID: String

    var description: String {
        "\(relativePath): \(ruleID)"
    }
}
