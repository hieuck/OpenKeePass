import AuthenticationServices
import Foundation
import SecurityKit

struct AutoFillCredentialStore {
    private let cache: AutoFillCredentialCache?

    init(container: AppGroupContainer = AppGroupContainer()) {
        if let directory = container.url() {
            cache = AutoFillCredentialCache(directory: directory)
        } else {
            cache = nil
        }
    }

    func records(matching serviceIdentifiers: [ASCredentialServiceIdentifier] = []) -> [AutoFillCredentialRecord] {
        (try? cache?.credentials(matchingServiceIdentifiers: serviceIdentifiers.map(\.identifier))) ?? []
    }

    func credentialIdentities(matching serviceIdentifiers: [ASCredentialServiceIdentifier] = []) -> [ASPasswordCredentialIdentity] {
        records(matching: serviceIdentifiers).compactMap { record in
            guard let host = record.serviceHost else {
                return nil
            }
            let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
            return ASPasswordCredentialIdentity(
                serviceIdentifier: service,
                user: record.username,
                recordIdentifier: record.id
            )
        }
    }

    func credential(recordIdentifier: String) -> ASPasswordCredential? {
        guard let record = try? cache?.credential(id: recordIdentifier) else {
            return nil
        }
        return ASPasswordCredential(user: record.username, password: record.password)
    }
}
