import AuthenticationServices
import Foundation

struct AutoFillCredentialStore {
    func credentialIdentities() -> [ASPasswordCredentialIdentity] {
        let service = ASCredentialServiceIdentifier(identifier: "example.com", type: .domain)
        return [
            ASPasswordCredentialIdentity(serviceIdentifier: service, user: "user@example.com", recordIdentifier: "sample")
        ]
    }
}
