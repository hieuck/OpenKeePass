import AuthenticationServices
import UIKit

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let credentials = [
        ASPasswordCredential(user: "user@example.com", password: "password")
    ]

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        extensionContext.completeRequest(withSelectedCredential: nil, completionHandler: nil)
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        extensionContext.completeRequest(withSelectedCredential: credentials[0], completionHandler: nil)
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        extensionContext.completeRequest(withSelectedCredential: credentials[0], completionHandler: nil)
    }
}
