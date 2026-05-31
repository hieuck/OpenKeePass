import AuthenticationServices
import UIKit

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let store = AutoFillCredentialStore()

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        extensionContext.completeRequest(withSelectedCredential: nil, completionHandler: nil)
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        completeRequest(for: credentialIdentity)
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        completeRequest(for: credentialIdentity)
    }

    private func completeRequest(for credentialIdentity: ASPasswordCredentialIdentity) {
        guard
            let recordIdentifier = credentialIdentity.recordIdentifier,
            let credential = store.credential(recordIdentifier: recordIdentifier)
        else {
            extensionContext.cancelRequest(withError: NSError(
                domain: "dev.openkeepass.autofill",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Credential is no longer available."]
            ))
            return
        }

        extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
    }
}
