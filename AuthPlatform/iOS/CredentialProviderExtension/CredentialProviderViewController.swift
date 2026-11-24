import AuthenticationServices
import LocalAuthentication
import UIKit

/// Credential Provider Extension. Credential secrets are decrypted only after
/// the user completes device-owner authentication.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let domains = serviceIdentifiers
            .filter { $0.type == .domain }
            .map(\.identifier)
        let candidateDomains = Set(domains.flatMap { domain in
            [domain] + ApplePasswordManagerResources.shared.relatedCredentialDomains(for: domain)
        })
        let matches = candidateDomains.sorted().flatMap { domain -> [StoredCredentialIdentity] in
            (try? SharedCredentialVault.credentialIdentities(for: domain)) ?? []
        }
        guard !matches.isEmpty else {
            extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
            return
        }

        let picker = UIAlertController(title: "Choose a sign-in", message: nil, preferredStyle: .alert)
        for item in matches {
            picker.addAction(UIAlertAction(title: "\(item.username) · \(item.service)", style: .default) { [weak self] _ in
                self?.authenticateAndProvide(service: item.service, username: item.username)
            })
        }
        picker.addAction(UIAlertAction(title: "Cancel", style: .cancel) { [weak self] _ in
            self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
        })
        present(picker, animated: true)
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        authenticateAndProvide(
            service: credentialIdentity.serviceIdentifier.identifier,
            username: credentialIdentity.user
        )
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        // Do not release passwords silently. Require explicit user presence.
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    private func authenticateAndProvide(service: String, username: String) {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock a saved sign-in") { [weak self] success, error in
            DispatchQueue.main.async {
                guard let self else { return }
                guard success else {
                    self.extensionContext.cancelRequest(withError: error ?? ASExtensionError(.userCanceled))
                    return
                }
                do {
                    // Only decrypt after successful Face ID / Touch ID / passcode authentication.
                    guard let item = try SharedCredentialVault.credential(service: service, username: username) else {
                        self.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                        return
                    }
                    let credential = ASPasswordCredential(user: item.username, password: item.password)
                    self.extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
                } catch {
                    self.extensionContext.cancelRequest(withError: error)
                }
            }
        }
    }
}
