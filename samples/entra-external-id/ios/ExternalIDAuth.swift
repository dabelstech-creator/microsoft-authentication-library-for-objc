import Foundation
import MSAL
import UIKit

/// Browser-delegated Entra External ID sign-in.
/// The identity provider owns password, email verification, MFA and recovery UX.
@MainActor
final class ExternalIDAuth {
    static let shared = ExternalIDAuth()

    private let application: MSALPublicClientApplication

    private init() {
        guard
            let clientId = Bundle.main.object(forInfoDictionaryKey: "ENTRA_CLIENT_ID") as? String,
            let authorityURL = URL(string:
                Bundle.main.object(forInfoDictionaryKey: "ENTRA_AUTHORITY") as? String ?? "")
        else {
            fatalError("Missing ENTRA_CLIENT_ID or ENTRA_AUTHORITY in app configuration")
        }

        do {
            let authority = try MSALAuthority(url: authorityURL)
            let config = MSALPublicClientApplicationConfig(
                clientId: clientId,
                redirectUri: nil, // MSAL derives msauth.<bundle-id>://auth
                authority: authority
            )
            application = try MSALPublicClientApplication(configuration: config)
        } catch {
            fatalError("Unable to initialize MSAL: \(error)")
        }
    }

    func signIn(presenting viewController: UIViewController,
                scopes: [String],
                completion: @escaping (Result<MSALResult, Error>) -> Void) {
        let webParameters = MSALWebviewParameters(authPresentationViewController: viewController)
        let parameters = MSALInteractiveTokenParameters(
            scopes: scopes,
            webviewParameters: webParameters
        )
        application.acquireToken(with: parameters) { result, error in
            if let error {
                completion(.failure(error))
            } else if let result {
                completion(.success(result))
            } else {
                completion(.failure(NSError(
                    domain: "ExternalIDAuth",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "MSAL returned no result"]
                )))
            }
        }
    }

    func acquireTokenSilently(scopes: [String],
                              completion: @escaping (Result<MSALResult, Error>) -> Void) {
        do {
            let accounts = try application.accounts()
            guard let account = accounts.first else {
                throw NSError(domain: "ExternalIDAuth", code: -2,
                              userInfo: [NSLocalizedDescriptionKey: "No signed-in account"])
            }
            let parameters = MSALSilentTokenParameters(scopes: scopes, account: account)
            application.acquireTokenSilent(with: parameters) { result, error in
                if let error { completion(.failure(error)) }
                else if let result { completion(.success(result)) }
                else {
                    completion(.failure(NSError(domain: "ExternalIDAuth", code: -3,
                        userInfo: [NSLocalizedDescriptionKey: "MSAL returned no result"])))
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    /// Forward the app URL callback from UIApplicationDelegate / scene lifecycle.
    static func handleRedirect(_ url: URL) -> Bool {
        MSALPublicClientApplication.handleMSALResponse(url, sourceApplication: nil)
    }
}
