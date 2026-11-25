import {
  PublicClientApplication,
  type Configuration,
  type RedirectRequest,
} from "@azure/msal-browser";

const clientId = import.meta.env.VITE_ENTRA_CLIENT_ID as string;
const authority = import.meta.env.VITE_ENTRA_AUTHORITY as string;
const redirectUri = import.meta.env.VITE_ENTRA_REDIRECT_URI as string;
const apiScope = import.meta.env.VITE_ENTRA_API_SCOPE as string;

if (!clientId || !authority || !redirectUri || !apiScope) {
  throw new Error("Missing required Entra External ID SPA configuration");
}

const configuration: Configuration = {
  auth: {
    clientId,
    authority, // https://<tenant-subdomain>.ciamlogin.com/
    redirectUri,
    postLogoutRedirectUri: redirectUri,
    navigateToLoginRequestUrl: true,
  },
  cache: {
    cacheLocation: "sessionStorage",
    storeAuthStateInCookie: false,
  },
};

export const msalInstance = new PublicClientApplication(configuration);

export const signInRequest: RedirectRequest = {
  scopes: [apiScope],
};

// Call once during application startup, before rendering routes.
export async function initializeIdentity(): Promise<void> {
  await msalInstance.initialize();
  const result = await msalInstance.handleRedirectPromise();
  if (result?.account) msalInstance.setActiveAccount(result.account);
  if (!msalInstance.getActiveAccount()) {
    const accounts = msalInstance.getAllAccounts();
    if (accounts.length === 1) msalInstance.setActiveAccount(accounts[0]);
  }
}

export async function signIn(): Promise<void> {
  await msalInstance.loginRedirect(signInRequest);
}

export async function getApiAccessToken(): Promise<string> {
  const account = msalInstance.getActiveAccount();
  if (!account) throw new Error("No signed-in account");
  try {
    const result = await msalInstance.acquireTokenSilent({
      account,
      scopes: [apiScope],
    });
    return result.accessToken;
  } catch {
    // MSAL redirects to the hosted flow; MFA and recovery stay provider-managed.
    await msalInstance.acquireTokenRedirect({
      account,
      scopes: [apiScope],
    });
    throw new Error("Interactive authentication required");
  }
}

export async function signOut(): Promise<void> {
  const account = msalInstance.getActiveAccount();
  await msalInstance.logoutRedirect({ account, postLogoutRedirectUri: redirectUri });
}
