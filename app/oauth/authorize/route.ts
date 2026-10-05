import { NextRequest, NextResponse } from "next/server";
import {
  createAuthorizationCode,
  getMcpResource,
  getOAuthClient,
  getRequestedResource,
  includesWorkflowyScope,
  isAllowedResource,
  redirectUriMatches,
} from "../../lib/oauth";
import {
  adminSecretMatches,
  isAdminAuthenticated,
  setAdminSessionCookie,
} from "../../api/admin/_auth";

export const runtime = "nodejs";

interface AuthorizationParams {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  resource: string;
}

function htmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function readParams(searchParams: URLSearchParams, requestUrl: string): AuthorizationParams {
  return {
    responseType: searchParams.get("response_type") ?? "",
    clientId: searchParams.get("client_id") ?? "",
    redirectUri: searchParams.get("redirect_uri") ?? "",
    scope: searchParams.get("scope") ?? "workflowy",
    state: searchParams.get("state") ?? "",
    codeChallenge: searchParams.get("code_challenge") ?? "",
    codeChallengeMethod: searchParams.get("code_challenge_method") ?? "",
    resource: getRequestedResource(searchParams.get("resource"), requestUrl),
  };
}

function formPage(params: AuthorizationParams, options: { authenticated: boolean; error?: string; clientName?: string }): Response {
  const title = "Authorize Workflowy MCP";
  const clientLabel = options.clientName || params.clientId || "OAuth client";
  const adminSecretField = options.authenticated
    ? `<p class="ok">You are already signed in as the owner.</p>`
    : `<label>ADMIN_SECRET <input name="admin_secret" type="password" autocomplete="current-password" required /></label>`;
  const error = options.error ? `<p class="error">${htmlEscape(options.error)}</p>` : "";

  const hiddenFields = Object.entries(params)
    .map(([key, value]) => `<input type="hidden" name="${htmlEscape(key)}" value="${htmlEscape(value)}" />`)
    .join("\n");

  return new Response(
    `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f7f7f8; color: #18181b; margin: 0; }
    main { max-width: 560px; margin: 8vh auto; background: white; padding: 32px; border-radius: 16px; box-shadow: 0 20px 50px rgba(0,0,0,.08); }
    h1 { margin-top: 0; }
    p { line-height: 1.5; }
    code { background: #f4f4f5; padding: 2px 6px; border-radius: 6px; }
    label { display: grid; gap: 8px; margin: 20px 0; font-weight: 600; }
    input { font: inherit; padding: 12px; border: 1px solid #d4d4d8; border-radius: 10px; }
    button { border: 0; border-radius: 10px; padding: 12px 16px; font: inherit; font-weight: 700; cursor: pointer; }
    .primary { background: #2563eb; color: white; }
    .secondary { background: #e4e4e7; color: #18181b; margin-left: 8px; }
    .error { color: #b91c1c; background: #fee2e2; padding: 12px; border-radius: 10px; }
    .ok { color: #166534; background: #dcfce7; padding: 12px; border-radius: 10px; }
    .meta { color: #52525b; font-size: 14px; overflow-wrap: anywhere; }
  </style>
</head>
<body>
  <main>
    <h1>${title}</h1>
    ${error}
    <p><strong>${htmlEscape(clientLabel)}</strong> is requesting access to your hosted Workflowy MCP server.</p>
    <p>This will let the client call MCP tools through this server. Your Workflowy API key remains server-side and is not shared with the client.</p>
    <p class="meta">Resource: <code>${htmlEscape(params.resource)}</code></p>
    <form method="post">
      ${hiddenFields}
      ${adminSecretField}
      <button class="primary" type="submit" name="decision" value="approve">Approve</button>
      <button class="secondary" type="submit" name="decision" value="deny">Deny</button>
    </form>
  </main>
</body>
</html>`,
    { headers: { "Content-Type": "text/html; charset=utf-8" } },
  );
}

function redirectWithError(redirectUri: string, error: string, state: string): NextResponse {
  const redirect = new URL(redirectUri);
  redirect.searchParams.set("error", error);
  if (state) {
    redirect.searchParams.set("state", state);
  }
    return NextResponse.redirect(redirect, 303);
}

async function validateParams(params: AuthorizationParams, requestUrl: string): Promise<{ ok: true; clientName?: string } | { ok: false; error: string }> {
  if (params.responseType !== "code") {
    return { ok: false, error: "response_type must be code" };
  }
  if (!params.clientId) {
    return { ok: false, error: "client_id is required" };
  }
  if (!params.redirectUri) {
    return { ok: false, error: "redirect_uri is required" };
  }
  if (!params.codeChallenge || params.codeChallengeMethod.toUpperCase() !== "S256") {
    return { ok: false, error: "PKCE S256 is required" };
  }
  if (!isAllowedResource(params.resource, requestUrl)) {
    return { ok: false, error: `resource must be ${getMcpResource(requestUrl)}` };
  }
  if (!includesWorkflowyScope(params.scope)) {
    return { ok: false, error: "scope must include workflowy" };
  }

  const client = await getOAuthClient(params.clientId);
  if (!client) {
    return { ok: false, error: "Unknown OAuth client" };
  }
  if (!redirectUriMatches(client, params.redirectUri)) {
    return { ok: false, error: "redirect_uri does not match registered client" };
  }

  return { ok: true, clientName: client.client_name ?? undefined };
}

export async function GET(request: NextRequest): Promise<Response> {
  const params = readParams(request.nextUrl.searchParams, request.url);
  const validation = await validateParams(params, request.url);
  return formPage(params, {
    authenticated: isAdminAuthenticated(request),
    error: validation.ok ? undefined : validation.error,
    clientName: validation.ok ? validation.clientName : undefined,
  });
}

export async function POST(request: NextRequest): Promise<Response> {
  const form = await request.formData();
  const searchParams = new URLSearchParams();
  for (const key of [
    "responseType",
    "clientId",
    "redirectUri",
    "scope",
    "state",
    "codeChallenge",
    "codeChallengeMethod",
    "resource",
  ]) {
    const value = form.get(key);
    if (typeof value === "string") {
      searchParams.set(
        key
          .replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)
          .replace(/^_/, ""),
        value,
      );
    }
  }

  const params = readParams(searchParams, request.url);
  const validation = await validateParams(params, request.url);
  if (!validation.ok) {
    return formPage(params, { authenticated: isAdminAuthenticated(request), error: validation.error });
  }

  const decision = form.get("decision");
  if (decision !== "approve") {
    return redirectWithError(params.redirectUri, "access_denied", params.state);
  }

  const authenticated = isAdminAuthenticated(request);
  const adminSecret = form.get("admin_secret");
  if (!authenticated && (typeof adminSecret !== "string" || !adminSecretMatches(adminSecret))) {
    return formPage(params, {
      authenticated: false,
      error: "Invalid ADMIN_SECRET",
      clientName: validation.clientName,
    });
  }

  const code = await createAuthorizationCode({
    clientId: params.clientId,
    redirectUri: params.redirectUri,
    codeChallenge: params.codeChallenge,
    codeChallengeMethod: "S256",
    resource: params.resource,
    scope: params.scope,
  });

  const redirect = new URL(params.redirectUri);
  redirect.searchParams.set("code", code);
  if (params.state) {
    redirect.searchParams.set("state", params.state);
  }

   const response = NextResponse.redirect(redirect, 303);
  if (!authenticated) {
    setAdminSessionCookie(response);
  }
  return response;
}
