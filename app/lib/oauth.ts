import { createHash, randomBytes, timingSafeEqual } from "crypto";
import { neon, type NeonQueryFunction } from "@neondatabase/serverless";

export type SqlClient = NeonQueryFunction<false, false>;

export interface OAuthClientRecord {
  client_id: string;
  client_name: string | null;
  redirect_uris: string[];
  scope: string | null;
}

export interface OAuthTokenAuthInfo {
  clientId: string;
  scopes: string[];
  resource: string;
}

const ACCESS_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 365 * 10;
const AUTH_CODE_TTL_SECONDS = 10 * 60;
const DEFAULT_SCOPE = "workflowy";

let dbPromise: Promise<SqlClient> | undefined;

export async function getOAuthDb(): Promise<SqlClient> {
  if (dbPromise) {
    return dbPromise;
  }

  dbPromise = (async () => {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error("DATABASE_URL is not set in process.env");
    }

    const sql = neon(databaseUrl);
    await sql`
      CREATE TABLE IF NOT EXISTS workflowy_oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_name TEXT,
        redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
        grant_types JSONB NOT NULL DEFAULT '["authorization_code"]'::jsonb,
        response_types JSONB NOT NULL DEFAULT '["code"]'::jsonb,
        scope TEXT NOT NULL DEFAULT 'workflowy',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS workflowy_oauth_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES workflowy_oauth_clients(client_id) ON DELETE CASCADE,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        code_challenge_method TEXT NOT NULL,
        resource TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT 'workflowy',
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS workflowy_oauth_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES workflowy_oauth_clients(client_id) ON DELETE CASCADE,
        resource TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT 'workflowy',
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE INDEX IF NOT EXISTS idx_workflowy_oauth_codes_client
      ON workflowy_oauth_codes (client_id, expires_at)
    `;
    await sql`
      CREATE INDEX IF NOT EXISTS idx_workflowy_oauth_tokens_client
      ON workflowy_oauth_tokens (client_id, expires_at)
    `;

    return sql;
  })();

  return dbPromise;
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function getIssuer(requestUrl: string): string {
  return new URL(requestUrl).origin;
}

export function getMcpResource(requestUrl: string): string {
  return `${getIssuer(requestUrl)}/api/mcp`;
}

export function normalizeResource(resource: string): string | null {
  try {
    const parsed = new URL(resource);
    parsed.hash = "";
    parsed.search = "";
    const normalized = parsed.toString();
    return normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
  } catch {
    return null;
  }
}

export function isAllowedResource(resource: string, requestUrl: string): boolean {
  const normalized = normalizeResource(resource);
  if (!normalized) {
    return false;
  }

  const issuer = getIssuer(requestUrl);
  const mcpResource = getMcpResource(requestUrl);
  return normalized === normalizeResource(issuer) || normalized === normalizeResource(mcpResource);
}

export function getRequestedResource(value: string | null, requestUrl: string): string {
  const fallback = getMcpResource(requestUrl);
  if (!value) {
    return fallback;
  }
  return normalizeResource(value) ?? fallback;
}

export function splitScope(scope: string | null | undefined): string[] {
  return (scope || DEFAULT_SCOPE)
    .split(/\s+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function includesWorkflowyScope(scope: string | null | undefined): boolean {
  return splitScope(scope).includes(DEFAULT_SCOPE);
}

export function pkceS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function timingSafeStringEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }
  return timingSafeEqual(aBuffer, bBuffer);
}

export function verifyPkceS256(verifier: string, challenge: string): boolean {
  return timingSafeStringEqual(pkceS256(verifier), challenge);
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string");
}

export async function registerOAuthClient(input: {
  clientName?: string;
  redirectUris: string[];
  grantTypes?: string[];
  responseTypes?: string[];
  scope?: string;
}): Promise<OAuthClientRecord> {
  const sql = await getOAuthDb();
  const clientId = `wf_${randomToken(24)}`;
  const grantTypes = input.grantTypes?.length ? input.grantTypes : ["authorization_code"];
  const responseTypes = input.responseTypes?.length ? input.responseTypes : ["code"];
  const scope = input.scope?.trim() || DEFAULT_SCOPE;

  await sql`
    INSERT INTO workflowy_oauth_clients (
      client_id,
      client_name,
      redirect_uris,
      grant_types,
      response_types,
      scope
    ) VALUES (
      ${clientId},
      ${input.clientName ?? null},
      ${JSON.stringify(input.redirectUris)}::jsonb,
      ${JSON.stringify(grantTypes)}::jsonb,
      ${JSON.stringify(responseTypes)}::jsonb,
      ${scope}
    )
  `;

  return {
    client_id: clientId,
    client_name: input.clientName ?? null,
    redirect_uris: input.redirectUris,
    scope,
  };
}

export async function getOAuthClient(clientId: string): Promise<OAuthClientRecord | null> {
  const sql = await getOAuthDb();
  const rows = await sql`
    SELECT client_id, client_name, redirect_uris, scope
    FROM workflowy_oauth_clients
    WHERE client_id = ${clientId}
    LIMIT 1
  `;

  const row = rows[0] as Record<string, unknown> | undefined;
  if (!row) {
    return null;
  }

  return {
    client_id: String(row.client_id),
    client_name: typeof row.client_name === "string" ? row.client_name : null,
    redirect_uris: asStringArray(row.redirect_uris),
    scope: typeof row.scope === "string" ? row.scope : DEFAULT_SCOPE,
  };
}

export function redirectUriMatches(client: OAuthClientRecord, redirectUri: string): boolean {
  return client.redirect_uris.includes(redirectUri);
}

export async function createAuthorizationCode(input: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  resource: string;
  scope?: string;
}): Promise<string> {
  const sql = await getOAuthDb();
  const code = randomToken(32);
  const codeHash = hashToken(code);
  const scope = input.scope?.trim() || DEFAULT_SCOPE;

  await sql`
    INSERT INTO workflowy_oauth_codes (
      code_hash,
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      resource,
      scope,
      expires_at
    ) VALUES (
      ${codeHash},
      ${input.clientId},
      ${input.redirectUri},
      ${input.codeChallenge},
      ${input.codeChallengeMethod},
      ${input.resource},
      ${scope},
      NOW() + (${AUTH_CODE_TTL_SECONDS} || ' seconds')::interval
    )
  `;

  return code;
}

export async function exchangeAuthorizationCode(input: {
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
  resource: string;
}): Promise<{ accessToken: string; expiresIn: number; scope: string } | null> {
  const sql = await getOAuthDb();
  const codeHash = hashToken(input.code);
  const rows = await sql`
    SELECT code_hash, client_id, redirect_uri, code_challenge, code_challenge_method, resource, scope, expires_at, used_at
    FROM workflowy_oauth_codes
    WHERE code_hash = ${codeHash}
    LIMIT 1
  `;

  const codeRow = rows[0] as Record<string, unknown> | undefined;
  if (!codeRow) {
    return null;
  }

  if (
    codeRow.used_at ||
    String(codeRow.client_id) !== input.clientId ||
    String(codeRow.redirect_uri) !== input.redirectUri ||
    String(codeRow.resource) !== input.resource ||
    new Date(String(codeRow.expires_at)).getTime() <= Date.now() ||
    String(codeRow.code_challenge_method).toUpperCase() !== "S256" ||
    !verifyPkceS256(input.codeVerifier, String(codeRow.code_challenge))
  ) {
    return null;
  }

  await sql`
    UPDATE workflowy_oauth_codes
    SET used_at = NOW()
    WHERE code_hash = ${codeHash} AND used_at IS NULL
  `;

  const accessToken = `wft_${randomToken(32)}`;
  const tokenHash = hashToken(accessToken);
  const scope = String(codeRow.scope || DEFAULT_SCOPE);

  await sql`
    INSERT INTO workflowy_oauth_tokens (
      token_hash,
      client_id,
      resource,
      scope,
      expires_at
    ) VALUES (
      ${tokenHash},
      ${input.clientId},
      ${input.resource},
      ${scope},
      NOW() + (${ACCESS_TOKEN_TTL_SECONDS} || ' seconds')::interval
    )
  `;

  return {
    accessToken,
    expiresIn: ACCESS_TOKEN_TTL_SECONDS,
    scope,
  };
}

export async function validateOAuthAccessToken(
  accessToken: string,
  requestUrl: string,
): Promise<OAuthTokenAuthInfo | null> {
  if (!accessToken.startsWith("wft_")) {
    return null;
  }

  const sql = await getOAuthDb();
  const tokenHash = hashToken(accessToken);
  const rows = await sql`
    SELECT client_id, resource, scope, expires_at, revoked_at
    FROM workflowy_oauth_tokens
    WHERE token_hash = ${tokenHash}
    LIMIT 1
  `;

  const row = rows[0] as Record<string, unknown> | undefined;
  if (!row) {
    return null;
  }

  const resource = String(row.resource);
  if (
    row.revoked_at ||
    new Date(String(row.expires_at)).getTime() <= Date.now() ||
    !isAllowedResource(resource, requestUrl) ||
    !includesWorkflowyScope(String(row.scope || DEFAULT_SCOPE))
  ) {
    return null;
  }

  return {
    clientId: String(row.client_id),
    scopes: splitScope(String(row.scope || DEFAULT_SCOPE)),
    resource,
  };
}
