// P7d (D58): consent for MCP clients asking to use vault-mcp. Order matters: sign in, then two-factor, and only then
// look at the request, list the client through mcp-approve (which demands two-factor), and approve it in Supabase Auth.
// Everything shown from the request is attacker-controllable, so it's set with textContent only.
const SUPABASE_URL = "https://lqskqqgqdhqgekesqygu.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imxxc2txcWdxZGhxZ2VrZXNxeWd1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTEwNzA1NjcsImV4cCI6MjEwNjY0NjU2N30.hSrGEXzmKYk716xzNQA7VbLhH8rEkkLjnqR2aV-lK08"; // Public by design; the vault isn't reachable through it.
const client = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: true, detectSessionInUrl: false } });
const authorizationId = new URLSearchParams(location.search).get("authorization_id");
const $ = (id) => document.getElementById(id);
let details = null;

function show(section) {
  for (const id of ["signin", "enroll", "mfa", "consent", "message"]) $(id).hidden = id !== section;
  $("error").textContent = "";
}
function fail(text) { $("error").textContent = text; for (const b of document.querySelectorAll("button")) b.disabled = false; }
function busy(button) { button.disabled = true; $("error").textContent = ""; }
function message(text) { $("message-text").textContent = text; show("message"); }

async function next() {
  if (!authorizationId) return message("Nothing to approve here. This page opens when you connect an AI app to the vault.");
  const { data: { session } } = await client.auth.getSession();
  if (!session) return show("signin");

  const { data: aal, error: aalError } = await client.auth.mfa.getAuthenticatorAssuranceLevel();
  if (aalError) return fail("Couldn't check two-factor status. Reload and try again.");
  if (aal.currentLevel !== "aal2") {
    const { data: factors } = await client.auth.mfa.listFactors();
    if (!factors || factors.totp.length === 0) return await startEnroll();
    return show("mfa");
  }

  const { data, error } = await client.auth.oauth.getAuthorizationDetails(authorizationId);
  if (error) return fail("This request has expired or isn't valid. Start connecting again from the AI app.");
  if (data.redirect_url && !data.authorization_id) { location.href = data.redirect_url; return; } // Approved before.
  details = data;
  $("client-name").textContent = data.client?.name || "An unnamed app";
  try { $("redirect-host").textContent = new URL(data.redirect_uri).host; } catch { $("redirect-host").textContent = "unknown"; }
  $("user-email").textContent = data.user?.email || "";
  show("consent");
}

async function startEnroll() {
  // Clear half-finished enrollments first, so a reload doesn't pile them up.
  const { data: factors } = await client.auth.mfa.listFactors();
  for (const f of factors?.all ?? []) if (f.status !== "verified") await client.auth.mfa.unenroll({ factorId: f.id });
  const { data, error } = await client.auth.mfa.enroll({ factorType: "totp", friendlyName: "Authenticator" });
  if (error) return fail("Couldn't start two-factor setup.");
  $("enroll").dataset.factorId = data.id;
  if (typeof data.totp.qr_code === "string" && data.totp.qr_code.startsWith("data:image/svg+xml")) $("qr").src = data.totp.qr_code;
  $("secret").textContent = data.totp.secret;
  show("enroll");
}

$("signin-button").onclick = async (e) => {
  busy(e.target);
  const { error } = await client.auth.signInWithPassword({ email: $("email").value.trim(), password: $("password").value });
  if (error) return fail("Sign-in failed. Check your email and password.");
  $("password").value = "";
  await next();
};

$("enroll-button").onclick = async (e) => {
  busy(e.target);
  const { error } = await client.auth.mfa.challengeAndVerify({ factorId: $("enroll").dataset.factorId, code: $("enroll-code").value.trim() });
  if (error) return fail("That code didn't work. Wait for the next one and try again.");
  await next();
};

$("mfa-button").onclick = async (e) => {
  busy(e.target);
  const { data: factors } = await client.auth.mfa.listFactors();
  const factor = factors?.totp?.[0];
  const { error } = await client.auth.mfa.challengeAndVerify({ factorId: factor?.id, code: $("mfa-code").value.trim() });
  if (error) return fail("That code didn't work. Wait for the next one and try again.");
  await next();
};

$("approve").onclick = async (e) => {
  busy(e.target);
  const { data: { session } } = await client.auth.getSession();
  const listed = await fetch(`${SUPABASE_URL}/functions/v1/mcp-approve`, {
    method: "POST",
    headers: { authorization: `Bearer ${session.access_token}`, "content-type": "application/json" },
    body: JSON.stringify({ client_id: details.client.id, client_name: details.client.name || "unnamed" }),
  }).catch(() => null);
  if (!listed || !listed.ok) return fail("Couldn't record the approval. Nothing was approved; try again.");
  const { error } = await client.auth.oauth.approveAuthorization(authorizationId); // Redirects back to the app.
  if (error) fail("Approval failed. Start connecting again from the AI app.");
};

$("deny").onclick = async (e) => {
  busy(e.target);
  const { error } = await client.auth.oauth.denyAuthorization(authorizationId); // Redirects back to the app.
  if (error) message("Denied.");
};

next().catch(() => fail("Something went wrong. Reload and try again."));
