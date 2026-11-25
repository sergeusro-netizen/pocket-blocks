// Pocket Blocks leaderboard API (Cloudflare Worker + D1)
//
// POST /api/login        { name, pin }                 -> sign in, or create the player if the name is new
// POST /api/score        { token, score, level, lines } -> record a finished game
// GET  /api/me           Authorization: Bearer <token>  -> the player's bests
// GET  /api/leaderboard  ?limit=10                      -> top players by best score

const ALLOWED_ORIGINS = [
  "https://sergeusro-netizen.github.io",
  "https://games.herman.company",
];
const PBKDF2_ITERATIONS = 100000;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) || /^http:\/\/localhost(:\d+)?$/.test(origin);
  return {
    "Access-Control-Allow-Origin": allowed ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function json(request, status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(request) },
  });
}

const enc = new TextEncoder();

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function hashPin(pin, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return toHex(bits);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function makeToken(env, nameKey) {
  const key = await hmacKey(env.TOKEN_SECRET);
  const sig = toHex(await crypto.subtle.sign("HMAC", key, enc.encode(nameKey)));
  return btoa(nameKey) + "." + sig;
}

async function readToken(env, token) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [b64, sig] = token.split(".");
  let nameKey;
  try { nameKey = atob(b64); } catch { return null; }
  const expected = await makeToken(env, nameKey);
  return safeEqual(expected, token) && sig ? nameKey : null;
}

function cleanName(raw) {
  if (typeof raw !== "string") return null;
  const name = raw.trim().replace(/\s+/g, " ");
  if (!/^[A-Za-z0-9 _.-]{2,16}$/.test(name)) return null;
  return name;
}

function publicPlayer(p) {
  return {
    name: p.name,
    best_score: p.best_score,
    best_level: p.best_level,
    best_lines: p.best_lines,
    games: p.games,
  };
}

async function rankOf(env, score) {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM players WHERE best_score > ?").bind(score).first();
  return (row ? row.n : 0) + 1;
}

async function login(request, env) {
  const body = await request.json().catch(() => ({}));
  const name = cleanName(body.name);
  const pin = typeof body.pin === "string" ? body.pin : "";
  if (!name) return json(request, 400, { error: "Names are 2 to 16 letters, numbers, spaces, dots, dashes or underscores." });
  if (!/^\d{4}$/.test(pin)) return json(request, 400, { error: "The PIN must be exactly 4 digits." });

  const nameKey = name.toLowerCase();
  const now = Date.now();
  const existing = await env.DB.prepare("SELECT * FROM players WHERE name_key = ?").bind(nameKey).first();

  if (!existing) {
    const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
    const pinHash = await hashPin(pin, salt);
    await env.DB.prepare(
      "INSERT INTO players (name_key, name, pin_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(nameKey, name, pinHash, salt, now).run();
    const player = { name, best_score: 0, best_level: 0, best_lines: 0, games: 0 };
    return json(request, 200, { created: true, token: await makeToken(env, nameKey), player });
  }

  if (existing.locked_until > now) {
    const mins = Math.ceil((existing.locked_until - now) / 60000);
    return json(request, 429, { error: `Too many wrong PINs. Try again in ${mins} minute${mins === 1 ? "" : "s"}.` });
  }

  const pinHash = await hashPin(pin, existing.salt);
  if (!safeEqual(pinHash, existing.pin_hash)) {
    const fails = existing.fails + 1;
    const lockedUntil = fails >= MAX_FAILS ? now + LOCK_MS : 0;
    await env.DB.prepare("UPDATE players SET fails = ?, locked_until = ? WHERE name_key = ?")
      .bind(fails >= MAX_FAILS ? 0 : fails, lockedUntil, nameKey).run();
    return json(request, 401, {
      error: fails >= MAX_FAILS
        ? "Too many wrong PINs. Try again in 15 minutes."
        : `That name is taken and the PIN doesn't match. ${MAX_FAILS - fails} tries left.`,
    });
  }

  if (existing.fails) {
    await env.DB.prepare("UPDATE players SET fails = 0 WHERE name_key = ?").bind(nameKey).run();
  }
  return json(request, 200, { created: false, token: await makeToken(env, nameKey), player: publicPlayer(existing) });
}

async function submitScore(request, env) {
  const body = await request.json().catch(() => ({}));
  const nameKey = await readToken(env, body.token);
  if (!nameKey) return json(request, 401, { error: "Sign in again to save scores." });

  const score = Math.floor(Number(body.score));
  const level = Math.floor(Number(body.level));
  const lines = Math.floor(Number(body.lines));
  const valid = (n, max) => Number.isFinite(n) && n >= 0 && n <= max;
  if (!valid(score, 99999999) || !valid(level, 999) || !valid(lines, 99999)) {
    return json(request, 400, { error: "That score doesn't look valid." });
  }

  const now = Date.now();
  const before = await env.DB.prepare("SELECT * FROM players WHERE name_key = ?").bind(nameKey).first();
  if (!before) return json(request, 401, { error: "Sign in again to save scores." });

  await env.DB.batch([
    env.DB.prepare("INSERT INTO scores (name_key, score, level, lines, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(nameKey, score, level, lines, now),
    env.DB.prepare(
      "UPDATE players SET games = games + 1, best_score = MAX(best_score, ?), best_level = MAX(best_level, ?), best_lines = MAX(best_lines, ?) WHERE name_key = ?"
    ).bind(score, level, lines, nameKey),
  ]);

  const after = await env.DB.prepare("SELECT * FROM players WHERE name_key = ?").bind(nameKey).first();
  return json(request, 200, {
    player: publicPlayer(after),
    new_best: score > before.best_score,
    rank: await rankOf(env, after.best_score),
  });
}

async function me(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const nameKey = await readToken(env, auth.replace(/^Bearer\s+/i, ""));
  if (!nameKey) return json(request, 401, { error: "Sign in again." });
  const p = await env.DB.prepare("SELECT * FROM players WHERE name_key = ?").bind(nameKey).first();
  if (!p) return json(request, 401, { error: "Sign in again." });
  return json(request, 200, { player: publicPlayer(p), rank: p.best_score > 0 ? await rankOf(env, p.best_score) : null });
}

async function leaderboard(request, env, url) {
  const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get("limit") || "10", 10) || 10));
  const { results } = await env.DB.prepare(
    "SELECT name, best_score, best_level, best_lines, games FROM players WHERE best_score > 0 ORDER BY best_score DESC, created_at ASC LIMIT ?"
  ).bind(limit).all();
  return json(request, 200, { players: results });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/login" && request.method === "POST") return await login(request, env);
      if (url.pathname === "/api/score" && request.method === "POST") return await submitScore(request, env);
      if (url.pathname === "/api/me" && request.method === "GET") return await me(request, env);
      if (url.pathname === "/api/leaderboard" && request.method === "GET") return await leaderboard(request, env, url);
      return json(request, 404, { error: "Not found" });
    } catch (err) {
      return json(request, 500, { error: "Something went wrong on the server. Try again." });
    }
  },
};
