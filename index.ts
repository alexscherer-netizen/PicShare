// PicShare Edge Function
// Backend für Picdrop-ähnliche Kunden-Galerie-App.
// - Admin-Login via HMAC-Token (Pattern wie Dateiablage)
// - Galerie-CRUD, Bild-Upload (App -> HiDrive), HiDrive-Ordner einlesen
// - PIN-geschützter Kundenzugang pro Galerie
// - Favoriten, Kommentare, Auswahl-Limit, Bestätigung
// - HiDrive WebDAV-Proxy für Original-Download (streamt durch)
//
// Secrets (via CLI setzen):
//   supabase secrets set PICSHARE_JWT_SECRET=...      (für HMAC-Tokens)
//   supabase secrets set HIDRIVE_USER=...             (WebDAV Benutzer)
//   supabase secrets set HIDRIVE_PASS=...             (WebDAV Passwort/App-Token)
//   supabase secrets set HIDRIVE_BASE=https://webdav.hidrive.ionos.com
//   SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY sind automatisch verfügbar
//
// deploy:  supabase functions deploy picshare --no-verify-jwt
//   (verify_jwt:false, da wir eigene HMAC-Tokens nutzen)

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const JWT_SECRET = Deno.env.get("PICSHARE_JWT_SECRET") || "change-me";
const HIDRIVE_USER = Deno.env.get("HIDRIVE_USER") || "";
const HIDRIVE_PASS = Deno.env.get("HIDRIVE_PASS") || "";
const HIDRIVE_BASE = (Deno.env.get("HIDRIVE_BASE") || "https://webdav.hidrive.ionos.com").replace(/\/+$/, "");

const db = createClient(SUPABASE_URL, SERVICE_KEY);

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, x-picshare-pin",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
};

// ---------- Krypto-Helfer ----------
const enc = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hmacKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", enc.encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function signToken(payload: Record<string, unknown>): Promise<string> {
  const body = b64url(enc.encode(JSON.stringify({ ...payload, exp: Date.now() + 1000 * 60 * 60 * 12 })));
  const key = await hmacKey();
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(body)));
  return `${body}.${b64url(sig)}`;
}
async function verifyToken(token: string | null): Promise<Record<string, unknown> | null> {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const key = await hmacKey();
  const ok = await crypto.subtle.verify("HMAC", key, b64urlToBytes(sig), enc.encode(body));
  if (!ok) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(body)));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------- HiDrive WebDAV ----------
function davHeaders(extra: Record<string, string> = {}): HeadersInit {
  const auth = "Basic " + btoa(`${HIDRIVE_USER}:${HIDRIVE_PASS}`);
  return { Authorization: auth, ...extra };
}
function davUrl(path: string): string {
  const clean = "/" + path.split("/").filter(Boolean).map(encodeURIComponent).join("/");
  return HIDRIVE_BASE + clean;
}
// PROPFIND -> Liste der Dateien in einem Ordner
async function davList(path: string): Promise<{ name: string; path: string; isDir: boolean }[]> {
  const res = await fetch(davUrl(path), {
    method: "PROPFIND",
    headers: davHeaders({ Depth: "1", "Content-Type": "application/xml" }),
    body: `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:displayname/></d:prop></d:propfind>`,
  });
  if (!res.ok) throw new Error(`PROPFIND ${res.status}`);
  const xml = await res.text();
  const items: { name: string; path: string; isDir: boolean }[] = [];
  const responses = xml.split(/<\/?d:response>/i).filter((s) => /<d:href/i.test(s));
  for (const r of responses) {
    const href = (r.match(/<d:href>([^<]+)<\/d:href>/i) || [])[1];
    if (!href) continue;
    const decoded = decodeURIComponent(href);
    const isDir = /<d:collection\s*\/?>/i.test(r);
    const name = decoded.replace(/\/+$/, "").split("/").pop() || "";
    if (!name) continue;
    items.push({ name, path: decoded, isDir });
  }
  return items;
}

// ---------- Response-Helfer ----------
function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { ...CORS, "Content-Type": "application/json" } });
}
function err(msg: string, status = 400): Response {
  return json({ error: msg }, status);
}

// ---------- Handler ----------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  const url = new URL(req.url);
  const action = url.searchParams.get("action") || "";

  try {
    // ===== Öffentlicher Download-Proxy (GET) =====
    // /picshare?action=download&token=<dl-token>
    if (action === "download" && req.method === "GET") {
      const dlToken = url.searchParams.get("token");
      const payload = await verifyToken(dlToken);
      if (!payload || payload.kind !== "dl") return err("invalid token", 403);
      const filePath = String(payload.path);
      const davRes = await fetch(davUrl(filePath), { headers: davHeaders() });
      if (!davRes.ok || !davRes.body) return err("hidrive fetch failed", 502);
      const fname = filePath.split("/").pop() || "download";
      return new Response(davRes.body, {
        headers: {
          ...CORS,
          "Content-Type": davRes.headers.get("Content-Type") || "application/octet-stream",
          "Content-Disposition": `attachment; filename="${fname}"`,
        },
      });
    }

    if (req.method !== "POST") return err("method not allowed", 405);
    const bodyIn = await req.json().catch(() => ({}));

    // ===== ADMIN-Bereich =====
    if (action === "admin_login") {
      const { username, password } = bodyIn;
      const { data: admin } = await db.from("picshare_admin").select("*").eq("username", username).maybeSingle();
      if (!admin) return err("invalid credentials", 401);
      const hash = await sha256Hex(`${password}:${admin.id}`);
      if (hash !== admin.password_hash) return err("invalid credentials", 401);
      const token = await signToken({ kind: "admin", sub: admin.id });
      return json({ token });
    }

    const authHeader = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || null;

    async function requireAdmin() {
      const p = await verifyToken(authHeader);
      if (!p || p.kind !== "admin") throw new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { ...CORS, "Content-Type": "application/json" } });
      return p;
    }

    // ---- Galerie anlegen ----
    if (action === "admin_create_gallery") {
      await requireAdmin();
      const { title, client_name, pin, hidrive_path, selection_limit, watermark_enabled, download_enabled } = bodyIn;
      if (!title || !pin || !hidrive_path) return err("title, pin, hidrive_path required");
      const pin_hash = await sha256Hex(`pin:${pin}`);
      const { data, error } = await db.from("picshare_galleries").insert({
        title, client_name: client_name || null, pin_hash, hidrive_path,
        selection_limit: selection_limit ?? null,
        watermark_enabled: watermark_enabled ?? true,
        download_enabled: download_enabled ?? true,
      }).select().single();
      if (error) return err(error.message, 500);
      return json({ gallery: data });
    }

    // ---- Galerien auflisten ----
    if (action === "admin_list_galleries") {
      await requireAdmin();
      const { data } = await db.from("picshare_galleries")
        .select("*, picshare_images(count), picshare_images!inner(favorited)")
        .order("created_at", { ascending: false });
      // separate Zählung sauberer:
      const { data: galleries } = await db.from("picshare_galleries").select("*").order("created_at", { ascending: false });
      const enriched = [];
      for (const g of galleries || []) {
        const { count: total } = await db.from("picshare_images").select("*", { count: "exact", head: true }).eq("gallery_id", g.id);
        const { count: favs } = await db.from("picshare_images").select("*", { count: "exact", head: true }).eq("gallery_id", g.id).eq("favorited", true);
        enriched.push({ ...g, image_count: total || 0, favorite_count: favs || 0 });
      }
      return json({ galleries: enriched });
    }

    // ---- Galerie-Detail (Admin) ----
    if (action === "admin_gallery_detail") {
      await requireAdmin();
      const { gallery_id } = bodyIn;
      const { data: gallery } = await db.from("picshare_galleries").select("*").eq("id", gallery_id).maybeSingle();
      if (!gallery) return err("not found", 404);
      const { data: images } = await db.from("picshare_images").select("*").eq("gallery_id", gallery_id).order("sort_order");
      const { data: comments } = await db.from("picshare_comments").select("*").eq("gallery_id", gallery_id).order("created_at");
      return json({ gallery, images, comments });
    }

    // ---- HiDrive-Ordner einlesen (Bilder importieren, ohne hochzuladen) ----
    if (action === "admin_import_hidrive") {
      await requireAdmin();
      const { gallery_id } = bodyIn;
      const { data: gallery } = await db.from("picshare_galleries").select("*").eq("id", gallery_id).maybeSingle();
      if (!gallery) return err("gallery not found", 404);
      const files = await davList(gallery.hidrive_path);
      const imgFiles = files.filter((f) => !f.isDir && /\.(jpe?g|png|webp|gif|tiff?)$/i.test(f.name));
      let added = 0;
      for (let i = 0; i < imgFiles.length; i++) {
        const f = imgFiles[i];
        const fullPath = `${gallery.hidrive_path.replace(/\/+$/, "")}/${f.name}`;
        const { data: exists } = await db.from("picshare_images").select("id").eq("gallery_id", gallery_id).eq("filename", f.name).maybeSingle();
        if (exists) continue;
        await db.from("picshare_images").insert({
          gallery_id, filename: f.name, hidrive_file_path: fullPath, sort_order: i,
        });
        added++;
      }
      return json({ added, total: imgFiles.length, note: "Thumbnails werden beim ersten Aufruf generiert oder per Upload mitgeliefert." });
    }

    // ---- Bild-Upload (App -> HiDrive + Thumbnail -> Supabase) ----
    if (action === "admin_upload_image") {
      await requireAdmin();
      const { gallery_id, filename, original_b64, thumb_b64, width, height } = bodyIn;
      const { data: gallery } = await db.from("picshare_galleries").select("*").eq("id", gallery_id).maybeSingle();
      if (!gallery) return err("gallery not found", 404);

      const fullPath = `${gallery.hidrive_path.replace(/\/+$/, "")}/${filename}`;
      // Original auf HiDrive (PUT)
      const origBytes = b64urlToBytes(original_b64.replace(/^data:[^,]+,/, "").replace(/\+/g, "-").replace(/\//g, "_"));
      const put = await fetch(davUrl(fullPath), { method: "PUT", headers: davHeaders(), body: origBytes });
      if (!put.ok && put.status !== 201 && put.status !== 204) return err(`hidrive PUT ${put.status}`, 502);

      // Thumbnail in Supabase Storage
      let thumb_path: string | null = null;
      if (thumb_b64) {
        const thumbBytes = b64urlToBytes(thumb_b64.replace(/^data:[^,]+,/, "").replace(/\+/g, "-").replace(/\//g, "_"));
        const key = `${gallery_id}/${crypto.randomUUID()}.webp`;
        const up = await db.storage.from("picshare-thumbs").upload(key, thumbBytes, { contentType: "image/webp", upsert: true });
        if (!up.error) thumb_path = key;
      }
      const { data: img, error } = await db.from("picshare_images").insert({
        gallery_id, filename, hidrive_file_path: fullPath, thumb_path, width: width || null, height: height || null,
      }).select().single();
      if (error) return err(error.message, 500);
      return json({ image: img });
    }

    // ---- Thumbnail nachliefern (für importierte Bilder) ----
    if (action === "admin_set_thumb") {
      await requireAdmin();
      const { image_id, thumb_b64, width, height } = bodyIn;
      const { data: img } = await db.from("picshare_images").select("*").eq("id", image_id).maybeSingle();
      if (!img) return err("image not found", 404);
      const thumbBytes = b64urlToBytes(thumb_b64.replace(/^data:[^,]+,/, "").replace(/\+/g, "-").replace(/\//g, "_"));
      const key = `${img.gallery_id}/${crypto.randomUUID()}.webp`;
      const up = await db.storage.from("picshare-thumbs").upload(key, thumbBytes, { contentType: "image/webp", upsert: true });
      if (up.error) return err(up.error.message, 500);
      await db.from("picshare_images").update({ thumb_path: key, width: width || null, height: height || null }).eq("id", image_id);
      return json({ thumb_path: key });
    }

    // ---- Original holen (Admin, für lokale Thumbnail-Generierung) ----
    if (action === "admin_fetch_original_url") {
      await requireAdmin();
      const { image_id } = bodyIn;
      const { data: img } = await db.from("picshare_images").select("*").eq("id", image_id).maybeSingle();
      if (!img) return err("not found", 404);
      const dl = await signToken({ kind: "dl", path: img.hidrive_file_path });
      return json({ url: `${SUPABASE_URL}/functions/v1/picshare?action=download&token=${encodeURIComponent(dl)}` });
    }

    // ---- Galerie löschen ----
    if (action === "admin_delete_gallery") {
      await requireAdmin();
      const { gallery_id } = bodyIn;
      await db.from("picshare_galleries").delete().eq("id", gallery_id);
      return json({ ok: true });
    }

    // ===== KUNDEN-Bereich (PIN-geschützt) =====

    // ---- Galerie-Login per PIN -> Galerie-Token ----
    if (action === "gallery_login") {
      const { gallery_id, pin } = bodyIn;
      const { data: gallery } = await db.from("picshare_galleries").select("*").eq("id", gallery_id).maybeSingle();
      if (!gallery) return err("not found", 404);
      const pin_hash = await sha256Hex(`pin:${pin}`);
      if (pin_hash !== gallery.pin_hash) return err("falsche PIN", 401);
      const token = await signToken({ kind: "gallery", gid: gallery.id });
      return json({ token, gallery: { id: gallery.id, title: gallery.title, client_name: gallery.client_name, selection_limit: gallery.selection_limit, watermark_enabled: gallery.watermark_enabled, download_enabled: gallery.download_enabled, confirmed: gallery.confirmed } });
    }

    async function requireGallery(gid: string) {
      const p = await verifyToken(authHeader);
      if (!p || p.kind !== "gallery" || p.gid !== gid) {
        throw new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { ...CORS, "Content-Type": "application/json" } });
      }
      return p;
    }

    // ---- Galerie-Inhalt für Kunde ----
    if (action === "gallery_view") {
      const { gallery_id } = bodyIn;
      await requireGallery(gallery_id);
      const { data: gallery } = await db.from("picshare_galleries").select("id,title,client_name,selection_limit,watermark_enabled,download_enabled,confirmed").eq("id", gallery_id).maybeSingle();
      const { data: images } = await db.from("picshare_images").select("id,filename,thumb_path,width,height,favorited,sort_order").eq("gallery_id", gallery_id).order("sort_order");
      const { data: comments } = await db.from("picshare_comments").select("*").eq("gallery_id", gallery_id).order("created_at");
      return json({ gallery, images, comments });
    }

    // ---- Favorit togglen ----
    if (action === "gallery_toggle_fav") {
      const { gallery_id, image_id } = bodyIn;
      await requireGallery(gallery_id);
      const { data: img } = await db.from("picshare_images").select("favorited").eq("id", image_id).eq("gallery_id", gallery_id).maybeSingle();
      if (!img) return err("not found", 404);
      // Limit prüfen
      if (!img.favorited) {
        const { data: gallery } = await db.from("picshare_galleries").select("selection_limit").eq("id", gallery_id).maybeSingle();
        if (gallery?.selection_limit) {
          const { count } = await db.from("picshare_images").select("*", { count: "exact", head: true }).eq("gallery_id", gallery_id).eq("favorited", true);
          if ((count || 0) >= gallery.selection_limit) return err(`Auswahl-Limit erreicht (${gallery.selection_limit})`, 409);
        }
      }
      const { data: updated } = await db.from("picshare_images").update({ favorited: !img.favorited }).eq("id", image_id).select("favorited").single();
      return json({ favorited: updated?.favorited });
    }

    // ---- Kommentar hinzufügen ----
    if (action === "gallery_comment") {
      const { gallery_id, image_id, body } = bodyIn;
      await requireGallery(gallery_id);
      if (!body?.trim()) return err("leerer Kommentar");
      const { data } = await db.from("picshare_comments").insert({ gallery_id, image_id, body: body.trim() }).select().single();
      return json({ comment: data });
    }

    // ---- Auswahl bestätigen ----
    if (action === "gallery_confirm") {
      const { gallery_id } = bodyIn;
      await requireGallery(gallery_id);
      await db.from("picshare_galleries").update({ confirmed: true, confirmed_at: new Date().toISOString() }).eq("id", gallery_id);
      return json({ ok: true });
    }

    // ---- Download-Link für ein Bild (Kunde) ----
    if (action === "gallery_download") {
      const { gallery_id, image_id } = bodyIn;
      await requireGallery(gallery_id);
      const { data: gallery } = await db.from("picshare_galleries").select("download_enabled").eq("id", gallery_id).maybeSingle();
      if (!gallery?.download_enabled) return err("Download deaktiviert", 403);
      const { data: img } = await db.from("picshare_images").select("hidrive_file_path").eq("id", image_id).eq("gallery_id", gallery_id).maybeSingle();
      if (!img) return err("not found", 404);
      const dl = await signToken({ kind: "dl", path: img.hidrive_file_path });
      return json({ url: `${SUPABASE_URL}/functions/v1/picshare?action=download&token=${encodeURIComponent(dl)}` });
    }

    return err("unknown action", 404);
  } catch (e) {
    if (e instanceof Response) return e;
    return err(String(e?.message || e), 500);
  }
});
