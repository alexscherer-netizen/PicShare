# PicShare — Setup

Picdrop-ähnliche Kunden-Galerie-App. Thumbnails in Supabase, Originale auf HiDrive.
Supabase-Projekt: **Mastermind** (`ugitunttmvswyxmyhnjb`).

---

## 1. Edge Function deployen

Lege `supabase/functions/picshare/index.ts` in dein Supabase-Repo (Datei liegt bei).

```bash
# Secrets setzen (HiDrive-Zugangsdaten + JWT-Secret)
supabase secrets set PICSHARE_JWT_SECRET="$(openssl rand -hex 32)"
supabase secrets set HIDRIVE_USER="alexanderglauche080388"      # dein HiDrive-Login
supabase secrets set HIDRIVE_PASS="DEIN_HIDRIVE_PASSWORT"        # oder App-Token
supabase secrets set HIDRIVE_BASE="https://webdav.hidrive.ionos.com"

# Function deployen (eigene HMAC-Tokens -> kein JWT-Verify)
supabase functions deploy picshare --no-verify-jwt --project-ref ugitunttmvswyxmyhnjb
```

> `SUPABASE_URL` und `SUPABASE_SERVICE_ROLE_KEY` sind in Edge Functions automatisch verfügbar — nicht setzen.

---

## 2. Frontend deployen

`index.html` ist eine Single-File-App → auf GitHub Pages oder IONOS hochladen.
Die Function-URL ist bereits in `CONFIG.FN_URL` eingetragen.

---

## 3. Login

**Admin** (Root-URL): Benutzer `alex`, Passwort `PicShare2026!`
→ **Bitte sofort ändern** (siehe unten).

**Kunde**: `…/index.html?g=<GALERIE_ID>` + PIN. Den Link erzeugt der „Kunden-Link"-Button.

---

## Passwort ändern

```sql
update picshare_admin
set password_hash = encode(digest('NEUES_PASSWORT' || ':' || id::text, 'sha256'), 'hex')
where username = 'alex';
```

---

## Datenmodell

- `picshare_galleries` — Galerien (PIN-Hash, HiDrive-Pfad, Limit, Flags, Bestätigung)
- `picshare_images` — Bilder (HiDrive-Pfad + Thumbnail-Pfad, `favorited`)
- `picshare_comments` — Kundenkommentare pro Bild
- `picshare_admin` — Admin-Accounts
- Storage-Bucket `picshare-thumbs` — Vorschaubilder (public read, write nur service_role)

RLS ist auf allen Tabellen aktiv ohne public policies → Zugriff ausschließlich über die Edge Function.

---

## Workflow

1. **Galerie anlegen** → Titel, PIN, HiDrive-Ordner, optional Auswahl-Limit.
2. **Bilder rein** — entweder per **Upload** (App verkleinert → Thumbnail nach Supabase, Original per WebDAV nach HiDrive) oder **„HiDrive einlesen"** (liest vorhandene Bilder im Ordner, lädt Originale durch und erzeugt Thumbnails).
3. **Kunden-Link + PIN** an den Kunden geben.
4. Kunde wählt Favoriten, kommentiert, lädt ggf. herunter, **bestätigt**.
5. Im Admin-Detail: Auswahl & Kommentare ansehen, **Auswahl exportieren** (Dateinamenliste als .txt). Bestätigung erscheint als Badge im Dashboard.

## Logo-Wasserzeichen

Im Admin oben rechts „Logo" → Bild-URL oder Datei. Wird lokal (localStorage) gespeichert und über Vorschaubilder gelegt. Pro Galerie an/abschaltbar.
