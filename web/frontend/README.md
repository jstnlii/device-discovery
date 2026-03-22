# Device Discovery — Frontend

React + TypeScript + Vite UI for Device Discovery. Lets you start scans, see progress, cancel mid-scan, and view device inventory in a table.

---

## Setup (first time)

From the repo root:

```bash
cd web/frontend
npm install
```

---

## Run (development)

From `web/frontend/`:

```bash
npm run dev
```

Then open **http://localhost:5173** (Vite’s default port).

**Requires the backend** to be running on port 8008. The Vite dev server proxies `/api` requests to `http://localhost:8008`.

---

## Build (production)

```bash
npm run build
```

Output goes to `dist/`. Serve with any static file server, or run `npm run preview` to test the production build locally.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `npm run dev` | Start dev server (HMR) |
| `npm run build` | TypeScript check + Vite build |
| `npm run preview` | Serve production build locally |
| `npm run lint` | Run ESLint |

---

## Proxy

The dev server proxies `/api` to the backend. Ensure `vite.config.ts` has:

```ts
proxy: { "/api": { target: "http://localhost:8008", changeOrigin: true } }
```

If the backend runs on a different port, update the `target` accordingly.
