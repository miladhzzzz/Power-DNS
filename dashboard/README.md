# Power-DNS Control Plane

Same dashboard as the live preview (glass chrome, multi-instance, proxy). Packaged as Next.js so the original **Dockerfile** works.

Unzip and build from **this folder** (Dockerfile sits next to `package.json`).

## Docker

```bash
cd power-dns-dashboard
docker build -t power-dns-dashboard .
docker run --rm -p 3000:3000 power-dns-dashboard
```

Rebuild the image after replacing files — an old container will not match the preview.

Then open the app and add your Power-DNS instance (URL + optional token).

Standalone output: `node server.js` on port 3000.

## Local (no Docker)

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

## Notes

- Browser traffic goes through `/api/proxy/*` so Power-DNS does not need CORS.
