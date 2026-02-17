# SOTH Dashboard

Real-time UI for SOTH sensor telemetry.

## Tech Stack

- Next.js 15 (App Router)
- TanStack Query
- Tailwind CSS v4
- Radix UI + shadcn/ui primitives
- Phosphor Icons

## Runtime Model

The dashboard uses two services:

- API service (Rust): `soth dev api start`
- UI service (Next.js): `soth dev ui start`

The sensor proxy is independent and can run with or without the dashboard.

## Quick Start (Current CLI)

1. Start sensor lifecycle:

```bash
soth up
```

2. Start API service (default `:3001`):

```bash
soth dev api start
```

3. Start UI dev service (default `:3002`):

```bash
soth dev ui start
```

4. Open `http://localhost:3002`

To stop sensor lifecycle:

```bash
soth down
```

## Endpoint Configuration

By default the UI uses same-origin `/api`, and local dev expects API on `localhost:3001`.

Override with `.env.local` when needed:

```bash
NEXT_PUBLIC_SOTH_API_BASE=http://localhost:3001/api
NEXT_PUBLIC_SOTH_WS_BASE=ws://localhost:3001
```

## UI Primitive Workflow

Add shadcn components:

```bash
npm run ui:add -- button
```

Generated components should live in `src/components/ui`.

## Minimal Config Example

```yaml
dashboard:
  enabled: true
  port: 3001

forward_proxy:
  enabled: true
  port: 8080
  hosts:
    mode: selective
    block: []
```

## Production Build

```bash
cd dashboard
npm run build
```

## API Endpoints Used by UI

- `GET /api/health`
- `GET /api/identity`
- `GET /api/policy`
- `GET /api/observe`
- `GET /api/budget`
- `GET /api/proxy`
- `GET /api/events`
- `GET /api/agents`
- `WS /api/events/stream`
