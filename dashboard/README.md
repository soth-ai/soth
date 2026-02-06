# SOTH Dashboard

Real-time metrics dashboard for the SOTH edge proxy.

## Tech Stack

- **Next.js 15** - React framework with App Router
- **TanStack Query** - Data fetching with auto-refresh
- **Tailwind CSS v4** - Styling
- **Radix UI** - Accessible primitives
- **shadcn/ui (configured)** - Canonical UI primitive workflow
- **Phosphor Icons** - Icon set

## Development

### UI Primitive Workflow (shadcn)

This dashboard is now configured for shadcn (`components.json`).

- Add a new shadcn component:
  ```bash
  npm run ui:add -- button
  ```
- Generated components should live in `src/components/ui`.
- Keep performance-critical stream/panel views custom; use shadcn primitives for shared controls/surfaces.

### With MCP Proxy

1. Start the SOTH proxy with dashboard enabled:
   ```yaml
   # soth.yaml
   dashboard:
     enabled: true
     port: 3001
   ```

2. Run the proxy:
   ```bash
   cargo run -- -c soth.yaml start
   ```

3. In a separate terminal, start the dashboard:
   ```bash
   cd dashboard
   npm install
   npm run dev
   ```

4. Open [http://localhost:3002](http://localhost:3002)

### With Forward Proxy

1. Configure both forward proxy and dashboard:
   ```yaml
   # soth.yaml
   forward_proxy:
     enabled: true
     port: 8080
     hosts:
       allow:
         - "api.openai.com"
         - "api.anthropic.com"

   dashboard:
     enabled: true
     port: 3001

   production:
     rate_limit:
       enabled: true
     circuit_breaker:
       enabled: true
   ```

2. Set up the CA certificate:
   ```bash
   soth proxy setup-ca
   ```

3. Start the forward proxy:
   ```bash
   soth proxy start --config soth.yaml
   ```

4. Start the dashboard:
   ```bash
   cd dashboard
   npm run dev
   ```

5. Configure your shell and make requests:
   ```bash
   eval $(soth proxy env)
   curl https://api.openai.com/v1/models
   ```

6. View metrics at [http://localhost:3002](http://localhost:3002)

## Production

For production, you can build and embed the dashboard:

```bash
npm run build
```

The static files in `.next/` can be served from the Rust backend.

## Architecture

```
dashboard/
├── src/
│   ├── app/
│   │   ├── globals.css      # Theme + animations
│   │   ├── layout.tsx       # Root layout
│   │   └── page.tsx         # Main dashboard
│   ├── components/
│   │   ├── panels/          # Metric panels
│   │   │   ├── identity-panel.tsx
│   │   │   ├── policy-panel.tsx
│   │   │   ├── observe-panel.tsx
│   │   │   ├── budget-panel.tsx
│   │   │   └── proxy-panel.tsx   # Forward proxy metrics
│   │   ├── providers.tsx    # React Query provider
│   │   └── ui/              # Reusable components
│   ├── hooks/
│   │   └── useDashboardData.ts  # API hooks
│   ├── lib/
│   │   └── utils.ts         # Utilities
│   └── types/
│       └── index.ts         # API types
```

## API Endpoints

The dashboard fetches from these endpoints (proxied to `:3001`):

### Core Metrics
- `GET /api/health` - Server health + uptime
- `GET /api/identity` - Identity verification metrics
- `GET /api/policy` - Policy evaluation metrics
- `GET /api/observe` - Request/response + PII metrics
- `GET /api/budget` - Token usage + cost metrics

### Forward Proxy Metrics
- `GET /api/proxy` - Proxy connection and request metrics
- `GET /metrics` - Prometheus metrics (raw format)

### Live Feed
- `GET /api/events` - Recent events
- `WS /api/events/stream` - WebSocket event stream
- `GET /api/agents` - Connected agent statistics
