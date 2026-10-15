'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Activity, AlertTriangle, Database, Gauge, ListFilter, Menu, Network, Plus, RefreshCw, Settings2, Trash2, X, Zap } from 'lucide-react'

type PageKey = 'Overview' | 'Upstreams' | 'Records' | 'Cache' | 'Incidents' | 'Metrics'
type RecordItem = { name: string; type: string; value: string; ttl: number }
type PowerDnsInstance = { id: string; name: string; url: string; token: string }

const INSTANCES_KEY = 'powerdns-instances'
const ACTIVE_INSTANCE_KEY = 'powerdns-active-instance'

function newInstanceId() {
  return `pdns_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
}

function loadInstances(): { instances: PowerDnsInstance[]; activeId: string } {
  const fallback: PowerDnsInstance = {
    id: 'default',
    name: 'Local',
    url: 'http://127.0.0.1:8000',
    token: '',
  }
  try {
    const raw = window.localStorage.getItem(INSTANCES_KEY)
    const activeId = window.localStorage.getItem(ACTIVE_INSTANCE_KEY) || ''
    if (raw) {
      const parsed = JSON.parse(raw) as PowerDnsInstance[]
      if (Array.isArray(parsed) && parsed.length > 0) {
        const id = parsed.some((p) => p.id === activeId) ? activeId : parsed[0].id
        return { instances: parsed, activeId: id }
      }
    }
    // migrate single-endpoint keys
    const oldUrl = window.localStorage.getItem('powerdns-api-base')
    const oldToken = window.localStorage.getItem('powerdns-api-token') || ''
    if (oldUrl) {
      const migrated: PowerDnsInstance = {
        id: 'default',
        name: 'Primary',
        url: oldUrl.replace(/\/$/, ''),
        token: oldToken,
      }
      return { instances: [migrated], activeId: migrated.id }
    }
  } catch {
    /* ignore */
  }
  return { instances: [fallback], activeId: fallback.id }
}

function persistInstances(instances: PowerDnsInstance[], activeId: string) {
  window.localStorage.setItem(INSTANCES_KEY, JSON.stringify(instances))
  window.localStorage.setItem(ACTIVE_INSTANCE_KEY, activeId)
  const active = instances.find((i) => i.id === activeId)
  if (active) {
    window.localStorage.setItem('powerdns-api-base', active.url)
    window.localStorage.setItem('powerdns-api-token', active.token)
  }
}

const INCIDENT_KIND_INFO: Record<string, { label: string; severity: 'critical' | 'warning' | 'info'; blurb: string }> = {
  upstream_unavailable: {
    label: 'Upstream unavailable',
    severity: 'critical',
    blurb: 'Every endpoint on this transport is unhealthy — resolution for this path is broken.',
  },
  transport_degradation: {
    label: 'Transport degradation',
    severity: 'warning',
    blurb: 'All endpoints on a transport are degraded or worse.',
  },
  provider_degradation: {
    label: 'Provider degradation',
    severity: 'warning',
    blurb: 'One endpoint is bad while peers on the same transport stay healthier.',
  },
  latency_degradation: {
    label: 'Latency degradation',
    severity: 'warning',
    blurb: 'Endpoint EWMA latency is elevated versus peers.',
  },
  dns_error_spike: {
    label: 'DNS error spike',
    severity: 'warning',
    blurb: 'High failure ratio on an endpoint.',
  },
}

function incidentMeta(item: IncidentItem) {
  const kind = String(item.kind || item.type || 'unknown').toLowerCase()
  const info = INCIDENT_KIND_INFO[kind]
  const severityRaw = String(item.severity || info?.severity || 'warning').toLowerCase()
  const severity: 'critical' | 'warning' | 'info' =
    severityRaw.includes('critical') || kind === 'upstream_unavailable'
      ? 'critical'
      : severityRaw.includes('info')
        ? 'info'
        : 'warning'
  return {
    kind,
    label: info?.label || kind.replace(/_/g, ' '),
    severity,
    blurb: info?.blurb || '',
  }
}
type UpstreamRow = {
  path: string
  endpoint: string
  state: string
  score?: number
  ewma_latency_ms?: number
  requests?: number
  successes?: number
  failures?: number
}
type IncidentItem = {
  kind?: string
  severity?: string
  title?: string
  detail?: string
  endpoint?: string
  path?: string
  state?: string
  message?: string
  [key: string]: unknown
}
type StatusFeatures = {
  metrics?: boolean
  records?: boolean
  cache?: boolean
  resolver?: boolean
  relay?: boolean
  relay_dot?: boolean
  dns_server?: boolean
  adaptive?: boolean
  admin_api?: boolean
  admin_auth?: boolean
}

type StatusPayload = {
  // legacy flat flags (older builds)
  resolver?: boolean
  cache?: boolean
  relay?: boolean
  records?: boolean
  cache_entries?: number
  cache_capacity?: number
  // expanded admin status
  mode?: string
  features?: StatusFeatures
  log?: { level?: string; format?: string }
  listen?: {
    api?: string
    dns?: string
    dns_dot?: string
    relay_dot?: string
    relay_path?: string
  }
  resolution?: { order?: string[]; adaptive?: boolean }
  cache_settings?: Record<string, unknown>
  // some builds nest cache under cache with entries/capacity + settings
  records_info?: { path?: string; enabled?: boolean }
  relay_info?: {
    configured?: boolean
    url?: string
    dot_addr?: string
    timeout?: number | string
    auth_configured?: boolean
  }
  upstream?: {
    doh_servers?: string[]
    dot_servers?: string[]
    plain_servers?: string[]
    doh_count?: number
    dot_count?: number
    plain_count?: number
    timeout?: number | string
  }
  security?: {
    admin_auth?: boolean
    relay_auth?: boolean
    allowed_domains?: string[]
    relay_rate_limit_per_minute?: number
    banned_answer_cidrs?: string[]
    ban_list_active?: boolean
  }
  health?: {
    endpoints_observed?: number
    active_incidents?: number
  }
  [key: string]: unknown
}

/** Normalize expanded or legacy admin status into a stable view model. */
function viewStatus(s: StatusPayload | null) {
  if (!s) return null
  const features: StatusFeatures = {
    metrics: s.features?.metrics,
    records: s.features?.records ?? s.records,
    cache: s.features?.cache ?? s.cache,
    resolver: s.features?.resolver ?? s.resolver,
    relay: s.features?.relay ?? s.relay,
    relay_dot: s.features?.relay_dot,
    dns_server: s.features?.dns_server,
    adaptive: s.features?.adaptive ?? (s.resolution as { adaptive?: boolean } | undefined)?.adaptive,
    admin_api: s.features?.admin_api ?? true,
    admin_auth: s.features?.admin_auth ?? s.security?.admin_auth,
  }

  const cacheObj = (s.cache && typeof s.cache === 'object' && !Array.isArray(s.cache) ? s.cache : null) as Record<
    string,
    unknown
  > | null
  const entries =
    (typeof cacheObj?.entries === 'number' ? cacheObj.entries : undefined) ??
    s.cache_entries ??
    (typeof s.entries === 'number' ? s.entries : undefined)
  const capacity =
    (typeof cacheObj?.capacity === 'number' ? cacheObj.capacity : undefined) ??
    s.cache_capacity ??
    (typeof s.capacity === 'number' ? s.capacity : undefined)

  const upstream = s.upstream || {}
  const dohList = upstream.doh_servers || []
  const dotList = upstream.dot_servers || []
  const plainList = upstream.plain_servers || []

  return {
    mode: s.mode || 'unknown',
    features,
    log: s.log || {},
    listen: s.listen || {},
    resolution: s.resolution || {},
    cache: {
      entries: entries ?? 0,
      capacity: capacity ?? 0,
      stale_while_revalidate_seconds: undefined as unknown,
      stale_while_revalidate: undefined as unknown,
      prefetch: undefined as unknown,
      prefetch_enabled: undefined as unknown,
      ...(cacheObj || {}),
      ...(s.cache_settings || {}),
    } as {
      entries: number
      capacity: number
      stale_while_revalidate_seconds?: unknown
      stale_while_revalidate?: unknown
      prefetch?: unknown
      prefetch_enabled?: unknown
    },
    records: s.records_info || (typeof s.records === 'object' && s.records !== null ? (s.records as object) : {}),
    relay:
      s.relay_info ||
      (typeof s.relay === 'object' && s.relay !== null && typeof s.relay !== 'boolean' ? (s.relay as object) : {}),
    upstream: {
      doh: dohList,
      dot: dotList,
      plain: plainList,
      doh_count: upstream.doh_count ?? dohList.length,
      dot_count: upstream.dot_count ?? dotList.length,
      plain_count: upstream.plain_count ?? plainList.length,
      timeout: upstream.timeout,
    },
    security: s.security || {},
    health: s.health || {},
    raw: s,
  }
}

function AdminStatusPanel({
  status,
  statusError,
  onRetry,
}: {
  status: StatusPayload | null
  statusError: string | null
  onRetry?: () => void
}) {
  const v = viewStatus(status)

  if (statusError) {
    const is404 = statusError.includes('404')
    return (
      <Card>
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="font-medium text-white">Process status</h2>
            <p className="mt-1 text-xs text-slate-500">GET /api/v1/admin/status</p>
          </div>
          {onRetry && <Button onClick={onRetry}>Retry</Button>}
        </div>
        <div className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-100">
          <p className="font-medium">{is404 ? 'Admin API is disabled or not mounted' : 'Could not load admin status'}</p>
          <p className="mt-2 text-xs leading-5 text-amber-100/80">{statusError}</p>
          {is404 && (
            <div className="mt-3 space-y-2 text-xs leading-6 text-amber-50/90">
              <p>Enable the admin surface in Power-DNS config (empty prefix disables it):</p>
              <pre className="overflow-x-auto rounded-md border border-white/10 bg-black/30 p-3 font-mono text-[11px] text-slate-300">{`[api]
# default mounts admin under /api/v1/admin — set empty to disable
admin_path_prefix = "/api/v1/admin"

[security]
# optional; if set, dashboard must send this bearer token
admin_auth_token = "change-me"`}</pre>
              <p>
                Then restart is only needed if you changed listen addresses or the prefix itself; most other fields
                hot-reload. Confirm with:
              </p>
              <pre className="overflow-x-auto rounded-md border border-white/10 bg-black/30 p-3 font-mono text-[11px] text-slate-300">{`curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/admin/status | jq .`}</pre>
            </div>
          )}
        </div>
      </Card>
    )
  }

  if (!v) {
    return (
      <Card>
        <h2 className="font-medium text-white">Process status</h2>
        <p className="mt-2 text-sm text-slate-500">No status payload yet — waiting for the admin API.</p>
      </Card>
    )
  }

  const featureRows: [string, boolean | undefined][] = [
    ['Resolver', v.features.resolver],
    ['DNS server', v.features.dns_server],
    ['Cache', v.features.cache],
    ['Records', v.features.records],
    ['Relay', v.features.relay],
    ['Relay DoT', v.features.relay_dot],
    ['Adaptive routing', v.features.adaptive],
    ['Metrics', v.features.metrics],
    ['Admin API', v.features.admin_api],
    ['Admin auth', v.features.admin_auth],
  ]

  const order = Array.isArray(v.resolution.order) ? v.resolution.order.join(' → ') : '—'
  const banned = Array.isArray(v.security.banned_answer_cidrs)
    ? v.security.banned_answer_cidrs.join(', ')
    : '—'
  const domains = Array.isArray(v.security.allowed_domains)
    ? v.security.allowed_domains.length
      ? v.security.allowed_domains.join(', ')
      : '(all)'
    : '—'

  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-medium text-white">Process status</h2>
          <p className="mt-1 text-xs text-slate-500">
            Live runtime snapshot from <code className="text-slate-400">/api/v1/admin/status</code>
          </p>
        </div>
        <span className="rounded-full border border-white/10 px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider text-slate-300">
          mode {v.mode}
        </span>
      </div>

      <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="tile-sm p-3">
          <p className="text-[10px] uppercase tracking-widest text-slate-500">Listen</p>
          <p className="mt-2 font-mono text-xs text-slate-300">API {String(v.listen.api || '—')}</p>
          <p className="mt-1 font-mono text-xs text-slate-400">DNS {String(v.listen.dns || '—')}</p>
          {v.listen.dns_dot ? <p className="mt-1 font-mono text-xs text-slate-500">DoT {String(v.listen.dns_dot)}</p> : null}
          {v.listen.relay_dot ? (
            <p className="mt-1 font-mono text-xs text-slate-500">Relay DoT {String(v.listen.relay_dot)}</p>
          ) : null}
        </div>
        <div className="tile-sm p-3">
          <p className="text-[10px] uppercase tracking-widest text-slate-500">Resolution</p>
          <p className="mt-2 text-xs leading-5 text-slate-300">{order}</p>
          <p className="mt-2 text-[11px] text-slate-500">
            adaptive {v.resolution.adaptive || v.features.adaptive ? 'on' : 'off'}
          </p>
        </div>
        <div className="tile-sm p-3">
          <p className="text-[10px] uppercase tracking-widest text-slate-500">Cache</p>
          <p className="mt-2 text-lg font-semibold text-white">
            {Number(v.cache.entries || 0).toLocaleString()}
            <span className="text-sm font-normal text-slate-500">
              {' '}
              / {Number(v.cache.capacity || 0).toLocaleString() || '—'}
            </span>
          </p>
          <p className="mt-1 text-[11px] text-slate-500">
            SWR {String(v.cache.stale_while_revalidate_seconds ?? v.cache.stale_while_revalidate ?? '—')}s · prefetch{' '}
            {v.cache.prefetch === false || v.cache.prefetch_enabled === false
              ? 'off'
              : v.cache.prefetch || v.cache.prefetch_enabled
                ? 'on'
                : '—'}
          </p>
        </div>
        <div className="tile-sm p-3">
          <p className="text-[10px] uppercase tracking-widest text-slate-500">Health snapshot</p>
          <p className="mt-2 text-sm text-slate-200">
            {v.health.endpoints_observed ?? '—'} endpoints · {v.health.active_incidents ?? '—'} incidents
          </p>
          <p className="mt-1 text-[11px] text-slate-500">
            log {String(v.log.level || '—')} / {String(v.log.format || '—')}
          </p>
        </div>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <div>
          <p className="text-[10px] uppercase tracking-widest text-slate-500">Features</p>
          <div className="mt-3 grid grid-cols-2 gap-2">
            {featureRows.map(([label, on]) => (
              <div key={label} className="flex items-center justify-between rounded-md border border-white/[0.06] px-2.5 py-2 text-xs">
                <span className="text-slate-400">{label}</span>
                <span className={on ? 'text-emerald-300' : on === false ? 'text-slate-600' : 'text-slate-500'}>
                  {on === true ? 'on' : on === false ? 'off' : '—'}
                </span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-widest text-slate-500">Upstreams configured</p>
          <div className="mt-3 space-y-2 text-xs">
            <p>
              <span className="text-slate-500">DoH ({v.upstream.doh_count}) </span>
              <span className="font-mono text-slate-300">
                {v.upstream.doh.length ? v.upstream.doh.join(', ') : '—'}
              </span>
            </p>
            <p>
              <span className="text-slate-500">DoT ({v.upstream.dot_count}) </span>
              <span className="font-mono text-slate-300">
                {v.upstream.dot.length ? v.upstream.dot.join(', ') : '—'}
              </span>
            </p>
            <p>
              <span className="text-slate-500">Plain ({v.upstream.plain_count}) </span>
              <span className="font-mono text-slate-300">
                {v.upstream.plain.length ? v.upstream.plain.join(', ') : '—'}
              </span>
            </p>
            {v.upstream.timeout != null && (
              <p className="text-slate-500">timeout {String(v.upstream.timeout)}</p>
            )}
          </div>
          <p className="mt-4 text-[10px] uppercase tracking-widest text-slate-500">Security</p>
          <div className="mt-2 space-y-1 text-xs text-slate-400">
            <p>
              admin auth {v.security.admin_auth ? 'required' : 'off'} · relay auth{' '}
              {v.security.relay_auth ? 'required' : 'off'}
            </p>
            <p>
              banned CIDRs <span className="font-mono text-slate-300">{banned}</span>
              {v.security.ban_list_active ? ' (active)' : ''}
            </p>
            <p>
              allowed domains <span className="font-mono text-slate-300">{domains}</span>
            </p>
            {v.security.relay_rate_limit_per_minute != null && (
              <p>relay rate limit {String(v.security.relay_rate_limit_per_minute)}/min</p>
            )}
          </div>
        </div>
      </div>
    </Card>
  )
}
type CachePayload = {
  entries?: number
  capacity?: number
  size?: number
  max?: number
  [key: string]: unknown
}

const nav: { label: PageKey; icon: typeof Gauge }[] = [
  { label: 'Overview', icon: Gauge },
  { label: 'Upstreams', icon: Network },
  { label: 'Records', icon: ListFilter },
  { label: 'Cache', icon: Database },
  { label: 'Incidents', icon: AlertTriangle },
  { label: 'Metrics', icon: Activity },
]

function Dot({ tone = 'good' }: { tone?: 'good' | 'warn' | 'bad' | 'neutral' }) {
  return (
    <span
      className={`inline-block size-2 rounded-full ${
        tone === 'good' ? 'bg-emerald-400' : tone === 'warn' ? 'bg-amber-400' : tone === 'bad' ? 'bg-red-500' : 'bg-slate-500'
      }`}
    />
  )
}

function Button({
  children,
  onClick,
  tone = 'default',
  disabled = false,
}: {
  children: React.ReactNode
  onClick?: () => void
  tone?: 'default' | 'danger'
  disabled?: boolean
}) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      className={`rounded-md border px-3 py-2 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${
        tone === 'danger'
          ? 'border-red-500/30 text-red-300 hover:bg-red-500/10'
          : 'border-white/10 text-slate-300 hover:border-white/20 hover:bg-white/[0.04]'
      }`}
    >
      {children}
    </button>
  )
}

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <section className={`tile p-5 ${className}`}>{children}</section>
}

function Header({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-[0.2em] text-red-400">Power-DNS / control</p>
      <h1 className="mt-2 text-2xl font-semibold text-white">{title}</h1>
      <p className="mt-1 text-sm text-slate-500">{subtitle}</p>
    </div>
  )
}

function authHeaders(token: string, json = false): Record<string, string> {
  const headers: Record<string, string> = {}
  if (json) headers['Content-Type'] = 'application/json'
  if (token.trim()) headers.Authorization = `Bearer ${token.trim()}`
  return headers
}

function baseUrl(api: string) {
  return api.replace(/\/$/, '')
}

/**
 * All browser → Power-DNS traffic goes same-origin through /api/proxy/*
 * so CORS is never required on the Power-DNS process.
 * The real upstream is passed as X-PowerDNS-Base.
 */
function proxyUrl(path: string) {
  const clean = path.startsWith('/') ? path.slice(1) : path
  return `/api/proxy/${clean}`
}

async function apiFetch(api: string, path: string, token: string, init?: RequestInit) {
  const res = await fetch(proxyUrl(path), {
    ...init,
    headers: {
      ...authHeaders(token, !!init?.body),
      'X-PowerDNS-Base': baseUrl(api),
      ...(init?.headers || {}),
    },
    signal: AbortSignal.timeout(12000),
  })
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const j = await res.clone().json()
      if (j?.detail) detail = `${detail}: ${j.detail}`
      else if (j?.error) detail = `${detail}: ${j.error}`
    } catch {
      /* ignore */
    }
    throw new Error(detail)
  }
  return res
}

/** Parse Prometheus text exposition into a flat map of full metric keys → values. */
function parsePrometheus(text: string): Record<string, number> {
  const out: Record<string, number> = {}
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    // value is last whitespace-separated token (handles scientific notation)
    const match = trimmed.match(/^(.+?)\s+([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)$/)
    if (!match) continue
    const namePart = match[1]
    const value = Number(match[2])
    if (Number.isNaN(value)) continue
    out[namePart] = value
  }
  return out
}

/** Sum all series whose name is exactly `name` or starts with `name{`. */
function metricSum(metrics: Record<string, number>, name: string): number {
  let sum = 0
  const prefix = name + '{'
  for (const [k, v] of Object.entries(metrics)) {
    if (k === name || k.startsWith(prefix)) sum += v
  }
  return sum
}

function metricGet(metrics: Record<string, number>, name: string): number {
  return metrics[name] ?? 0
}

function metricLabeled(metrics: Record<string, number>, name: string, labelKey: string, labelVal: string): number {
  return metrics[`${name}{${labelKey}="${labelVal}"}`] ?? 0
}

/** Pull a single label value out of a Prometheus key, e.g. endpoint="…" */
function labelValue(key: string, label: string): string | null {
  const re = new RegExp(`${label}="([^"]*)"`)
  const m = key.match(re)
  return m ? m[1] : null
}

type DerivedMetrics = {
  uptimeSec: number
  queries: {
    total: number
    cache: number
    doh: number
    dot: number
    plain: number
    relay: number
    failed: number
    records: number
  }
  cache: {
    hits: number
    staleHits: number
    missesExpired: number
    missesNotFound: number
    misses: number
    freshRate: number // 0–1 from gauge or computed
    effectiveRate: number
    entries: number
    capacity: number
    staleRevalidations: number
    staleRevalidationFailures: number
    prefetchSuccess: number
    prefetchFailure: number
    prefetchProtectedHits: number
  }
  upstream: {
    callsDoh: number
    callsDot: number
    callsPlain: number
    callsTotal: number
    coalescedDoh: number
    coalescedDot: number
    coalescedPlain: number
    coalescedTotal: number
    latencyAvgDoh: number
    latencyAvgDot: number
    latencyAvgPlain: number
  }
  poison: number
  relayCalls: number
  relayCoalesced: number
}

function deriveMetrics(raw: Record<string, number>): DerivedMetrics {
  const qCache = metricLabeled(raw, 'powerdns_queries_total', 'strategy', 'cache')
  const qDoh = metricLabeled(raw, 'powerdns_queries_total', 'strategy', 'doh')
  const qDot = metricLabeled(raw, 'powerdns_queries_total', 'strategy', 'dot')
  const qPlain = metricLabeled(raw, 'powerdns_queries_total', 'strategy', 'plain')
  const qRelay = metricLabeled(raw, 'powerdns_queries_total', 'strategy', 'relay')
  const qFailed = metricLabeled(raw, 'powerdns_queries_total', 'strategy', 'failed')
  const qRecords = metricLabeled(raw, 'powerdns_queries_total', 'strategy', 'records')
  const qTotal = metricSum(raw, 'powerdns_queries_total')

  const hits = metricGet(raw, 'powerdns_cache_hits_total')
  const staleHits = metricGet(raw, 'powerdns_cache_stale_hits_total')
  const missExpired = metricLabeled(raw, 'powerdns_cache_misses_total', 'reason', 'expired')
  const missNotFound = metricLabeled(raw, 'powerdns_cache_misses_total', 'reason', 'not_found')
  const misses = metricSum(raw, 'powerdns_cache_misses_total')

  // Prefer process gauges when present
  const freshRateGauge = metricGet(raw, 'powerdns_cache_hit_rate')
  const effectiveRateGauge = metricGet(raw, 'powerdns_cache_effective_hit_rate')
  const denomFresh = hits + misses
  const denomEff = hits + staleHits + misses
  const freshRate = freshRateGauge > 0 ? freshRateGauge : denomFresh > 0 ? hits / denomFresh : 0
  const effectiveRate =
    effectiveRateGauge > 0 ? effectiveRateGauge : denomEff > 0 ? (hits + staleHits) / denomEff : 0

  const callsDoh = metricLabeled(raw, 'powerdns_upstream_calls_total', 'path', 'doh')
  const callsDot = metricLabeled(raw, 'powerdns_upstream_calls_total', 'path', 'dot')
  const callsPlain = metricLabeled(raw, 'powerdns_upstream_calls_total', 'path', 'plain')
  const coalescedDoh = metricLabeled(raw, 'powerdns_upstream_coalesced_total', 'path', 'doh')
  const coalescedDot = metricLabeled(raw, 'powerdns_upstream_coalesced_total', 'path', 'dot')
  const coalescedPlain = metricLabeled(raw, 'powerdns_upstream_coalesced_total', 'path', 'plain')

  const latSumDoh = metricGet(raw, 'powerdns_upstream_latency_ms_sum{path="doh"}')
  const latCntDoh = metricGet(raw, 'powerdns_upstream_latency_ms_count{path="doh"}')
  const latSumDot = metricGet(raw, 'powerdns_upstream_latency_ms_sum{path="dot"}')
  const latCntDot = metricGet(raw, 'powerdns_upstream_latency_ms_count{path="dot"}')
  const latSumPlain = metricGet(raw, 'powerdns_upstream_latency_ms_sum{path="plain"}')
  const latCntPlain = metricGet(raw, 'powerdns_upstream_latency_ms_count{path="plain"}')

  return {
    uptimeSec: metricGet(raw, 'powerdns_uptime_seconds'),
    queries: {
      total: qTotal,
      cache: qCache,
      doh: qDoh,
      dot: qDot,
      plain: qPlain,
      relay: qRelay,
      failed: qFailed,
      records: qRecords,
    },
    cache: {
      hits,
      staleHits,
      missesExpired: missExpired,
      missesNotFound: missNotFound,
      misses,
      freshRate,
      effectiveRate,
      entries: metricGet(raw, 'powerdns_cache_entries'),
      capacity: metricGet(raw, 'powerdns_cache_capacity'),
      staleRevalidations: metricGet(raw, 'powerdns_cache_stale_revalidations_total'),
      staleRevalidationFailures: metricGet(raw, 'powerdns_cache_stale_revalidation_failures_total'),
      prefetchSuccess: metricLabeled(raw, 'powerdns_cache_prefetch_total', 'result', 'success'),
      prefetchFailure: metricLabeled(raw, 'powerdns_cache_prefetch_total', 'result', 'failure'),
      prefetchProtectedHits: metricGet(raw, 'powerdns_cache_prefetch_protected_hits_total'),
    },
    upstream: {
      callsDoh,
      callsDot,
      callsPlain,
      callsTotal: callsDoh + callsDot + callsPlain,
      coalescedDoh,
      coalescedDot,
      coalescedPlain,
      coalescedTotal: coalescedDoh + coalescedDot + coalescedPlain,
      latencyAvgDoh: latCntDoh > 0 ? latSumDoh / latCntDoh : 0,
      latencyAvgDot: latCntDot > 0 ? latSumDot / latCntDot : 0,
      latencyAvgPlain: latCntPlain > 0 ? latSumPlain / latCntPlain : 0,
    },
    poison: metricSum(raw, 'powerdns_poisoned_answers_total'),
    relayCalls: metricGet(raw, 'powerdns_relay_calls_total'),
    relayCoalesced: metricGet(raw, 'powerdns_relay_coalesced_total'),
  }
}

function formatUptime(sec: number): string {
  if (!sec || sec < 1) return '—'
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

function pct(rate: number): string {
  if (!rate && rate !== 0) return '—'
  return `${(rate * 100).toFixed(1)}%`
}

function stateTone(state: string): 'good' | 'warn' | 'bad' | 'neutral' {
  const s = state.toLowerCase()
  if (s === 'healthy') return 'good'
  if (s === 'degraded' || s === 'probing') return 'warn'
  if (s === 'unhealthy') return 'bad'
  return 'neutral'
}

function OverviewPremium({
  setPage,
  connection,
  status,
  statusError,
  onRetryStatus,
  metrics,
  upstreams,
  incidents,
  lastChecked,
}: {
  setPage: (page: PageKey) => void
  connection: 'checking' | 'live' | 'offline'
  status: StatusPayload | null
  statusError: string | null
  onRetryStatus?: () => void
  metrics: Record<string, number>
  upstreams: UpstreamRow[]
  incidents: IncidentItem[]
  lastChecked: string
}) {
  const d = deriveMetrics(metrics)
  const vs = viewStatus(status)
  const healthy = upstreams.filter((u) => u.state === 'healthy').length
  const attention = upstreams.filter((u) => ['probing', 'degraded', 'unhealthy'].includes(u.state)).length
  const strategyBars: [string, number, string][] = [
    ['cache', d.queries.cache, 'bg-emerald-500/80'],
    ['doh', d.queries.doh, 'bg-sky-500/70'],
    ['dot', d.queries.dot, 'bg-violet-500/70'],
    ['plain', d.queries.plain, 'bg-amber-500/70'],
    ['failed', d.queries.failed, 'bg-red-500/80'],
  ]
  if (d.queries.relay > 0) strategyBars.splice(1, 0, ['relay', d.queries.relay, 'bg-teal-500/70'])
  const maxBar = Math.max(...strategyBars.map(([, v]) => v), 1)

  const connLabel =
    connection === 'live' ? `Live · ${lastChecked || 'just now'}` : connection === 'checking' ? 'Checking…' : 'Unreachable'

  const qps = d.uptimeSec > 0 ? d.queries.total / d.uptimeSec : 0
  const poisonRate = d.queries.plain > 0 ? d.poison / (d.upstream.callsPlain || d.queries.plain) : 0

  return (
    <div className="flex flex-col gap-5">
      <div className="relative overflow-hidden rounded-2xl border border-white/[0.09] bg-gradient-to-br from-[#1b1d22] via-[#15171b] to-[#241517] p-6 sm:p-8">
        <div className="pointer-events-none absolute -right-24 -top-24 size-72 rounded-full bg-red-600/10 blur-3xl" />
        <div className="relative flex flex-col justify-between gap-6 lg:flex-row lg:items-end">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.24em] text-red-400">Power-DNS / resolver plane</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Resolver operations</h1>
            <p className="mt-2 max-w-xl text-sm text-slate-400">
              Query outcomes, cache efficiency, poison rejects, and upstream path health — from live process metrics.
            </p>
          </div>
          <div
            className={`flex items-center gap-3 rounded-lg border px-3 py-2 text-xs ${
              connection === 'live'
                ? 'border-emerald-400/15 bg-emerald-400/[0.06] text-emerald-300'
                : connection === 'checking'
                  ? 'border-amber-400/15 bg-amber-400/[0.06] text-amber-200'
                  : 'border-red-400/20 bg-red-400/10 text-red-300'
            }`}
          >
            <Dot tone={connection === 'live' ? 'good' : connection === 'checking' ? 'warn' : 'bad'} />
            API status <span className="text-slate-600">·</span> {connLabel}
          </div>
        </div>
        <div className="relative mt-8 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <div className="tile-sm p-4">
            <p className="text-[10px] uppercase tracking-widest text-slate-500">Queries resolved</p>
            <p className="mt-2 text-2xl font-semibold text-white">{d.queries.total.toLocaleString()}</p>
            <p className="mt-1 text-xs text-slate-500">
              uptime {formatUptime(d.uptimeSec)}
              {qps > 0 ? ` · ~${qps.toFixed(2)} q/s` : ''}
            </p>
          </div>
          <div className="tile-sm p-4">
            <p className="text-[10px] uppercase tracking-widest text-slate-500">Effective cache</p>
            <p className="mt-2 text-2xl font-semibold text-white">{pct(d.cache.effectiveRate)}</p>
            <p className="mt-1 text-xs text-slate-500">
              {d.cache.hits.toLocaleString()} fresh · {d.cache.staleHits.toLocaleString()} stale (SWR)
            </p>
          </div>
          <div className="tile-sm p-4">
            <p className="text-[10px] uppercase tracking-widest text-slate-500">Fresh hit rate</p>
            <p className="mt-2 text-2xl font-semibold text-white">{pct(d.cache.freshRate)}</p>
            <p className="mt-1 text-xs text-slate-500">
              {d.cache.misses.toLocaleString()} misses · {d.cache.entries}/{d.cache.capacity || '—'} entries
            </p>
          </div>
          <div
            className={`tile-sm p-4 ${d.poison > 0 || attention > 0 ? 'border-red-400/30' : ''}`}
          >
            <p className={`text-[10px] uppercase tracking-widest ${d.poison > 0 ? 'text-red-300/70' : 'text-slate-500'}`}>
              Poison rejects
            </p>
            <p className={`mt-2 text-2xl font-semibold ${d.poison > 0 ? 'text-red-200' : 'text-white'}`}>
              {d.poison.toLocaleString()}
            </p>
            <p className={`mt-1 text-xs ${d.poison > 0 ? 'text-red-300/70' : 'text-slate-500'}`}>
              banned CIDRs on plain DNS
              {attention > 0 ? ` · ${attention} upstream path(s) degraded` : ''}
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          [
            'Upstream network calls',
            d.upstream.callsTotal.toLocaleString(),
            `DoH ${d.upstream.callsDoh.toLocaleString()} · DoT ${d.upstream.callsDot.toLocaleString()} · plain ${d.upstream.callsPlain.toLocaleString()}`,
          ],
          [
            'Coalesced queries',
            d.upstream.coalescedTotal.toLocaleString(),
            d.upstream.callsTotal + d.upstream.coalescedTotal > 0
              ? `${((d.upstream.coalescedTotal / (d.upstream.callsTotal + d.upstream.coalescedTotal)) * 100).toFixed(1)}% of upstream demand`
              : 'no upstream demand yet',
          ],
          [
            'Prefetch protected hits',
            d.cache.prefetchProtectedHits.toLocaleString(),
            `${d.cache.prefetchSuccess.toLocaleString()} ok · ${d.cache.prefetchFailure.toLocaleString()} fail`,
          ],
          [
            'Failed strategy',
            d.queries.failed.toLocaleString(),
            d.queries.total > 0
              ? `${((d.queries.failed / d.queries.total) * 100).toFixed(2)}% of all queries`
              : '—',
          ],
        ].map(([label, value, detail]) => (
          <Card key={label}>
            <div className="flex items-start justify-between">
              <p className="text-xs text-slate-500">{label}</p>
              <Gauge className="size-4 text-slate-600" />
            </div>
            <p className="mt-4 text-2xl font-semibold text-white">{value}</p>
            <p className="mt-1 text-[11px] text-slate-600">{detail}</p>
          </Card>
        ))}
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.4fr_.9fr]">
        <Card>
          <div className="flex items-start justify-between">
            <div>
              <h2 className="font-medium text-white">Answered by strategy</h2>
              <p className="mt-1 text-xs text-slate-500">
                powerdns_queries_total — first strategy that produced a usable answer.
              </p>
            </div>
            <Button onClick={() => setPage('Metrics')}>Open metrics</Button>
          </div>
          {/* Stacked share strip */}
          <div className="mt-6 h-3 overflow-hidden rounded-full bg-white/[0.06]">
            <div className="flex h-full w-full">
              {strategyBars.map(([label, value, color]) => {
                const share = d.queries.total > 0 ? (value / d.queries.total) * 100 : 0
                if (share <= 0) return null
                return (
                  <div
                    key={label}
                    className={`h-full ${color}`}
                    style={{ width: `${share}%` }}
                    title={`${label}: ${value.toLocaleString()} (${share.toFixed(1)}%)`}
                  />
                )
              })}
            </div>
          </div>

          {/* Horizontal bars — fixed layout, no % height bugs */}
          <div className="mt-6 flex flex-col gap-3">
            {strategyBars.map(([label, value, color]) => {
              const share = d.queries.total > 0 ? (value / d.queries.total) * 100 : 0
              const barPct = maxBar > 0 ? (value / maxBar) * 100 : 0
              return (
                <div key={label} className="grid grid-cols-[4.5rem_1fr_auto] items-center gap-3">
                  <span className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</span>
                  <div className="h-7 overflow-hidden rounded-md bg-white/[0.05]">
                    <div
                      className={`flex h-full min-w-0 items-center rounded-md px-2 ${color} transition-[width] duration-500`}
                      style={{ width: `${Math.max(value > 0 ? 2 : 0, barPct)}%` }}
                    >
                      {barPct > 18 && (
                        <span className="truncate text-[11px] font-medium text-black/70">{value.toLocaleString()}</span>
                      )}
                    </div>
                  </div>
                  <div className="w-24 text-right">
                    <span className="font-mono text-sm text-slate-200">{value.toLocaleString()}</span>
                    <span className="ml-1.5 font-mono text-[11px] text-slate-500">{share.toFixed(1)}%</span>
                  </div>
                </div>
              )
            })}
          </div>

          <div className="mt-5 flex flex-wrap gap-x-5 gap-y-1 border-t border-white/[0.06] pt-4 text-[11px] text-slate-500">
            <span>
              Total <strong className="text-slate-300">{d.queries.total.toLocaleString()}</strong>
            </span>
            <span>
              Avg DoH{' '}
              <strong className="text-slate-300">
                {d.upstream.latencyAvgDoh ? `${d.upstream.latencyAvgDoh.toFixed(0)} ms` : '—'}
              </strong>
            </span>
            <span>
              Avg DoT{' '}
              <strong className="text-slate-300">
                {d.upstream.latencyAvgDot ? `${d.upstream.latencyAvgDot.toFixed(0)} ms` : '—'}
              </strong>
            </span>
            <span>
              Avg plain{' '}
              <strong className="text-slate-300">
                {d.upstream.latencyAvgPlain ? `${d.upstream.latencyAvgPlain.toFixed(0)} ms` : '—'}
              </strong>
            </span>
          </div>
        </Card>
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-medium text-white">Control plane</h2>
              <p className="mt-1 text-xs text-slate-500">Health API + process gauges.</p>
            </div>
            <Button onClick={() => setPage('Incidents')}>Incidents</Button>
          </div>
          <div className="mt-6 flex flex-col gap-4">
            {[
              [
                'Resolver API',
                connection === 'live' ? 'operational' : connection === 'checking' ? 'checking' : 'unreachable',
                connection === 'live' ? 'good' : 'warn',
              ],
              [
                'Mode / adaptive',
                vs ? `${vs.mode}${vs.features.adaptive ? ' · adaptive' : ''}` : '—',
                'good',
              ],
              [
                'Cache occupancy',
                (vs?.cache.capacity || d.cache.capacity)
                  ? `${Number(vs?.cache.entries ?? d.cache.entries).toLocaleString()} / ${Number(vs?.cache.capacity ?? d.cache.capacity).toLocaleString()}`
                  : String(vs?.cache.entries ?? d.cache.entries),
                'good',
              ],
              [
                'Upstream endpoints',
                upstreams.length
                  ? `${healthy} healthy · ${attention} need attention`
                  : vs?.health.endpoints_observed != null
                    ? `${vs.health.endpoints_observed} observed`
                    : 'no endpoint telemetry yet',
                attention ? 'warn' : 'good',
              ],
              [
                'Poison / plain risk',
                d.poison > 0 ? `${d.poison} rejected` : 'none rejected',
                d.poison > 0 ? 'warn' : 'good',
              ],
              [
                'Active incidents',
                String(vs?.health.active_incidents ?? incidents.length),
                (vs?.health.active_incidents ?? incidents.length) ? 'warn' : 'good',
              ],
            ].map(([label, value, tone]) => (
              <div key={label} className="flex items-center justify-between border-b border-white/[0.06] pb-3 last:border-0">
                <span className="flex items-center gap-2 text-sm text-slate-300">
                  <Dot tone={tone === 'good' ? 'good' : 'warn'} />
                  {label}
                </span>
                <span className={`text-xs ${tone === 'good' ? 'text-emerald-300' : 'text-red-300'}`}>{value}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <AdminStatusPanel status={status} statusError={statusError} onRetry={onRetryStatus} />
    </div>
  )
}

function Upstreams({ api, token, upstreams, loading, error, onRefresh }: {
  api: string
  token: string
  upstreams: UpstreamRow[]
  loading: boolean
  error: string
  onRefresh: () => void
}) {
  const healthy = upstreams.filter((u) => u.state === 'healthy').length
  const totalReq = upstreams.reduce((s, u) => s + (u.requests || 0), 0)
  const totalFail = upstreams.reduce((s, u) => s + (u.failures || 0), 0)
  const dohCalls = upstreams.filter((u) => u.path === 'doh').reduce((s, u) => s + (u.requests || 0), 0)
  const dotCalls = upstreams.filter((u) => u.path === 'dot').reduce((s, u) => s + (u.requests || 0), 0)
  const plainCalls = upstreams.filter((u) => u.path === 'plain').reduce((s, u) => s + (u.requests || 0), 0)

  const slowest = [...upstreams].sort((a, b) => (b.ewma_latency_ms || 0) - (a.ewma_latency_ms || 0))[0]
  const best = [...upstreams].filter((u) => u.state === 'healthy').sort((a, b) => (a.ewma_latency_ms || 0) - (b.ewma_latency_ms || 0))[0]
  const worstRatio = [...upstreams]
    .map((u) => ({
      ...u,
      ratio: (u.requests || 0) > 0 ? ((u.failures || 0) / (u.requests || 1)) * 100 : 0,
    }))
    .sort((a, b) => b.ratio - a.ratio)[0]

  return (
    <div className="flex flex-col gap-5">
      <Header title="Upstreams & relay" subtitle="Adaptive upstream routing and per-endpoint health from /api/v1/health/upstreams." />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ['Healthy paths', `${healthy} / ${upstreams.length || '—'}`, upstreams.length ? `${((healthy / upstreams.length) * 100).toFixed(0)}% available` : 'no data'],
          ['Upstream requests', totalReq.toLocaleString(), `DoH ${dohCalls} · DoT ${dotCalls} · plain ${plainCalls}`],
          ['Failures', totalFail.toLocaleString(), totalReq ? `${((totalFail / totalReq) * 100).toFixed(1)}% overall` : '—'],
          ['Endpoints tracked', String(upstreams.length), loading ? 'refreshing…' : error || 'live'],
        ].map(([a, b, c]) => (
          <Card key={a}>
            <p className="text-xs text-slate-500">{a}</p>
            <p className="mt-3 text-2xl font-semibold text-white">{b}</p>
            <p className="mt-1 text-[11px] text-slate-600">{c}</p>
          </Card>
        ))}
      </div>
      <div className="grid gap-5 xl:grid-cols-[1.7fr_1fr]">
        <Card>
          <div className="flex items-start justify-between">
            <div>
              <h2 className="font-medium">Upstream matrix</h2>
              <p className="mt-1 text-xs text-slate-500">Path, endpoint, state, EWMA latency, requests and failures.</p>
              {error && <p className="mt-2 text-[11px] text-red-300">{error}</p>}
            </div>
            <Button onClick={onRefresh} disabled={loading}>
              <span className="flex items-center gap-2">
                <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </span>
            </Button>
          </div>
          <div className="mt-5 overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="text-[10px] uppercase tracking-widest text-slate-600">
                <tr>
                  <th className="pb-3">Transport</th>
                  <th>Endpoint</th>
                  <th>State</th>
                  <th>EWMA</th>
                  <th>Requests</th>
                  <th>Success</th>
                  <th>Failures</th>
                  <th>Failure ratio</th>
                </tr>
              </thead>
              <tbody>
                {upstreams.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-500">
                      {loading ? 'Loading upstreams…' : 'No upstream data. Check API connection and /api/v1/health/upstreams.'}
                    </td>
                  </tr>
                ) : (
                  upstreams.map((item) => {
                    const total = item.requests || 0
                    const failed = item.failures || 0
                    const success = item.successes ?? Math.max(0, total - failed)
                    const ratio = total > 0 ? ((failed / total) * 100).toFixed(1) : '0.0'
                    return (
                      <tr key={`${item.path}-${item.endpoint}`} className="border-t border-white/[0.06]">
                        <td className="py-4 uppercase text-slate-500">{item.path}</td>
                        <td className="font-mono text-xs text-slate-300">{item.endpoint}</td>
                        <td className={item.state === 'healthy' ? 'text-emerald-300' : 'text-red-300'}>
                          <span className="flex items-center gap-2">
                            <Dot tone={stateTone(item.state)} />
                            {item.state}
                          </span>
                        </td>
                        <td className="text-slate-300">{(item.ewma_latency_ms ?? 0).toFixed(1)} ms</td>
                        <td className="text-slate-300">{total.toLocaleString()}</td>
                        <td className="text-emerald-300">{success.toLocaleString()}</td>
                        <td className="text-red-300">{failed.toLocaleString()}</td>
                        <td className="text-slate-400">{ratio}%</td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </Card>
        <Card>
          <h2 className="font-medium">Signals</h2>
          <div className="mt-5 flex flex-col gap-3">
            {[
              [
                'Probe state',
                `${upstreams.filter((u) => u.state !== 'healthy').length} non-healthy · ${healthy} healthy`,
                healthy === upstreams.length && upstreams.length > 0 ? 'good' : 'red',
              ],
              [
                'Slowest path',
                slowest ? `${slowest.endpoint} · ${(slowest.ewma_latency_ms ?? 0).toFixed(0)} ms` : '—',
                'red',
              ],
              [
                'Best healthy path',
                best ? `${best.endpoint} · ${(best.ewma_latency_ms ?? 0).toFixed(0)} ms` : '—',
                'good',
              ],
              [
                'Highest failure ratio',
                worstRatio && (worstRatio.requests || 0) > 0
                  ? `${worstRatio.endpoint} · ${worstRatio.ratio.toFixed(1)}%`
                  : '—',
                'red',
              ],
            ].map(([label, value, tone]) => (
              <div key={label} className="flex items-center justify-between border-b border-white/[0.06] pb-3 last:border-0">
                <div>
                  <p className="text-xs text-slate-500">{label}</p>
                  <p className={`mt-1 text-sm ${tone === 'good' ? 'text-emerald-300' : 'text-red-300'}`}>{value}</p>
                </div>
                <Gauge className="size-4 text-slate-600" />
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  )
}

function Records({ api, token }: { api: string; token: string }) {
  const [records, setRecords] = useState<RecordItem[]>([])
  const [form, setForm] = useState<RecordItem>({ name: '', type: 'A', value: '', ttl: 300 })
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await apiFetch(api, '/api/v1/records', token)
      const data = await res.json()
      const list: RecordItem[] = Array.isArray(data)
        ? data.map((r: RecordItem) => ({
            name: r.name || '',
            type: r.type || 'A',
            value: r.value || '',
            ttl: Number(r.ttl) || 300,
          }))
        : []
      setRecords(list)
      setMessage('')
    } catch (e) {
      setMessage(`Could not load records: ${e instanceof Error ? e.message : 'API error'}`)
    } finally {
      setLoading(false)
    }
  }, [api, token])

  useEffect(() => {
    load()
  }, [load])

  const add = async () => {
    const normalized = {
      ...form,
      name: form.name.trim(),
      value: form.value.trim(),
      ttl: Math.max(1, Math.floor(Number(form.ttl) || 300)),
    }
    if (!normalized.name || !normalized.value) {
      setMessage('Name and value are required.')
      return
    }
    try {
      await apiFetch(api, '/api/v1/records', token, {
        method: 'POST',
        body: JSON.stringify(normalized),
      })
      setMessage('Record created.')
      setForm({ name: '', type: 'A', value: '', ttl: 300 })
      await load()
    } catch (e) {
      setMessage(`Create failed: ${e instanceof Error ? e.message : 'API error'}`)
    }
  }

  const remove = async (record: RecordItem) => {
    try {
      const q = new URLSearchParams({
        name: record.name,
        type: record.type,
        value: record.value,
      })
      await apiFetch(api, `/api/v1/records?${q}`, token, { method: 'DELETE' })
      setMessage('Record deleted.')
      await load()
    } catch (e) {
      setMessage(`Delete failed: ${e instanceof Error ? e.message : 'API error'}`)
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <Header title="Records" subtitle="Authoritative overrides via /api/v1/records (A / AAAA / CNAME / TXT)." />
      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-medium">Add record</h2>
            <p className="mt-1 text-xs text-slate-500">POST to the records API. Token required if admin_auth_token is set.</p>
          </div>
          {message && <span className="max-w-md text-right text-xs text-red-300">{message}</span>}
        </div>
        <div className="mt-5 grid gap-3 md:grid-cols-[1.4fr_.6fr_1.4fr_.6fr_auto]">
          <input
            aria-label="Record name"
            placeholder="grafana.internal."
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-red-400/40"
          />
          <select
            aria-label="Record type"
            value={form.type}
            onChange={(e) => setForm({ ...form, type: e.target.value })}
            className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-red-400/40"
          >
            <option>A</option>
            <option>AAAA</option>
            <option>CNAME</option>
            <option>TXT</option>
          </select>
          <input
            aria-label="Record value"
            placeholder="10.0.0.5"
            value={form.value}
            onChange={(e) => setForm({ ...form, value: e.target.value })}
            className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-red-400/40"
          />
          <input
            aria-label="Record TTL"
            type="number"
            value={form.ttl}
            onChange={(e) => setForm({ ...form, ttl: Number(e.target.value) })}
            className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-red-400/40"
          />
          <Button onClick={add}>Add record</Button>
        </div>
      </Card>
      <Card>
        <div className="flex items-center justify-between">
          <h2 className="font-medium">Authoritative records</h2>
          <Button onClick={load} disabled={loading}>
            <span className="flex items-center gap-2">
              <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
              Reload
            </span>
          </Button>
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="text-[10px] uppercase tracking-widest text-slate-600">
              <tr>
                <th className="pb-3">Name</th>
                <th>Type</th>
                <th>Value</th>
                <th>TTL</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {records.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500">
                    {loading ? 'Loading…' : 'No records loaded.'}
                  </td>
                </tr>
              ) : (
                records.map((record) => (
                  <tr key={`${record.name}-${record.type}-${record.value}`} className="border-t border-white/[0.06]">
                    <td className="py-4 text-slate-200">{record.name}</td>
                    <td className="text-slate-400">{record.type}</td>
                    <td className="font-mono text-xs text-slate-300">{record.value}</td>
                    <td className="text-slate-400">{record.ttl}s</td>
                    <td className="text-right">
                      <button
                        aria-label={`Delete ${record.name}`}
                        onClick={() => remove(record)}
                        className="text-slate-500 hover:text-red-300"
                      >
                        <Trash2 className="size-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

function CachePage({
  api,
  token,
  status,
  metrics,
  onRefresh,
}: {
  api: string
  token: string
  status: StatusPayload | null
  metrics: Record<string, number>
  onRefresh: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [cacheInfo, setCacheInfo] = useState<CachePayload | null>(null)

  const vs = viewStatus(status)
  const entries =
    cacheInfo?.entries ??
    cacheInfo?.size ??
    vs?.cache.entries ??
    status?.cache_entries ??
    metrics['powerdns_cache_entries'] ??
    0
  const capacity =
    cacheInfo?.capacity ??
    cacheInfo?.max ??
    vs?.cache.capacity ??
    status?.cache_capacity ??
    metrics['powerdns_cache_capacity'] ??
    0
  const hits = metrics['powerdns_cache_hits_total'] ?? 0
  const stale = metrics['powerdns_cache_stale_hits_total'] ?? 0
  const queries = metricSum(metrics, 'powerdns_queries_total')
  const effective = queries > 0 ? (((hits + stale) / queries) * 100).toFixed(1) : '—'

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const res = await apiFetch(api, '/api/v1/admin/cache', token)
        const data = await res.json()
        if (!cancelled) setCacheInfo(data)
      } catch {
        /* optional endpoint */
      }
    })()
    return () => {
      cancelled = true
    }
  }, [api, token])

  const action = async (path: string) => {
    setBusy(true)
    setMessage('')
    try {
      await apiFetch(api, path, token, { method: 'POST' })
      setMessage('Request completed.')
      onRefresh()
    } catch (e) {
      setMessage(`Failed: ${e instanceof Error ? e.message : 'API error'}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <Header title="Cache" subtitle="Occupancy and invalidation via /api/v1/admin/cache and flush/refresh." />
      {message && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-200">{message}</div>
      )}
      <Card>
        <div className="grid gap-4 md:grid-cols-3">
          {[
            ['Entries', entries.toLocaleString()],
            ['Capacity', capacity ? capacity.toLocaleString() : '—'],
            ['Effective hit rate', effective === '—' ? '—' : `${effective}%`],
          ].map(([a, b]) => (
            <div key={a} className="border-b border-white/[0.06] pb-4 md:border-b-0 md:border-r md:pb-0 md:pr-4 last:border-0">
              <p className="text-xs text-slate-500">{a}</p>
              <p className="mt-2 text-2xl font-semibold text-white">{b}</p>
            </div>
          ))}
        </div>
        <div className="mt-6 flex flex-wrap gap-3">
          <Button disabled={busy} onClick={() => action('/api/v1/admin/cache/flush')}>
            Flush cache
          </Button>
          <Button disabled={busy} onClick={() => action('/api/v1/admin/cache/refresh')}>
            Refresh (prefetch trigger)
          </Button>
          <Button disabled={busy} onClick={onRefresh}>
            Reload stats
          </Button>
        </div>
        <p className="mt-4 text-[11px] text-slate-600">
          Flush: POST /api/v1/admin/cache/flush · Refresh: POST /api/v1/admin/cache/refresh · optional ?name=&amp;type=
        </p>
      </Card>
    </div>
  )
}

function IncidentsPage({
  incidents,
  loading,
  error,
  onRefresh,
  instanceName,
}: {
  incidents: IncidentItem[]
  loading: boolean
  error: string
  onRefresh: () => void
  instanceName: string
}) {
  const [acknowledged, setAcknowledged] = useState<string[]>([])
  const [filter, setFilter] = useState<'all' | 'critical' | 'warning' | 'active'>('active')

  const idFor = (item: IncidentItem, index: number) => {
    if (item.id) return String(item.id)
    const kind = String(item.kind || item.type || 'inc')
    const path = String(item.path || '')
    const endpoint = String(item.endpoint || '')
    return `${kind}:${path}:${endpoint}:${index}`
  }

  const enriched = incidents.map((item, index) => {
    const meta = incidentMeta(item)
    const id = idFor(item, index)
    return { item, meta, id, index }
  })

  const criticalCount = enriched.filter((e) => e.meta.severity === 'critical' && !acknowledged.includes(e.id)).length
  const warningCount = enriched.filter((e) => e.meta.severity === 'warning' && !acknowledged.includes(e.id)).length
  const activeCount = enriched.filter((e) => !acknowledged.includes(e.id)).length

  const visible = enriched.filter((e) => {
    if (filter === 'all') return true
    if (filter === 'active') return !acknowledged.includes(e.id)
    if (filter === 'critical') return e.meta.severity === 'critical' && !acknowledged.includes(e.id)
    if (filter === 'warning') return e.meta.severity === 'warning' && !acknowledged.includes(e.id)
    return true
  })

  const field = (item: IncidentItem, ...keys: string[]) => {
    for (const k of keys) {
      const v = item[k]
      if (v !== undefined && v !== null && String(v) !== '') return String(v)
    }
    return null
  }

  return (
    <div className="flex flex-col gap-5">
      <Header
        title="Incidents"
        subtitle={`Passive health classifications for ${instanceName} — observation only; does not change routing by itself.`}
      />
      {error && <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-200">{error}</div>}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Card>
          <p className="text-xs text-slate-500">Active</p>
          <p className="mt-2 text-2xl font-semibold text-white">{activeCount}</p>
          <p className="mt-1 text-[11px] text-slate-600">{incidents.length} reported by API</p>
        </Card>
        <Card>
          <p className="text-xs text-slate-500">Critical</p>
          <p className="mt-2 text-2xl font-semibold text-red-300">{criticalCount}</p>
          <p className="mt-1 text-[11px] text-slate-600">upstream_unavailable and critical severity</p>
        </Card>
        <Card>
          <p className="text-xs text-slate-500">Warnings</p>
          <p className="mt-2 text-2xl font-semibold text-amber-300">{warningCount}</p>
          <p className="mt-1 text-[11px] text-slate-600">degradation / latency / error spike</p>
        </Card>
        <Card>
          <p className="text-xs text-slate-500">Acknowledged (local)</p>
          <p className="mt-2 text-2xl font-semibold text-slate-300">{acknowledged.length}</p>
          <p className="mt-1 text-[11px] text-slate-600">session only — not sent to API</p>
        </Card>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2">
          {(
            [
              ['active', 'Active'],
              ['critical', 'Critical'],
              ['warning', 'Warnings'],
              ['all', 'All'],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              className={`rounded-md border px-3 py-1.5 text-xs transition ${
                filter === key
                  ? 'border-red-400/40 bg-red-500/10 text-red-200'
                  : 'border-white/10 text-slate-400 hover:bg-white/[0.04]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          {acknowledged.length > 0 && (
            <Button onClick={() => setAcknowledged([])}>Clear acknowledgements</Button>
          )}
          <Button onClick={onRefresh} disabled={loading}>
            <span className="flex items-center gap-2">
              <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </span>
          </Button>
        </div>
      </div>

      <div className="flex flex-col gap-3">
        {visible.length === 0 ? (
          <Card>
            <p className="text-sm text-slate-500">
              {loading
                ? 'Loading incidents…'
                : filter === 'active' && incidents.length > 0
                  ? 'All reported incidents are acknowledged locally.'
                  : 'No incidents in this view. Power-DNS only emits these from health snapshots.'}
            </p>
          </Card>
        ) : (
          visible.map(({ item, meta, id }) => {
            const endpoint = field(item, 'endpoint', 'server', 'target')
            const path = field(item, 'path', 'transport')
            const state = field(item, 'state')
            const detail =
              field(item, 'detail', 'message', 'description', 'summary') ||
              meta.blurb ||
              'See fields below for endpoint context.'
            const title = field(item, 'title') || meta.label
            const extraKeys = Object.entries(item).filter(
              ([k]) =>
                !['id', 'kind', 'type', 'severity', 'title', 'detail', 'message', 'description', 'summary', 'endpoint', 'path', 'state', 'transport', 'server', 'target'].includes(
                  k
                )
            )
            return (
              <Card key={id} className={acknowledged.includes(id) ? 'opacity-55' : ''}>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="flex gap-3">
                    <div
                      className={`mt-1.5 size-2.5 shrink-0 rounded-full ${
                        meta.severity === 'critical' ? 'bg-red-500' : meta.severity === 'info' ? 'bg-sky-400' : 'bg-amber-400'
                      }`}
                    />
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wider ${
                            meta.severity === 'critical'
                              ? 'bg-red-500/15 text-red-300'
                              : 'bg-amber-500/15 text-amber-200'
                          }`}
                        >
                          {meta.severity}
                        </span>
                        <span className="rounded-full border border-white/10 px-2 py-0.5 font-mono text-[10px] text-slate-400">
                          {meta.kind}
                        </span>
                        {path && (
                          <span className="rounded-full bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-wider text-slate-400">
                            {path}
                          </span>
                        )}
                        {state && (
                          <span className="text-[11px] uppercase tracking-wider text-slate-500">{state}</span>
                        )}
                      </div>
                      <h2 className="mt-2 text-base font-medium text-white">{title}</h2>
                      {endpoint && (
                        <p className="mt-1 font-mono text-xs text-slate-400 break-all">{endpoint}</p>
                      )}
                      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{detail}</p>
                      {meta.blurb && detail !== meta.blurb && (
                        <p className="mt-2 max-w-3xl text-[11px] leading-5 text-slate-600">{meta.blurb}</p>
                      )}
                      {extraKeys.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-500">
                          {extraKeys.slice(0, 8).map(([k, v]) => (
                            <span key={k}>
                              <span className="text-slate-600">{k} </span>
                              <span className="font-mono text-slate-400">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                  <Button
                    disabled={acknowledged.includes(id)}
                    onClick={() => setAcknowledged((c) => (c.includes(id) ? c : [...c, id]))}
                  >
                    {acknowledged.includes(id) ? 'Acknowledged' : 'Acknowledge'}
                  </Button>
                </div>
              </Card>
            )
          })
        )}
      </div>

      <Card className="border-dashed">
        <h2 className="text-sm font-medium text-slate-300">Incident kinds (from Power-DNS)</h2>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {Object.entries(INCIDENT_KIND_INFO).map(([kind, info]) => (
            <div key={kind} className="rounded-md border border-white/[0.06] px-3 py-2">
              <div className="flex items-center gap-2">
                <span
                  className={`size-1.5 rounded-full ${info.severity === 'critical' ? 'bg-red-500' : 'bg-amber-400'}`}
                />
                <span className="font-mono text-[11px] text-slate-400">{kind}</span>
              </div>
              <p className="mt-1 text-xs text-slate-500">{info.blurb}</p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[11px] text-slate-600">
          Source: <code className="text-slate-500">GET /api/v1/health/incidents</code> — acknowledge is local to this browser only.
        </p>
      </Card>
    </div>
  )
}

function MetricsPage({ metrics, connection }: { metrics: Record<string, number>; connection: string }) {
  const d = deriveMetrics(metrics)

  const composition = [
    ['Cache (strategy)', d.queries.cache, 'bg-emerald-500/80'],
    ['DoH', d.queries.doh, 'bg-sky-500/70'],
    ['DoT', d.queries.dot, 'bg-violet-500/70'],
    ['Plain', d.queries.plain, 'bg-amber-500/70'],
    ['Failed', d.queries.failed, 'bg-red-500'],
  ].filter(([, v]) => true)

  const stream: [string, string, string][] = [
    ['Queries total', d.queries.total.toLocaleString(), 'sum powerdns_queries_total{strategy=*}'],
    ['  · cache', d.queries.cache.toLocaleString(), 'strategy="cache"'],
    ['  · doh', d.queries.doh.toLocaleString(), 'strategy="doh"'],
    ['  · dot', d.queries.dot.toLocaleString(), 'strategy="dot"'],
    ['  · plain', d.queries.plain.toLocaleString(), 'strategy="plain"'],
    ['  · failed', d.queries.failed.toLocaleString(), 'strategy="failed"'],
    ['Cache hits (fresh)', d.cache.hits.toLocaleString(), 'powerdns_cache_hits_total'],
    ['Cache stale hits', d.cache.staleHits.toLocaleString(), 'powerdns_cache_stale_hits_total'],
    ['Cache misses', d.cache.misses.toLocaleString(), 'expired + not_found'],
    ['Fresh hit rate', pct(d.cache.freshRate), 'powerdns_cache_hit_rate'],
    ['Effective hit rate', pct(d.cache.effectiveRate), 'powerdns_cache_effective_hit_rate'],
    ['Prefetch protected hits', d.cache.prefetchProtectedHits.toLocaleString(), 'powerdns_cache_prefetch_protected_hits_total'],
    ['Upstream calls', d.upstream.callsTotal.toLocaleString(), 'powerdns_upstream_calls_total'],
    ['Upstream coalesced', d.upstream.coalescedTotal.toLocaleString(), 'powerdns_upstream_coalesced_total'],
    ['Poisoned answers', d.poison.toLocaleString(), 'powerdns_poisoned_answers_total'],
    ['Cache entries', `${d.cache.entries} / ${d.cache.capacity || '—'}`, 'powerdns_cache_entries'],
    ['Uptime', formatUptime(d.uptimeSec), `powerdns_uptime_seconds (${d.uptimeSec}s)`],
  ]

  // Endpoint table from metrics (complements health API)
  const endpoints: { path: string; endpoint: string; requests: number; failures: number; ewma: number; state: string }[] = []
  const stateByKey: Record<string, string> = {}
  for (const [k, v] of Object.entries(metrics)) {
    if (!k.startsWith('powerdns_upstream_endpoint_state{') || v !== 1) continue
    const path = labelValue(k, 'path') || '?'
    const endpoint = labelValue(k, 'endpoint') || '?'
    const state = labelValue(k, 'state') || '?'
    stateByKey[`${path}|${endpoint}`] = state
  }
  const seen = new Set<string>()
  for (const [k, v] of Object.entries(metrics)) {
    if (!k.startsWith('powerdns_upstream_endpoint_requests_total{')) continue
    const path = labelValue(k, 'path') || '?'
    const endpoint = labelValue(k, 'endpoint') || '?'
    const id = `${path}|${endpoint}`
    if (seen.has(id)) continue
    seen.add(id)
    const failures = metrics[`powerdns_upstream_endpoint_failures_total{path="${path}",endpoint="${endpoint}"}`] ?? 0
    const ewma = metrics[`powerdns_upstream_endpoint_latency_ewma_ms{path="${path}",endpoint="${endpoint}"}`] ?? 0
    endpoints.push({
      path,
      endpoint,
      requests: v,
      failures,
      ewma,
      state: stateByKey[id] || 'unknown',
    })
  }
  endpoints.sort((a, b) => a.path.localeCompare(b.path) || b.requests - a.requests)

  return (
    <div className="flex flex-col gap-5">
      <Header title="Metrics" subtitle="Live parse of GET /metrics — same series Grafana scrapes." />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ['Queries', d.queries.total.toLocaleString(), `${d.queries.failed.toLocaleString()} failed · uptime ${formatUptime(d.uptimeSec)}`],
          ['Effective cache', pct(d.cache.effectiveRate), `${d.cache.hits.toLocaleString()} fresh · ${d.cache.staleHits.toLocaleString()} stale`],
          ['Upstream calls', d.upstream.callsTotal.toLocaleString(), `${d.upstream.coalescedTotal.toLocaleString()} coalesced`],
          ['Poison rejects', d.poison.toLocaleString(), d.poison ? 'plain-path banned answers' : 'none'],
        ].map(([label, value, detail]) => (
          <Card key={label} className="relative overflow-hidden">
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-red-400/60 to-transparent" />
            <p className="text-xs text-slate-500">{label}</p>
            <p className="mt-3 text-3xl font-semibold text-white">{value}</p>
            <p className="mt-1 text-[11px] text-slate-600">{detail}</p>
          </Card>
        ))}
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.2fr_1fr]">
        <Card>
          <div className="flex items-start justify-between">
            <div>
              <h2 className="font-medium text-white">Strategy mix</h2>
              <p className="mt-1 text-xs text-slate-500">Which resolution strategy answered the query.</p>
            </div>
            <Activity className="size-4 text-slate-600" />
          </div>
          <div className="mt-7 flex flex-col gap-4">
            {composition.map(([label, value, color]) => {
              const n = Number(value)
              const percent = d.queries.total > 0 ? (n / d.queries.total) * 100 : 0
              return (
                <div key={String(label)}>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300">{String(label)}</span>
                    <span className="font-mono text-slate-500">
                      {n.toLocaleString()} · {percent.toFixed(1)}%
                    </span>
                  </div>
                  <div className="mt-2 h-2 overflow-hidden rounded-full bg-white/[0.06]">
                    <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.max(percent, percent > 0 ? 0.5 : 0)}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </Card>
        <Card>
          <div className="flex items-start justify-between">
            <div>
              <h2 className="font-medium text-white">Cache efficiency</h2>
              <p className="mt-1 text-xs text-slate-500">Fresh gauge + effective (fresh+stale) gauge.</p>
            </div>
            <Gauge className="size-4 text-slate-600" />
          </div>
          <div className="mt-6 flex items-center gap-6">
            <div
              className="relative flex size-32 items-center justify-center rounded-full"
              style={{
                background: `conic-gradient(#34d399 0 ${d.cache.freshRate * 100}%, #64748b ${d.cache.freshRate * 100}% ${d.cache.effectiveRate * 100}%, #2b3038 ${d.cache.effectiveRate * 100}% 100%)`,
              }}
            >
              <div className="flex size-24 flex-col items-center justify-center rounded-full bg-[#15181d]">
                <span className="text-2xl font-semibold text-white">{pct(d.cache.effectiveRate)}</span>
                <span className="text-[10px] text-slate-600">effective</span>
              </div>
            </div>
            <div className="flex flex-col gap-3 text-xs">
              <span className="flex items-center gap-2 text-slate-300">
                <Dot /> Fresh <strong>{pct(d.cache.freshRate)}</strong>
              </span>
              <span className="flex items-center gap-2 text-slate-400">
                <Dot tone="neutral" /> Stale share{' '}
                <strong>
                  {d.queries.total > 0 ? `${((d.cache.staleHits / d.queries.total) * 100).toFixed(1)}%` : '—'}
                </strong>
              </span>
              <span className="text-slate-500">
                Misses {d.cache.misses.toLocaleString()} (expired {d.cache.missesExpired.toLocaleString()} · not found{' '}
                {d.cache.missesNotFound.toLocaleString()})
              </span>
              <span className="text-slate-500">
                Prefetch protected {d.cache.prefetchProtectedHits.toLocaleString()}
              </span>
            </div>
          </div>
        </Card>
      </div>

      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-medium text-white">Upstream path latency (avg)</h2>
            <p className="mt-1 text-xs text-slate-500">histogram sum / count per path — includes failures.</p>
          </div>
        </div>
        <div className="mt-5 grid gap-4 sm:grid-cols-3">
          {[
            ['DoH', d.upstream.latencyAvgDoh, d.upstream.callsDoh, d.upstream.coalescedDoh],
            ['DoT', d.upstream.latencyAvgDot, d.upstream.callsDot, d.upstream.coalescedDot],
            ['Plain', d.upstream.latencyAvgPlain, d.upstream.callsPlain, d.upstream.coalescedPlain],
          ].map(([name, avg, calls, coal]) => (
            <div key={String(name)} className="tile-sm p-4">
              <p className="text-xs text-slate-500">{name}</p>
              <p className="mt-2 text-xl font-semibold text-white">
                {Number(avg) > 0 ? `${Number(avg).toFixed(0)} ms` : '—'}
              </p>
              <p className="mt-1 text-[11px] text-slate-600">
                {Number(calls).toLocaleString()} calls · {Number(coal).toLocaleString()} coalesced
              </p>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-medium text-white">Per-endpoint (from metrics)</h2>
            <p className="mt-1 text-xs text-slate-500">
              powerdns_upstream_endpoint_* — requests, failures, EWMA, active state.
            </p>
          </div>
          <span className="flex items-center gap-2 text-[10px] uppercase tracking-widest text-slate-500">
            <Dot tone={connection === 'live' ? 'good' : 'bad'} /> {connection === 'live' ? 'live' : 'offline'}
          </span>
        </div>
        <div className="mt-5 overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="text-[10px] uppercase tracking-widest text-slate-600">
              <tr>
                <th className="pb-3">Path</th>
                <th>Endpoint</th>
                <th>State</th>
                <th>EWMA</th>
                <th>Requests</th>
                <th>Failures</th>
                <th>Fail %</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-500">
                    No endpoint series in /metrics yet.
                  </td>
                </tr>
              ) : (
                endpoints.map((e) => {
                  const ratio = e.requests > 0 ? ((e.failures / e.requests) * 100).toFixed(1) : '0.0'
                  return (
                    <tr key={`${e.path}-${e.endpoint}`} className="border-t border-white/[0.06]">
                      <td className="py-3 uppercase text-slate-500">{e.path}</td>
                      <td className="font-mono text-xs text-slate-300">{e.endpoint}</td>
                      <td className={e.state === 'healthy' ? 'text-emerald-300' : 'text-red-300'}>
                        <span className="flex items-center gap-2">
                          <Dot tone={stateTone(e.state)} />
                          {e.state}
                        </span>
                      </td>
                      <td className="text-slate-300">{e.ewma ? `${e.ewma.toFixed(0)} ms` : '—'}</td>
                      <td className="text-slate-300">{e.requests.toLocaleString()}</td>
                      <td className="text-red-300">{e.failures.toLocaleString()}</td>
                      <td className="text-slate-400">{ratio}%</td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-medium text-white">Metric stream</h2>
            <p className="mt-1 text-xs text-slate-500">Derived values used by this dashboard.</p>
          </div>
        </div>
        <div className="mt-5 flex flex-col gap-2">
          {stream.map(([label, value, name]) => (
            <div key={name + label} className="flex items-center justify-between border-b border-white/[0.06] py-2 last:border-0">
              <div>
                <p className="text-sm text-slate-300">{label}</p>
                <p className="font-mono text-[10px] text-slate-600">{name}</p>
              </div>
              <span className="font-mono text-sm text-white">{value}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}

export default function Page() {
  const [active, setActive] = useState<PageKey>('Overview')
  const [instances, setInstances] = useState<PowerDnsInstance[]>([
    { id: 'default', name: 'Local', url: 'http://127.0.0.1:8000', token: '' },
  ])
  const [activeId, setActiveId] = useState('default')
  const [settings, setSettings] = useState(false)
  const [editDraft, setEditDraft] = useState<PowerDnsInstance | null>(null)
  const [connection, setConnection] = useState<'checking' | 'live' | 'offline'>('checking')
  const [lastChecked, setLastChecked] = useState('')
  const [upstreams, setUpstreams] = useState<UpstreamRow[]>([])
  const [incidents, setIncidents] = useState<IncidentItem[]>([])
  const [metrics, setMetrics] = useState<Record<string, number>>({})
  const [status, setStatus] = useState<StatusPayload | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [upstreamsError, setUpstreamsError] = useState('')
  const [incidentsError, setIncidentsError] = useState('')
  const [loadingUpstreams, setLoadingUpstreams] = useState(false)
  const [loadingIncidents, setLoadingIncidents] = useState(false)
  const [mobile, setMobile] = useState(false)
  // per-instance connection cache for the switcher
  const [instanceStatus, setInstanceStatus] = useState<Record<string, 'live' | 'offline' | 'checking' | 'unknown'>>({})

  const current = instances.find((i) => i.id === activeId) || instances[0]
  const api = current?.url || 'http://127.0.0.1:8000'
  const token = current?.token || ''

  useEffect(() => {
    const { instances: loaded, activeId: id } = loadInstances()
    setInstances(loaded)
    setActiveId(id)
  }, [])

  const selectInstance = (id: string) => {
    setActiveId(id)
    persistInstances(instances, id)
    // clear stale data while switching
    setUpstreams([])
    setIncidents([])
    setMetrics({})
    setStatus(null)
    setStatusError(null)
    setConnection('checking')
  }

  const saveInstances = (next: PowerDnsInstance[], nextActive: string) => {
    setInstances(next)
    setActiveId(nextActive)
    persistInstances(next, nextActive)
  }

  const checkConnection = useCallback(async () => {
    setConnection('checking')
    setInstanceStatus((s) => ({ ...s, [activeId]: 'checking' }))
    try {
      await apiFetch(api, '/healthz', token)
      setConnection('live')
      setInstanceStatus((s) => ({ ...s, [activeId]: 'live' }))
      setLastChecked(new Date().toLocaleTimeString())
      return true
    } catch {
      try {
        await apiFetch(api, '/metrics', token)
        setConnection('live')
        setInstanceStatus((s) => ({ ...s, [activeId]: 'live' }))
        setLastChecked(new Date().toLocaleTimeString())
        return true
      } catch {
        setConnection('offline')
        setInstanceStatus((s) => ({ ...s, [activeId]: 'offline' }))
        return false
      }
    }
  }, [api, token, activeId])

  const loadUpstreams = useCallback(async () => {
    setLoadingUpstreams(true)
    setUpstreamsError('')
    try {
      const res = await apiFetch(api, '/api/v1/health/upstreams', token)
      const data = await res.json()
      if (Array.isArray(data)) {
        setUpstreams(
          data.map((item: UpstreamRow) => ({
            path: item.path || 'unknown',
            endpoint: item.endpoint || 'unknown',
            state: item.state || 'unknown',
            score: item.score,
            ewma_latency_ms: item.ewma_latency_ms,
            requests: item.requests,
            successes: item.successes,
            failures: item.failures,
          }))
        )
      } else {
        setUpstreamsError('Unexpected upstreams response shape')
      }
    } catch (e) {
      setUpstreamsError(e instanceof Error ? e.message : 'Failed to load upstreams')
    } finally {
      setLoadingUpstreams(false)
    }
  }, [api, token])

  const loadIncidents = useCallback(async () => {
    setLoadingIncidents(true)
    setIncidentsError('')
    try {
      const res = await apiFetch(api, '/api/v1/health/incidents', token)
      const data = await res.json()
      setIncidents(Array.isArray(data) ? data : data?.incidents && Array.isArray(data.incidents) ? data.incidents : [])
    } catch (e) {
      setIncidentsError(e instanceof Error ? e.message : 'Failed to load incidents')
    } finally {
      setLoadingIncidents(false)
    }
  }, [api, token])

  const loadMetrics = useCallback(async () => {
    try {
      const res = await apiFetch(api, '/metrics', token)
      const text = await res.text()
      setMetrics(parsePrometheus(text))
    } catch {
      /* metrics optional */
    }
  }, [api, token])

  const loadStatus = useCallback(async () => {
    try {
      const res = await fetch(proxyUrl('/api/v1/admin/status'), {
        headers: {
          ...authHeaders(token),
          'X-PowerDNS-Base': baseUrl(api),
        },
        signal: AbortSignal.timeout(12000),
      })
      if (res.status === 404) {
        setStatus(null)
        setStatusError(
          '404 Not Found — admin endpoints are disabled or admin_path_prefix does not match /api/v1/admin'
        )
        return
      }
      if (res.status === 401 || res.status === 403) {
        setStatus(null)
        setStatusError(
          `${res.status} ${res.statusText} — set the instance bearer token to match security.admin_auth_token`
        )
        return
      }
      if (!res.ok) {
        setStatus(null)
        setStatusError(`${res.status} ${res.statusText}`)
        return
      }
      const data = await res.json()
      setStatus(data)
      setStatusError(null)
    } catch (e) {
      setStatus(null)
      setStatusError(e instanceof Error ? e.message : 'Failed to load admin status')
    }
  }, [api, token])

  const refreshAll = useCallback(async () => {
    const ok = await checkConnection()
    if (!ok) return
    await Promise.all([loadUpstreams(), loadIncidents(), loadMetrics(), loadStatus()])
  }, [checkConnection, loadUpstreams, loadIncidents, loadMetrics, loadStatus])

  useEffect(() => {
    refreshAll()
    const id = window.setInterval(refreshAll, 30000)
    return () => window.clearInterval(id)
  }, [refreshAll])

  // Probe other instances in background for the switcher dots
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      for (const inst of instances) {
        if (inst.id === activeId) continue
        try {
          await apiFetch(inst.url, '/healthz', inst.token)
          if (!cancelled) setInstanceStatus((s) => ({ ...s, [inst.id]: 'live' }))
        } catch {
          try {
            await apiFetch(inst.url, '/metrics', inst.token)
            if (!cancelled) setInstanceStatus((s) => ({ ...s, [inst.id]: 'live' }))
          } catch {
            if (!cancelled) setInstanceStatus((s) => ({ ...s, [inst.id]: 'offline' }))
          }
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [instances, activeId])

  const openNewInstance = () => {
    setEditDraft({
      id: newInstanceId(),
      name: `Instance ${instances.length + 1}`,
      url: 'http://127.0.0.1:8000',
      token: '',
    })
  }

  const saveDraft = () => {
    if (!editDraft) return
    const normalized: PowerDnsInstance = {
      ...editDraft,
      name: editDraft.name.trim() || 'Unnamed',
      url: editDraft.url.trim().replace(/\/$/, '') || 'http://127.0.0.1:8000',
      token: editDraft.token,
    }
    const exists = instances.some((i) => i.id === normalized.id)
    const next = exists ? instances.map((i) => (i.id === normalized.id ? normalized : i)) : [...instances, normalized]
    const nextActive = exists ? activeId : normalized.id
    saveInstances(next, nextActive)
    setEditDraft(null)
    setSettings(false)
  }

  const deleteInstance = (id: string) => {
    if (instances.length <= 1) return
    const next = instances.filter((i) => i.id !== id)
    const nextActive = activeId === id ? next[0].id : activeId
    saveInstances(next, nextActive)
    if (editDraft?.id === id) setEditDraft(null)
  }

  const content = useMemo(() => {
    if (active === 'Overview') {
      return (
        <OverviewPremium
          setPage={setActive}
          connection={connection}
          status={status}
          statusError={statusError}
          onRetryStatus={loadStatus}
          metrics={metrics}
          upstreams={upstreams}
          incidents={incidents}
          lastChecked={lastChecked}
        />
      )
    }
    if (active === 'Upstreams') {
      return (
        <Upstreams
          api={api}
          token={token}
          upstreams={upstreams}
          loading={loadingUpstreams}
          error={upstreamsError}
          onRefresh={loadUpstreams}
        />
      )
    }
    if (active === 'Records') return <Records api={api} token={token} />
    if (active === 'Metrics') return <MetricsPage metrics={metrics} connection={connection} />
    if (active === 'Incidents') {
      return (
        <IncidentsPage
          incidents={incidents}
          loading={loadingIncidents}
          error={incidentsError}
          onRefresh={loadIncidents}
          instanceName={current?.name || api}
        />
      )
    }
    return (
      <CachePage
        api={api}
        token={token}
        status={status}
        metrics={metrics}
        onRefresh={() => {
          loadMetrics()
          loadStatus()
        }}
      />
    )
  }, [
    active,
    api,
    token,
    connection,
    status,
    statusError,
    metrics,
    upstreams,
    incidents,
    lastChecked,
    loadingUpstreams,
    upstreamsError,
    loadingIncidents,
    incidentsError,
    loadUpstreams,
    loadIncidents,
    loadMetrics,
    loadStatus,
    current?.name,
  ])

  const statusBanner =
    connection === 'live'
      ? `Live · ${current?.name || 'instance'} · ${api}`
      : connection === 'checking'
        ? 'Checking API…'
        : `Unreachable · ${current?.name || ''} · ${api}`

  return (
    <main className="relative min-h-screen bg-bg text-fg">
      <div className="pointer-events-none fixed inset-0 bg-ambient" aria-hidden />
      <div className="pointer-events-none fixed inset-0 bg-grid" aria-hidden />

      <div
        className={`glass-chip fixed bottom-4 right-4 z-50 flex max-w-[min(100vw-2rem,28rem)] items-center gap-2 rounded-lg px-3 py-2 text-xs ${
          connection === 'live'
            ? 'text-ok'
            : connection === 'checking'
              ? 'text-warn'
              : 'text-danger'
        }`}
      >
        <Dot tone={connection === 'live' ? 'good' : connection === 'checking' ? 'warn' : 'bad'} />
        <span className="truncate text-fg">{statusBanner}</span>
      </div>

      {mobile && (
        <button
          aria-label="Close menu"
          className="fixed inset-0 z-20 bg-black/40 backdrop-blur-sm lg:hidden"
          onClick={() => setMobile(false)}
        />
      )}

      <div className="relative flex min-h-screen">
        <aside
          className={`glass-sidebar fixed inset-y-0 left-0 z-30 w-64 overflow-y-auto p-5 ${
            mobile ? 'block' : 'hidden'
          } lg:block`}
        >
          <div className="flex items-center gap-3">
            <div className="grid size-9 place-items-center rounded-lg bg-fg text-accent-fg">
              <Zap className="size-5 fill-current" />
            </div>
            <div>
              <p className="font-semibold tracking-tight text-fg">power-dns</p>
              <p className="text-[10px] uppercase tracking-[0.18em] text-subtle">control plane</p>
            </div>
          </div>

          <p className="mt-8 text-[10px] uppercase tracking-[0.18em] text-subtle">Instances</p>
          <div className="mt-2 flex flex-col gap-1">
            {instances.map((inst) => {
              const st = inst.id === activeId ? connection : instanceStatus[inst.id] || 'unknown'
              const tone = st === 'live' ? 'good' : st === 'offline' ? 'bad' : st === 'checking' ? 'warn' : 'neutral'
              return (
                <button
                  key={inst.id}
                  onClick={() => {
                    selectInstance(inst.id)
                    setMobile(false)
                  }}
                  className={`flex min-h-11 items-center gap-2 rounded-md px-3 py-2 text-left text-sm transition-colors duration-150 ${
                    inst.id === activeId ? 'bg-white/[0.08] text-fg' : 'text-muted hover:bg-white/[0.04] hover:text-fg'
                  }`}
                >
                  <Dot tone={tone} />
                  <span className="min-w-0 flex-1 truncate">{inst.name}</span>
                </button>
              )
            })}
            <button
              onClick={() => {
                setSettings(true)
                openNewInstance()
              }}
              className="mt-1 flex min-h-11 items-center gap-2 rounded-md px-3 py-2 text-left text-xs text-subtle hover:bg-white/[0.04] hover:text-fg"
            >
              <Plus className="size-3.5" /> Add instance
            </button>
          </div>

          <p className="mt-8 text-[10px] uppercase tracking-[0.18em] text-subtle">Operations</p>
          <nav className="mt-3 flex flex-col gap-1">
            {nav.map(({ label, icon: Icon }) => (
              <button
                key={label}
                onClick={() => {
                  setActive(label)
                  setMobile(false)
                }}
                className={`flex min-h-11 items-center gap-3 rounded-md px-3 py-2.5 text-left text-sm transition-colors duration-150 ${
                  active === label ? 'bg-white/[0.08] text-fg' : 'text-muted hover:bg-white/[0.04] hover:text-fg'
                }`}
              >
                <Icon className="size-4" />
                {label}
              </button>
            ))}
          </nav>
          <div className="mt-8 border-t border-white/[0.07] pt-5">
            <button
              onClick={() => {
                setEditDraft(null)
                setSettings(true)
              }}
              className="flex min-h-11 w-full items-center gap-3 rounded-md px-3 py-2.5 text-sm text-muted hover:bg-white/[0.04] hover:text-fg"
            >
              <Settings2 className="size-4" />
              Manage instances
            </button>
            <button
              onClick={() => refreshAll()}
              className="mt-1 flex min-h-11 w-full items-center gap-3 rounded-md px-3 py-2.5 text-sm text-muted hover:bg-white/[0.04] hover:text-fg"
            >
              <RefreshCw className="size-4" />
              Refresh all
            </button>
          </div>
          <div className="mt-8 rounded-lg border border-white/[0.08] bg-white/[0.03] p-3 text-xs text-subtle">
            <span className="flex items-center gap-2 text-fg">
              <Dot tone={connection === 'live' ? 'good' : connection === 'checking' ? 'warn' : 'bad'} />
              {current?.name || 'Instance'}
            </span>
            <p className="mt-2 break-all font-mono text-[10px] text-slate-600">{api}</p>
            <p className="mt-2">Browser uses same-origin proxy; token optional per instance.</p>
          </div>
        </aside>

        <section className="min-w-0 flex-1 lg:ml-64">
          <header className="glass-topbar sticky top-0 z-20 flex h-16 items-center justify-between px-5 sm:px-8">
            <button
              onClick={() => setMobile(!mobile)}
              className="grid size-11 place-items-center text-muted lg:hidden"
              aria-label="Open menu"
            >
              <Menu className="size-5" />
            </button>
            <p className="text-sm text-subtle">
              <span className="text-fg">{current?.name}</span>
              <span className="text-subtle"> / </span>
              {active}
            </p>
            <div className="flex items-center gap-3">
              <select
                aria-label="Active instance"
                value={activeId}
                onChange={(e) => selectInstance(e.target.value)}
                className="glass-chip hidden max-w-[12rem] rounded-md px-2 py-1.5 text-xs text-fg sm:block"
              >
                {instances.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.name}
                  </option>
                ))}
              </select>
              <Button
                onClick={() => {
                  setEditDraft(null)
                  setSettings(true)
                }}
              >
                Instances
              </Button>
              <span className="flex items-center gap-2 text-xs text-subtle">
                <Dot tone={connection === 'live' ? 'good' : connection === 'checking' ? 'warn' : 'bad'} />
                {connection === 'live' ? 'connected' : connection === 'checking' ? 'checking' : 'offline'}
              </span>
            </div>
          </header>
          <div className="mx-auto max-w-[1500px] p-5 sm:p-8">{content}</div>
        </section>
      </div>

      {settings && (
        <div role="dialog" aria-modal="true" className="fixed inset-0 z-40 grid place-items-center bg-black/50 p-5 backdrop-blur-md">
          <div className="glass-panel max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="font-semibold text-white">Power-DNS instances</h2>
                <p className="mt-1 text-xs text-slate-500">Connect multiple resolvers; switch from the sidebar.</p>
              </div>
              <button onClick={() => { setSettings(false); setEditDraft(null) }} aria-label="Close settings">
                <X className="size-4 text-slate-500" />
              </button>
            </div>

            <div className="mt-5 flex flex-col gap-2">
              {instances.map((inst) => {
                const st = inst.id === activeId ? connection : instanceStatus[inst.id] || 'unknown'
                return (
                  <div
                    key={inst.id}
                    className={`flex items-center gap-3 rounded-lg border px-3 py-3 ${
                      inst.id === activeId ? 'border-red-400/30 bg-red-500/5' : 'border-white/[0.08]'
                    }`}
                  >
                    <Dot tone={st === 'live' ? 'good' : st === 'offline' ? 'bad' : 'neutral'} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-white">{inst.name}</p>
                      <p className="truncate font-mono text-[10px] text-slate-500">{inst.url}</p>
                    </div>
                    <Button onClick={() => selectInstance(inst.id)}>Select</Button>
                    <Button
                      onClick={() =>
                        setEditDraft({ ...inst })
                      }
                    >
                      Edit
                    </Button>
                    <Button tone="danger" disabled={instances.length <= 1} onClick={() => deleteInstance(inst.id)}>
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                )
              })}
            </div>

            <div className="mt-4">
              <Button onClick={openNewInstance}>
                <span className="flex items-center gap-2">
                  <Plus className="size-3.5" /> Add instance
                </span>
              </Button>
            </div>

            {editDraft && (
              <div className="mt-6 rounded-lg border border-white/10 bg-black/20 p-4">
                <h3 className="text-sm font-medium text-white">
                  {instances.some((i) => i.id === editDraft.id) ? 'Edit instance' : 'New instance'}
                </h3>
                <label className="mt-4 block text-xs text-slate-400">
                  Display name
                  <input
                    className="mt-2 w-full rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-red-400/40"
                    value={editDraft.name}
                    onChange={(e) => setEditDraft({ ...editDraft, name: e.target.value })}
                    placeholder="Production relay"
                  />
                </label>
                <label className="mt-3 block text-xs text-slate-400">
                  API base URL
                  <input
                    className="mt-2 w-full rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-red-400/40"
                    value={editDraft.url}
                    onChange={(e) => setEditDraft({ ...editDraft, url: e.target.value })}
                    placeholder="http://192.168.1.13:8000"
                  />
                </label>
                <label className="mt-3 block text-xs text-slate-400">
                  Bearer token <span className="text-slate-600">(optional)</span>
                  <input
                    className="mt-2 w-full rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-red-400/40"
                    type="password"
                    value={editDraft.token}
                    onChange={(e) => setEditDraft({ ...editDraft, token: e.target.value })}
                    placeholder="Leave empty to omit Authorization"
                  />
                </label>
                <p className="mt-3 text-[11px] text-slate-600">
                  Requests go through <code className="text-slate-500">/api/proxy/*</code> with{' '}
                  <code className="text-slate-500">X-PowerDNS-Base</code> set to this URL (avoids CORS).
                </p>
                <div className="mt-4 flex justify-end gap-2">
                  <Button onClick={() => setEditDraft(null)}>Cancel</Button>
                  <Button onClick={saveDraft}>Save instance</Button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </main>
  )
}
