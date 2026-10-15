import { NextRequest, NextResponse } from 'next/server'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const HOP_BY_HOP = new Set([
  'connection','keep-alive','proxy-authenticate','proxy-authorization',
  'te','trailers','transfer-encoding','upgrade','host','content-length',
])

function resolveUpstream(req: NextRequest): string | null {
  const header = req.headers.get('x-powerdns-base')?.trim()
  const query = req.nextUrl.searchParams.get('base')?.trim()
  const raw = header || query || 'http://127.0.0.1:8000'
  try {
    const u = new URL(raw)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    return u.origin
  } catch {
    return null
  }
}

async function proxy(req: NextRequest, pathSegments: string[]) {
  const upstream = resolveUpstream(req)
  if (!upstream) {
    return NextResponse.json({ error: 'Invalid or missing Power-DNS base URL' }, { status: 400 })
  }
  const path = pathSegments.map(encodeURIComponent).join('/')
  const search = new URLSearchParams(req.nextUrl.searchParams)
  search.delete('base')
  const qs = search.toString()
  const target = `${upstream}/${path}${qs ? `?${qs}` : ''}`

  const headers = new Headers()
  req.headers.forEach((value, key) => {
    const lower = key.toLowerCase()
    if (HOP_BY_HOP.has(lower)) return
    if (lower === 'origin' || lower === 'referer' || lower === 'x-powerdns-base') return
    headers.set(key, value)
  })

  const init: RequestInit = { method: req.method, headers, redirect: 'manual' }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = await req.arrayBuffer()
  }

  try {
    const upstreamRes = await fetch(target, init)
    const outHeaders = new Headers()
    upstreamRes.headers.forEach((value, key) => {
      if (!HOP_BY_HOP.has(key.toLowerCase())) outHeaders.set(key, value)
    })
    outHeaders.set('Cache-Control', 'no-store')
    return new NextResponse(upstreamRes.body, {
      status: upstreamRes.status,
      statusText: upstreamRes.statusText,
      headers: outHeaders,
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Upstream fetch failed'
    return NextResponse.json({ error: 'Power-DNS upstream unreachable', detail: message, target }, { status: 502 })
  }
}

type Ctx = { params: Promise<{ path: string[] }> }
export async function GET(req: NextRequest, ctx: Ctx) { return proxy(req, (await ctx.params).path || []) }
export async function POST(req: NextRequest, ctx: Ctx) { return proxy(req, (await ctx.params).path || []) }
export async function PUT(req: NextRequest, ctx: Ctx) { return proxy(req, (await ctx.params).path || []) }
export async function PATCH(req: NextRequest, ctx: Ctx) { return proxy(req, (await ctx.params).path || []) }
export async function DELETE(req: NextRequest, ctx: Ctx) { return proxy(req, (await ctx.params).path || []) }
export async function OPTIONS() {
  return new NextResponse(null, { status: 204 })
}
