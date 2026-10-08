import type { IncomingMessage } from 'node:http'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import type { Plugin } from 'vite'
import { analyzerFromEnv } from './gateway/claudeAnalyzer.ts'
import { createMemoryRateStore, handleAnalyze } from './gateway/handler.ts'

// Dev-only: serves the same gateway handler as functions/api/analyze.ts at /api/analyze.
// The key is read from the server process environment; it is never exposed to the client bundle.
function devGateway(): Plugin {
  const rateStore = createMemoryRateStore()
  const analyzer = analyzerFromEnv(process.env)
  const readBody = (req: IncomingMessage) =>
    new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = []
      req.on('data', c => chunks.push(c))
      req.on('end', () => resolve(Buffer.concat(chunks)))
      req.on('error', reject)
    })
  return {
    name: 'cognisentry-dev-gateway',
    configureServer(server) {
      server.middlewares.use('/api/analyze', async (req, res) => {
        const body = req.method === 'POST' ? new Uint8Array(await readBody(req)) : undefined
        const headers = new Headers()
        for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v)
        const response = await handleAnalyze(new Request('http://localhost/api/analyze', { method: req.method, headers, body }), { rateStore, analyzer })
        res.statusCode = response.status
        response.headers.forEach((v, k) => res.setHeader(k, v))
        res.end(Buffer.from(await response.arrayBuffer()))
      })
    },
  }
}

export default defineConfig({ plugins: [react(), devGateway()] })
