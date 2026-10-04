import assert from 'node:assert/strict'
import test from 'node:test'
import nextConfig from '../next.config.mjs'

test('CSP permits eval only in development', async () => {
  const originalNodeEnv = process.env.NODE_ENV
  try {
    Reflect.set(process.env, 'NODE_ENV', 'production')
    const productionHeaders = await nextConfig.headers?.() ?? []
    const productionCsp = productionHeaders[0].headers.find((header) => header.key === 'Content-Security-Policy')?.value ?? ''
    assert.equal(productionCsp.includes("'unsafe-eval'"), false)

    Reflect.set(process.env, 'NODE_ENV', 'development')
    const developmentHeaders = await nextConfig.headers?.() ?? []
    const developmentCsp = developmentHeaders[0].headers.find((header) => header.key === 'Content-Security-Policy')?.value ?? ''
    assert.equal(developmentCsp.includes("'unsafe-eval'"), true)
  } finally {
    if (originalNodeEnv === undefined) Reflect.deleteProperty(process.env, 'NODE_ENV')
    else Reflect.set(process.env, 'NODE_ENV', originalNodeEnv)
  }
})
