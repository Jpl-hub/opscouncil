#!/usr/bin/env node

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'


function runtimeIdentity() {
  const runtimePath = path.join(os.homedir(), 'opscouncil-runtime.json')
  const fileConfig = fs.existsSync(runtimePath)
    ? JSON.parse(fs.readFileSync(runtimePath, 'utf8'))
    : {}
  const identity = {
    apiUrl: (process.env.OPSCOUNCIL_API_URL || fileConfig.api_url || '').replace(/\/+$/, ''),
    agentName: process.env.OPSCOUNCIL_AGENT_NAME || fileConfig.agent_name || '',
    role: process.env.OPSCOUNCIL_AGENT_ROLE || fileConfig.role || '',
    token: process.env.OPSCOUNCIL_AGENT_TOKEN || fileConfig.token || '',
  }
  const missing = Object.entries(identity)
    .filter(([, value]) => !value)
    .map(([key]) => key)
  if (missing.length) {
    throw new Error(`missing runtime identity fields: ${missing.join(', ')}`)
  }
  return identity
}


async function post(relativePath, payload, identity) {
  const response = await fetch(`${identity.apiUrl}${relativePath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-OpsCouncil-Agent-Token': identity.token,
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(30000),
  })
  const text = await response.text()
  if (!response.ok) {
    throw new Error(`callback rejected with HTTP ${response.status}: ${text}`)
  }
  return text ? JSON.parse(text) : {}
}


function parseArgs(argv) {
  const [command, collaborationId, workKey, ...rest] = argv
  if (!['claim', 'submit'].includes(command) || !/^\d+$/.test(collaborationId || '') || !workKey) {
    throw new Error(
      'usage: callback-client.mjs claim <collaboration-id> <work-key> [--lease-seconds N] | ' +
      'submit <collaboration-id> <work-key> --file result.json [--source-event-id ID]',
    )
  }
  const options = {}
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index]
    const value = rest[index + 1]
    if (!key?.startsWith('--') || value === undefined) {
      throw new Error(`invalid option: ${key || '<empty>'}`)
    }
    options[key.slice(2)] = value
  }
  return { command, collaborationId: Number(collaborationId), workKey, options }
}


async function main() {
  const identity = runtimeIdentity()
  const args = parseArgs(process.argv.slice(2))
  const basePath = `/api/collaboration/incidents/${args.collaborationId}/work/${args.workKey}`
  if (args.command === 'submit' && !args.options.file) {
    throw new Error('--file is required for submit')
  }
  const payload = args.command === 'claim'
    ? {
        role: identity.role,
        agent_name: identity.agentName,
        lease_seconds: Number(args.options['lease-seconds'] || 300),
      }
    : {
        role: identity.role,
        agent_name: identity.agentName,
        output: JSON.parse(fs.readFileSync(args.options.file, 'utf8')),
        source_event_id: args.options['source-event-id'] || null,
      }
  const result = await post(`${basePath}/${args.command}`, payload, identity)
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
}


main().catch((error) => {
  process.stderr.write(`${error.message}\n`)
  process.exitCode = 1
})
