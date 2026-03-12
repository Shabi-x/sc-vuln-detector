export async function tryParseSolidity(source: string): Promise<{
  ok: boolean
  message?: string
}> {
  const trimmed = source.trim()
  if (!trimmed) return { ok: false, message: '代码为空' }

  try {
    const parser = await import('@solidity-parser/parser')
    parser.parse(source, { tolerant: false })
    return { ok: true }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return { ok: false, message: msg }
  }
}

export function countLines(source: string) {
  if (!source) return 0
  return source.replace(/\r\n/g, '\n').split('\n').length
}

