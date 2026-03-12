import { http } from './http'

export type PreprocessRequest = {
  source: string
  filename?: string
}

export type PreprocessResponse = {
  original: {
    source: string
    lines: number
  }
  processed: {
    source: string
    lines: number
  }
  removedLines: number
  compressionRatio: number
}

export async function preprocessContract(req: PreprocessRequest) {
  const { data } = await http.post<PreprocessResponse>(
    '/api/contracts/preprocess',
    req,
  )
  return data
}

