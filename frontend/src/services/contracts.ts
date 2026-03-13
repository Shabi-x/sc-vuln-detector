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
  contractId?: string
}

export async function preprocessContract(req: PreprocessRequest) {
  const { data } = await http.post<PreprocessResponse>(
    '/api/contracts/preprocess',
    req,
  )
  return data
}

export type ContractSummary = {
  id: string
  name: string
  createdAt: string
}

export async function listContracts() {
  const { data } = await http.get<ContractSummary[]>('/api/contracts')
  return data
}

export type ContractDetail = {
  id: string
  name: string
  source: string
  processedSource: string
  originalLines: number
  processedLines: number
  removedLines: number
  compressionRatio: number
  createdAt: string
}

export async function getContract(id: string) {
  const { data } = await http.get<ContractDetail>(`/api/contracts/${id}`)
  return data
}

export async function deleteContract(id: string) {
  await http.delete(`/api/contracts/${id}`)
}



