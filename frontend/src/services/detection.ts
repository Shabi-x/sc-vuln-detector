import { http } from './http'
import type { Label } from './prompts'

export type DetectTokenScore = {
  token: string
  score: number
}

export type DetectResult = {
  contractId: string
  label: Label
  confidence: number
  vulnType: string
  matchedToken: string
  topK: DetectTokenScore[]
  elapsedMs: number
}

export type DetectJobStatus = 'queued' | 'running' | 'success' | 'failed'

export type DetectJob = {
  id: string
  status: DetectJobStatus
  promptId: string
  modelId: string
  paramsJson: string
  resultJson: string
  error: string
  startedAt?: string | null
  finishedAt?: string | null
  createdAt: string
  updatedAt: string
}

export type BatchDetectResult = {
  id: string
  jobId: string
  contractId: string
  modelId: string
  promptId: string
  label: Label
  confidence: number
  vulnType: string
  matchedToken: string
  topK: DetectTokenScore[]
  elapsedMs: number
  createdAt: string
}

export async function detectOne(body: {
  contractId: string
  promptId: string
  modelId?: string
}) {
  const { data } = await http.post<{
    modelId: string
    result: DetectResult
  }>('/api/detect', body)
  return data
}

export async function createDetectBatchJob(body: {
  contractIds: string[]
  promptId: string
  modelId?: string
}) {
  const { data } = await http.post<DetectJob>('/api/detect/batch', body)
  return data
}

export async function getDetectBatchJob(id: string) {
  const { data } = await http.get<{
    job: DetectJob
    results: BatchDetectResult[]
  }>(`/api/detect/jobs/${id}`)
  return data
}
