import { http } from './http'

export type PromptType = 'hard' | 'soft'

export type Prompt = {
  id: string
  name: string
  type: PromptType
  description: string
  templateText: string
  softConfigJson: string
  isPreset: boolean
  isActive: boolean
  createdAt: string
  updatedAt: string
}

export type Label = 'vulnerable' | 'nonVulnerable'

export type PromptMapping = {
  id: string
  promptId: string
  token: string
  label: Label
  isDefault: boolean
  createdAt: string
  updatedAt: string
}

export async function listPrompts(params?: {
  type?: PromptType
  active?: boolean
}) {
  const { data } = await http.get<Prompt[]>('/api/prompts', {
    params: params
      ? {
          ...params,
          active: params.active ? 'true' : undefined,
        }
      : undefined,
  })
  return data
}

export async function createPrompt(body: {
  name: string
  type: PromptType
  description?: string
  templateText?: string
  softConfigJson?: string
  isActive?: boolean
}) {
  const { data } = await http.post<Prompt>('/api/prompts', body)
  return data
}

export async function updatePrompt(
  id: string,
  body: Partial<{
    name: string
    type: PromptType
    description: string
    templateText: string
    softConfigJson: string
    isActive: boolean
  }>,
) {
  const { data } = await http.put<Prompt>(`/api/prompts/${id}`, body)
  return data
}

export async function deletePrompt(id: string) {
  await http.delete(`/api/prompts/${id}`)
}

export async function listPromptMappings(promptId: string) {
  const { data } = await http.get<PromptMapping[]>('/api/prompt-mappings', {
    params: { promptId },
  })
  return data
}

export async function createPromptMapping(body: {
  promptId: string
  token: string
  label: Label
  isDefault?: boolean
}) {
  const { data } = await http.post<PromptMapping>('/api/prompt-mappings', body)
  return data
}

export async function updatePromptMapping(
  id: string,
  body: Partial<{
    token: string
    label: Label
    isDefault: boolean
  }>,
) {
  const { data } = await http.put<PromptMapping>(`/api/prompt-mappings/${id}`, body)
  return data
}

export async function deletePromptMapping(id: string) {
  await http.delete(`/api/prompt-mappings/${id}`)
}

