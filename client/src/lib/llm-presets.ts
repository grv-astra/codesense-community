import type { LlmProviderId } from '@/types/llm';

export interface LlmPreset {
  id: string;
  label: string;
  provider: LlmProviderId;
  baseUrl: string;
  modelHint: string;
  /** Runs on this machine / LAN: no consent-worthy egress to a third party in the usual setup. */
  local: boolean;
}

// Starting points only: every field stays editable, and the server re-validates the URL.
export const LLM_PRESETS: LlmPreset[] = [
  { id: 'openai', label: 'OpenAI', provider: 'openai_compatible', baseUrl: 'https://api.openai.com/v1', modelHint: 'gpt-4o-mini', local: false },
  { id: 'azure', label: 'Azure OpenAI', provider: 'azure_openai', baseUrl: 'https://YOUR-RESOURCE.openai.azure.com', modelHint: 'your deployment name', local: false },
  { id: 'anthropic', label: 'Anthropic', provider: 'anthropic', baseUrl: 'https://api.anthropic.com', modelHint: 'claude-…', local: false },
  { id: 'gemini', label: 'Google Gemini (OpenAI-compatible)', provider: 'openai_compatible', baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai', modelHint: 'gemini-…', local: false },
  { id: 'mistral', label: 'Mistral', provider: 'openai_compatible', baseUrl: 'https://api.mistral.ai/v1', modelHint: 'mistral-…', local: false },
  { id: 'groq', label: 'Groq', provider: 'openai_compatible', baseUrl: 'https://api.groq.com/openai/v1', modelHint: 'model name', local: false },
  { id: 'ollama', label: 'Ollama (this machine)', provider: 'openai_compatible', baseUrl: 'http://localhost:11434/v1', modelHint: 'llama3.1', local: true },
  { id: 'lmstudio', label: 'LM Studio (this machine)', provider: 'openai_compatible', baseUrl: 'http://localhost:1234/v1', modelHint: 'model name', local: true },
  { id: 'vllm', label: 'vLLM / other local server', provider: 'openai_compatible', baseUrl: 'http://localhost:8000/v1', modelHint: 'model name', local: true },
  { id: 'custom', label: 'Custom OpenAI-compatible endpoint', provider: 'openai_compatible', baseUrl: '', modelHint: 'model name', local: false },
];

const norm = (u: string) => u.trim().replace(/\/+$/, '').toLowerCase();

/** Which preset the saved settings correspond to (falls back to "custom"). */
export function detectPreset(provider: LlmProviderId, baseUrl: string): LlmPreset {
  const url = norm(baseUrl);
  return (
    LLM_PRESETS.find((p) => p.id !== 'custom' && p.provider === provider && norm(p.baseUrl) === url) ??
    LLM_PRESETS.find((p) => p.id === 'custom')!
  );
}

/** True for loopback / localhost URLs, where data never leaves the machine. */
export function isLoopbackUrl(baseUrl: string): boolean {
  try {
    const host = new URL(baseUrl).hostname.toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host.endsWith('.localhost');
  } catch {
    return false;
  }
}
