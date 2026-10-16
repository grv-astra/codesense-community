import { BaseApiClient } from '@/lib/api';
import type { LlmSettings, LlmSettingsUpdate, LlmStatus, LlmTestResult } from '@/types/llm';

class LlmService extends BaseApiClient {
  async getSettings(): Promise<LlmSettings> {
    return this.get<LlmSettings>('api/settings/llm/');
  }

  async saveSettings(data: LlmSettingsUpdate): Promise<LlmSettings> {
    return this.put<LlmSettings>('api/settings/llm/', data);
  }

  /** Tests the given (possibly unsaved) values; the server decides whether the saved key may be reused. */
  async testConnection(data: LlmSettingsUpdate): Promise<LlmTestResult> {
    return this.post<LlmTestResult>('api/settings/llm/test/', data);
  }

  async getStatus(): Promise<LlmStatus> {
    return this.get<LlmStatus>('api/llm/status/');
  }
}

export const llmService = new LlmService();
