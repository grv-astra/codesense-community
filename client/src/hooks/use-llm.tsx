import { llmService } from '@/services/llm.service';
import type { LlmSettingsUpdate } from '@/types/llm';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

export function useLlmSettings(enabled = true) {
  return useQuery({
    queryKey: ['llm-settings'],
    queryFn: () => llmService.getSettings(),
    enabled,
  });
}

export function useSaveLlmSettings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: LlmSettingsUpdate) => llmService.saveSettings(data),
    onSuccess: (saved) => {
      queryClient.setQueryData(['llm-settings'], saved);
      queryClient.invalidateQueries({ queryKey: ['llm-status'] });
    },
  });
}

export function useTestLlmConnection() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: LlmSettingsUpdate) => llmService.testConnection(data),
    onSuccess: () => {
      // a test of the saved config updates the stored result the settings page and light show
      queryClient.invalidateQueries({ queryKey: ['llm-settings'] });
      queryClient.invalidateQueries({ queryKey: ['llm-status'] });
    },
  });
}

/** Dashboard health light: served from stored results, never triggers an LLM call. */
export function useLlmStatus() {
  return useQuery({
    queryKey: ['llm-status'],
    queryFn: () => llmService.getStatus(),
    staleTime: 30 * 1000,
    retry: false,
  });
}
