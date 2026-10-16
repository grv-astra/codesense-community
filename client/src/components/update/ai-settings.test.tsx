import { AxiosError } from 'axios';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import AiSettings from './ai-settings';
import { llmService } from '@/services/llm.service';
import { toast } from 'sonner';
import type { LlmSettings } from '@/types/llm';

vi.mock('@/services/llm.service', () => ({
  llmService: { getSettings: vi.fn(), saveSettings: vi.fn(), testConnection: vi.fn(), getStatus: vi.fn() },
}));
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const svc = vi.mocked(llmService);
const TYPED_KEY = 'sk-test-FAKE-1234';

// user-event isn't a dependency of this repo; fireEvent covers what these tests need.
const user = {
  click: async (el: Element) => { fireEvent.click(el); },
  type: async (el: Element, value: string) => { fireEvent.change(el, { target: { value } }); },
  clear: async (el: Element) => { fireEvent.change(el, { target: { value: '' } }); },
  selectOptions: async (el: Element, value: string) => { fireEvent.change(el, { target: { value } }); },
};
const userEvent = { setup: () => user };

// consent covering verification AND mitigation advice (what enabling records while the switch is on)
const consentGiven = (over: Partial<LlmSettings['consent']> = {}): LlmSettings['consent'] =>
  ({ given: true, reports: true, host: 'api.openai.com', at: null, by: '', ...over });

const settings = (over: Partial<LlmSettings> = {}): LlmSettings => ({
  enabled: false, provider: 'openai_compatible', base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini',
  api_version: '', timeout_s: 60, max_concurrency: 2, key_set: false,
  enrich_reports: true,
  consent: { given: false, reports: false, host: '', at: null, by: '' },
  last_test: { at: null, ok: null, error: '' }, updated_at: null,
  providers: [
    { id: 'openai_compatible', label: 'OpenAI-compatible', needs_key: false, needs_api_version: false },
    { id: 'azure_openai', label: 'Azure OpenAI', needs_key: true, needs_api_version: true, default_api_version: '2024-10-21' },
    { id: 'anthropic', label: 'Anthropic', needs_key: true, needs_api_version: false },
  ],
  limits: { timeout_s: [10, 300], max_concurrency: [1, 8] },
  disclosure: {
    sent: ['The type of weakness found and the language', 'A code excerpt (up to 1800 characters)'],
    sent_for_mitigation: ['The name of the analyzer rule', "The analyzer's one-line message (up to 400 characters)"],
    not_sent: ['File names and paths'], key_note: 'Your API key is sent only to this LLM host, as its login.',
    false_positive_min_confidence: 0.8,
  },
  ...over,
});

const serverError = (message: string, status = 400) =>
  new AxiosError('failed', 'ERR_BAD_REQUEST', undefined, undefined, {
    status, statusText: 'Bad Request', headers: {}, config: {} as never, data: { error: message },
  });

function renderIt(initial: LlmSettings) {
  svc.getSettings.mockResolvedValue(initial);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><AiSettings /></QueryClientProvider>);
}

beforeEach(() => vi.clearAllMocks());

describe('AiSettings', () => {
  it('loads saved settings and never shows a key', async () => {
    renderIt(settings({ key_set: true }));
    expect(await screen.findByLabelText('Model')).toHaveValue('gpt-4o-mini');
    expect(screen.getByLabelText('Base URL')).toHaveValue('https://api.openai.com/v1');
    const key = screen.getByLabelText(/API key/);
    expect(key).toHaveValue('');
    expect(key).toHaveAttribute('type', 'password');
    expect(key).toHaveAttribute('placeholder', expect.stringContaining('saved'));
    expect(screen.getByRole('switch', { name: 'Use my LLM for scans' })).not.toBeChecked();
  });

  it('shows the server error instead of swallowing it when loading fails', async () => {
    svc.getSettings.mockRejectedValue(serverError('Connecting your own LLM is not available in this edition.', 403));
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><AiSettings /></QueryClientProvider>);
    expect(await screen.findByRole('alert')).toHaveTextContent('not available in this edition');
  });

  it('saves the form, sending a key only when one was typed', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockResolvedValue(settings({ key_set: true }));
    renderIt(settings());
    await user.type(await screen.findByLabelText(/API key/), TYPED_KEY);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(svc.saveSettings).toHaveBeenCalledTimes(1));
    expect(svc.saveSettings.mock.calls[0][0]).toMatchObject({
      provider: 'openai_compatible', base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini',
      timeout_s: 60, max_concurrency: 2, api_key: TYPED_KEY,
    });
    expect(toast.success).toHaveBeenCalled();
    // after saving, the typed key is cleared from the field
    await waitFor(() => expect(screen.getByLabelText(/API key/)).toHaveValue(''));
  });

  it('does not send api_key when the field was left blank', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockResolvedValue(settings({ key_set: true }));
    renderIt(settings({ key_set: true }));
    await user.click(await screen.findByRole('button', { name: 'Save' }));
    await waitFor(() => expect(svc.saveSettings).toHaveBeenCalled());
    expect(svc.saveSettings.mock.calls[0][0]).not.toHaveProperty('api_key');
  });

  it('shows the server\'s message when saving is rejected', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockRejectedValue(serverError('Plain http is only allowed for local or private hosts; use https for a remote host.'));
    renderIt(settings());
    await user.click(await screen.findByRole('button', { name: 'Save' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalled());
    expect(toast.error).toHaveBeenCalledWith('Could not save AI settings', {
      description: 'Plain http is only allowed for local or private hosts; use https for a remote host.',
    });
  });

  it('test connection reports success and failure', async () => {
    const user = userEvent.setup();
    renderIt(settings());
    svc.testConnection.mockResolvedValueOnce({ ok: true, latency_ms: 123, error: '' });
    await user.click(await screen.findByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Connection works (123 ms)'));

    svc.testConnection.mockResolvedValueOnce({ ok: false, latency_ms: 5, error: 'The LLM rejected the API key (HTTP 401).' });
    await user.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Connection failed', {
      description: 'The LLM rejected the API key (HTTP 401).',
    }));
  });

  it('test connection shows the server message for invalid input', async () => {
    const user = userEvent.setup();
    renderIt(settings());
    svc.testConnection.mockRejectedValue(serverError('Enter the API key to test this connection.'));
    await user.click(await screen.findByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Could not test the connection', {
      description: 'Enter the API key to test this connection.',
    }));
  });

  it('turning on requires the consent dialog, which lists what is sent and where', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockResolvedValue(settings({ enabled: true, consent: consentGiven({ at: '2026-10-14T10:00:00Z', by: 'admin1' }) }));
    renderIt(settings());
    await user.click(await screen.findByRole('switch', { name: 'Use my LLM for scans' }));

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/Send code excerpts to api\.openai\.com/)).toBeInTheDocument();
    expect(within(dialog).getByText(/leave this computer/)).toBeInTheDocument();
    expect(within(dialog).getByText('A code excerpt (up to 1800 characters)')).toBeInTheDocument();
    expect(within(dialog).getByText('File names and paths')).toBeInTheDocument();
    expect(within(dialog).getByText(/API key is sent only to this LLM host/)).toBeInTheDocument();
    expect(svc.saveSettings).not.toHaveBeenCalled();                 // nothing happens before consent

    const confirm = within(dialog).getByRole('button', { name: 'Turn on AI verification' });
    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole('checkbox'));
    expect(confirm).toBeEnabled();
    await user.click(confirm);

    await waitFor(() => expect(svc.saveSettings).toHaveBeenCalledTimes(1));
    expect(svc.saveSettings.mock.calls[0][0]).toMatchObject({ enabled: true, consent: true, base_url: 'https://api.openai.com/v1' });
  });

  it('says the excerpts stay local for a loopback URL', async () => {
    const user = userEvent.setup();
    renderIt(settings({ base_url: 'http://localhost:11434/v1' }));
    await user.click(await screen.findByRole('switch', { name: 'Use my LLM for scans' }));
    expect(await within(await screen.findByRole('dialog')).findByText(/stay local/)).toBeInTheDocument();
  });

  it('cancelling the consent dialog sends nothing', async () => {
    const user = userEvent.setup();
    renderIt(settings());
    await user.click(await screen.findByRole('switch', { name: 'Use my LLM for scans' }));
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    expect(svc.saveSettings).not.toHaveBeenCalled();
  });

  it('turning off needs no dialog', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockResolvedValue(settings());
    renderIt(settings({ enabled: true, consent: consentGiven() }));
    await user.click(await screen.findByRole('switch', { name: 'Use my LLM for scans' }));
    await waitFor(() => expect(svc.saveSettings).toHaveBeenCalledWith({ enabled: false }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('with consent already given, turning on again skips the dialog', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockResolvedValue(settings({ enabled: true }));
    renderIt(settings({ consent: consentGiven() }));
    await user.click(await screen.findByRole('switch', { name: 'Use my LLM for scans' }));
    await waitFor(() => expect(svc.saveSettings).toHaveBeenCalled());
    expect(svc.saveSettings.mock.calls[0][0]).toMatchObject({ enabled: true });
    expect(svc.saveSettings.mock.calls[0][0]).not.toHaveProperty('consent');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('warns that changing the host resets consent and the saved key, and re-asks consent', async () => {
    const user = userEvent.setup();
    renderIt(settings({ enabled: false, key_set: true, consent: consentGiven() }));
    const url = await screen.findByLabelText('Base URL');
    await user.clear(url);
    await user.type(url, 'https://llm.other.example/v1');
    expect(screen.getByRole('status')).toHaveTextContent(/turns AI verification off and removes the saved key/);
    await user.click(screen.getByRole('switch', { name: 'Use my LLM for scans' }));
    expect(await screen.findByRole('dialog')).toBeInTheDocument();    // consent is host-bound
  });

  it('picking a preset fills provider URL and keeps the model for the admin to set', async () => {
    const user = userEvent.setup();
    renderIt(settings());
    await user.selectOptions(await screen.findByLabelText('Provider'), 'anthropic');
    expect(screen.getByLabelText('Base URL')).toHaveValue('https://api.anthropic.com');
  });

  it('shows the Azure api-version field and relabels the model as a deployment', async () => {
    const user = userEvent.setup();
    renderIt(settings());
    await user.selectOptions(await screen.findByLabelText('Provider'), 'azure');
    expect(screen.getByLabelText('API version')).toBeInTheDocument();
    expect(screen.getByLabelText('Deployment name')).toBeInTheDocument();
  });

  it('shows the recorded consent and last check', async () => {
    renderIt(settings({
      enabled: true,
      consent: consentGiven({ at: '2026-10-14T10:00:00Z', by: 'admin1' }),
      last_test: { at: '2026-10-14T10:05:00Z', ok: false, error: 'The LLM rejected the API key (HTTP 401).' },
    }));
    expect(await screen.findByText(/Data sharing confirmed for/)).toHaveTextContent('api.openai.com');
    expect(screen.getByText(/Data sharing confirmed for/)).toHaveTextContent('verification and mitigation advice');
    expect(screen.getByText(/Last check/)).toHaveTextContent('failed — The LLM rejected the API key');
  });

  it('says when the consent covers verification only', async () => {
    renderIt(settings({ enabled: true, consent: consentGiven({ reports: false }), enrich_reports: false }));
    expect(await screen.findByText(/Data sharing confirmed for/)).toHaveTextContent('verification only');
  });
});

describe('AiSettings: mitigation advice switch', () => {
  const reportsSwitch = () => screen.getByRole('switch', { name: 'Also write mitigation advice' });

  it('is on by default and explains the cost and the extra data', async () => {
    renderIt(settings());
    await screen.findByLabelText('Model');
    expect(reportsSwitch()).toBeChecked();
    expect(screen.getByText(/twice the calls and tokens/)).toBeInTheDocument();
    expect(screen.getByText(/also sends the rule name/)).toBeInTheDocument();
  });

  it('sends the switch with every save, including when turned off', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockResolvedValue(settings({ enrich_reports: false }));
    renderIt(settings());
    await screen.findByLabelText('Model');
    await user.click(reportsSwitch());
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(svc.saveSettings).toHaveBeenCalled());
    expect(svc.saveSettings.mock.calls[0][0]).toMatchObject({ enrich_reports: false });
  });

  it('the consent dialog lists the extra data only while the switch is on', async () => {
    const user = userEvent.setup();
    renderIt(settings());
    await user.click(await screen.findByRole('switch', { name: 'Use my LLM for scans' }));
    let dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Also sent to write mitigation advice')).toBeInTheDocument();
    expect(within(dialog).getByText('The name of the analyzer rule')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    await user.click(reportsSwitch());                              // off
    await user.click(screen.getByRole('switch', { name: 'Use my LLM for scans' }));
    dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByText('Also sent to write mitigation advice')).not.toBeInTheDocument();
  });

  it('turning on with verification-only consent asks for confirmation of the extra data', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockResolvedValue(settings({ enabled: true, consent: consentGiven() }));
    renderIt(settings({ consent: consentGiven({ reports: false }), enrich_reports: true }));
    await user.click(await screen.findByRole('switch', { name: 'Use my LLM for scans' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Also sent to write mitigation advice')).toBeInTheDocument();
    expect(svc.saveSettings).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('checkbox'));
    await user.click(within(dialog).getByRole('button', { name: 'Turn on AI verification' }));
    await waitFor(() => expect(svc.saveSettings).toHaveBeenCalledTimes(1));
    expect(svc.saveSettings.mock.calls[0][0]).toMatchObject({ enabled: true, consent: true, enrich_reports: true });
  });

  it('turning on with the switch off needs no extra confirmation when verification consent exists', async () => {
    const user = userEvent.setup();
    svc.saveSettings.mockResolvedValue(settings({ enabled: true }));
    renderIt(settings({ consent: consentGiven({ reports: false }), enrich_reports: false }));
    await user.click(await screen.findByRole('switch', { name: 'Use my LLM for scans' }));
    await waitFor(() => expect(svc.saveSettings).toHaveBeenCalled());
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(svc.saveSettings.mock.calls[0][0]).toMatchObject({ enabled: true, enrich_reports: false });
  });

  describe('an enabled connection whose consent predates mitigation advice', () => {
    const legacy = () => settings({ enabled: true, enrich_reports: true, consent: consentGiven({ reports: false }) });

    it('shows a banner, and its button opens the confirmation dialog', async () => {
      const user = userEvent.setup();
      renderIt(legacy());
      const banner = await screen.findByText(/not confirmed yet/);
      expect(banner).toHaveTextContent(/scans verify findings but do not write mitigation advice/);
      await user.click(screen.getByRole('button', { name: 'Review and confirm' }));
      const dialog = await screen.findByRole('dialog');
      expect(within(dialog).getByText('Also sent to write mitigation advice')).toBeInTheDocument();
      expect(within(dialog).getByRole('button', { name: 'Confirm' })).toBeDisabled();
    });

    it('Save asks for the confirmation instead of sending a request the server would refuse', async () => {
      const user = userEvent.setup();
      renderIt(legacy());
      await user.click(await screen.findByRole('button', { name: 'Save' }));
      expect(await screen.findByRole('dialog')).toBeInTheDocument();
      expect(svc.saveSettings).not.toHaveBeenCalled();
    });

    it('confirming sends consent and keeps it enabled', async () => {
      const user = userEvent.setup();
      svc.saveSettings.mockResolvedValue(settings({ enabled: true, consent: consentGiven() }));
      renderIt(legacy());
      await user.click(await screen.findByRole('button', { name: 'Review and confirm' }));
      const dialog = await screen.findByRole('dialog');
      await user.click(within(dialog).getByRole('checkbox'));
      await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));
      await waitFor(() => expect(svc.saveSettings).toHaveBeenCalledTimes(1));
      expect(svc.saveSettings.mock.calls[0][0]).toMatchObject({ enabled: true, consent: true, enrich_reports: true });
      expect(toast.success).toHaveBeenCalledWith('Data sharing confirmed');
    });

    it('switching advice off removes the banner and Save goes through normally', async () => {
      const user = userEvent.setup();
      svc.saveSettings.mockResolvedValue(settings({ enabled: true, enrich_reports: false }));
      renderIt(legacy());
      await screen.findByText(/not confirmed yet/);
      await user.click(reportsSwitch());
      expect(screen.queryByText(/not confirmed yet/)).not.toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Save' }));
      await waitFor(() => expect(svc.saveSettings).toHaveBeenCalled());
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('shows no banner for a covered connection', async () => {
      renderIt(settings({ enabled: true, consent: consentGiven() }));
      await screen.findByLabelText('Model');
      expect(screen.queryByText(/not confirmed yet/)).not.toBeInTheDocument();
    });
  });
});
