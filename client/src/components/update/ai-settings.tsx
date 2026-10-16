import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Loader2, ShieldAlert } from 'lucide-react';
import { Button } from '@/components/atomic/button';
import { Card } from '@/components/atomic/card';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/atomic/dialog';
import { Input } from '@/components/atomic/input';
import { Switch } from '@/components/atomic/switch';
import { useLlmSettings, useSaveLlmSettings, useTestLlmConnection } from '@/hooks/use-llm';
import { apiErrorMessage, toastApiError } from '@/lib/api-error';
import {
  type AiFormState, buildUpdate, formFromSettings, hostOf, needsConsent, reportsUnconfirmed,
} from '@/lib/llm-form';
import { LLM_PRESETS, detectPreset, isLoopbackUrl } from '@/lib/llm-presets';
import type { LlmSettingsUpdate } from '@/types/llm';

const fieldLabel = 'mb-1 block text-sm font-medium';
const hintText = 'mt-1 text-xs text-muted-foreground';

export default function AiSettings() {
  const { data: settings, isLoading, error } = useLlmSettings();
  const save = useSaveLlmSettings();
  const test = useTestLlmConnection();

  const [form, setForm] = useState<AiFormState | null>(null);
  const [consentOpen, setConsentOpen] = useState(false);
  const [understood, setUnderstood] = useState(false);

  useEffect(() => {
    if (settings) setForm(formFromSettings(settings));
  }, [settings]);

  if (isLoading) return <Card className="p-6 text-sm text-muted-foreground">Loading AI verification settings…</Card>;
  if (error || !settings || !form) {
    return (
      <Card className="p-6 text-sm text-destructive" role="alert">
        {apiErrorMessage(error, 'AI verification settings could not be loaded.')}
      </Card>
    );
  }

  const providerInfo = settings.providers.find((p) => p.id === form.provider);
  const preset = LLM_PRESETS.find((p) => p.id === form.presetId);
  const formHost = hostOf(form.base_url);
  const savedHost = hostOf(settings.base_url);
  const hostChanged = !!savedHost && formHost !== savedHost;
  const local = isLoopbackUrl(form.base_url);
  const unconfirmed = reportsUnconfirmed(settings, form);
  const set =(patch: Partial<AiFormState>) => setForm((f) => (f ? { ...f, ...patch } : f));

  const pickPreset = (id: string) => {
    const p = LLM_PRESETS.find((x) => x.id === id);
    if (!p) return;
    set({
      presetId: id,
      provider: p.provider,
      base_url: p.baseUrl,
      api_version: p.provider === 'azure_openai' ? form.api_version || providerInfo?.default_api_version || '' : '',
    });
  };

  const run = async (data: LlmSettingsUpdate, okMessage: string, failTitle: string) => {
    try {
      await save.mutateAsync(data);
      toast.success(okMessage);
      return true;
    } catch (e) {
      toastApiError(failTitle, e);
      return false;
    }
  };

  const openConsent = () => {
    setUnderstood(false);
    setConsentOpen(true);
  };

  // Saving with mitigation advice switched on while consent does not cover it would be refused by the
  // server; ask for the confirmation instead of showing an error.
  const onSave = () => {
    if (unconfirmed) {
      openConsent();
      return Promise.resolve(false);
    }
    return run(buildUpdate(form), 'AI verification settings saved', 'Could not save AI settings');
  };

  const onTest = async () => {
    try {
      const r = await test.mutateAsync(buildUpdate(form));
      if (r.ok) toast.success(`Connection works (${r.latency_ms} ms)`);
      else toast.error('Connection failed', { description: r.error || 'The LLM did not answer.' });
    } catch (e) {
      toastApiError('Could not test the connection', e);
    }
  };

  const onToggle = (on: boolean) => {
    if (!on) {
      void run({ enabled: false }, 'AI verification turned off', 'Could not turn AI verification off');
    } else if (!needsConsent(settings, form, true)) {
      void run({ ...buildUpdate(form), enabled: true }, 'AI verification turned on', 'Could not turn AI verification on');
    } else {
      openConsent();
    }
  };

  const onConsent = async () => {
    const ok = await run(
      { ...buildUpdate(form), enabled: true, consent: true },
      settings.enabled ? 'Data sharing confirmed' : 'AI verification turned on',
      'Could not confirm data sharing',
    );
    if (ok) setConsentOpen(false);
  };

  const busy = save.isPending || test.isPending;

  return (
    <Card className="space-y-5 p-6">
      <div>
        <h2 className="text-lg font-semibold">AI verification — your own LLM</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Use a model you already have (OpenAI, Azure OpenAI, Anthropic, Gemini, Ollama, LM Studio, vLLM and others) to
          check each finding for false positives. Off by default. If a model call fails, the finding is kept and marked unverified.
        </p>
      </div>

      <div className="flex gap-2 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
        <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <p>
          When this is on, short code excerpts from your scans are sent to the LLM host you configure
          {local ? ' (this machine — they stay local)' : ''}. Nothing is sent until you turn it on and confirm.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <label htmlFor="llm-preset" className={fieldLabel}>Provider</label>
          <select
            id="llm-preset"
            value={form.presetId}
            onChange={(e) => pickPreset(e.target.value)}
            className="dark:bg-input/30 border-input h-9 w-full rounded border bg-transparent px-3 text-sm"
          >
            {LLM_PRESETS.map((p) => (
              <option key={p.id} value={p.id}>{p.label}</option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="llm-model" className={fieldLabel}>
            {form.provider === 'azure_openai' ? 'Deployment name' : 'Model'}
          </label>
          <Input id="llm-model" value={form.model} placeholder={preset?.modelHint ?? 'model name'}
            onChange={(e) => set({ model: e.target.value })} />
        </div>

        <div className="md:col-span-2">
          <label htmlFor="llm-url" className={fieldLabel}>Base URL</label>
          <Input id="llm-url" value={form.base_url} placeholder="https://…" autoComplete="off"
            onChange={(e) => set({ base_url: e.target.value, presetId: detectPreset(form.provider, e.target.value).id })} />
          <p className={hintText}>
            Remote hosts must use https. Local and private-network hosts (for example Ollama) may use http.
          </p>
          {hostChanged && (
            <p className="mt-1 text-xs text-amber-700 dark:text-amber-300" role="status">
              Changing the host turns AI verification off and removes the saved key until you confirm again.
            </p>
          )}
        </div>

        <div className={form.provider === 'azure_openai' ? '' : 'md:col-span-2'}>
          <label htmlFor="llm-key" className={fieldLabel}>
            API key{providerInfo && !providerInfo.needs_key ? ' (optional for local servers)' : ''}
          </label>
          <Input id="llm-key" type="password" autoComplete="new-password" value={form.api_key}
            placeholder={settings.key_set ? 'A key is saved — leave blank to keep it' : 'Paste your API key'}
            onChange={(e) => set({ api_key: e.target.value })} />
          <p className={hintText}>
            Stored encrypted on this machine and never shown again.
            {settings.key_set && (
              <>
                {' '}
                <button type="button" className="underline"
                  onClick={() => void run({ clear_api_key: true }, 'Saved key removed', 'Could not remove the key')}>
                  Remove saved key
                </button>
              </>
            )}
          </p>
        </div>

        {form.provider === 'azure_openai' && (
          <div>
            <label htmlFor="llm-apiver" className={fieldLabel}>API version</label>
            <Input id="llm-apiver" value={form.api_version}
              placeholder={providerInfo?.default_api_version ?? ''}
              onChange={(e) => set({ api_version: e.target.value })} />
          </div>
        )}

        <div>
          <label htmlFor="llm-timeout" className={fieldLabel}>Timeout (seconds)</label>
          <Input id="llm-timeout" type="number" inputMode="numeric" value={form.timeout_s}
            min={settings.limits.timeout_s[0]} max={settings.limits.timeout_s[1]}
            onChange={(e) => set({ timeout_s: e.target.value })} />
        </div>
        <div>
          <label htmlFor="llm-conc" className={fieldLabel}>Parallel requests</label>
          <Input id="llm-conc" type="number" inputMode="numeric" value={form.max_concurrency}
            min={settings.limits.max_concurrency[0]} max={settings.limits.max_concurrency[1]}
            onChange={(e) => set({ max_concurrency: e.target.value })} />
        </div>
      </div>

      <div className="flex items-start justify-between gap-4 rounded-md border p-3">
        <div className="text-sm">
          <label htmlFor="llm-reports" className="font-medium">Also write mitigation advice</label>
          <p className={hintText}>
            A second model call per finding writes its title, description, impact and Mitigation Steps. This uses
            about twice the calls and tokens, and also sends the rule name and the analyzer's one-line message. Off:
            findings keep the standard rule text. The advice is AI-written, so review it before applying.
          </p>
        </div>
        <Switch id="llm-reports" checked={form.enrich_reports} disabled={busy}
          onCheckedChange={(v) => set({ enrich_reports: v })} aria-label="Also write mitigation advice" />
      </div>

      {unconfirmed && (
        <div className="flex flex-wrap items-center gap-3 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200" role="status">
          <p className="flex-1">
            Mitigation advice is switched on but not confirmed yet. Until you confirm, scans verify findings but
            do not write mitigation advice.
          </p>
          <Button size="sm" variant="outline" onClick={openConsent} disabled={busy}>Review and confirm</Button>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={() => void onSave()} disabled={busy}>
          {save.isPending && <Loader2 className="animate-spin" aria-hidden="true" />}Save
        </Button>
        <Button variant="outline" onClick={() => void onTest()} disabled={busy}>
          {test.isPending && <Loader2 className="animate-spin" aria-hidden="true" />}Test connection
        </Button>
        <span className="ml-auto flex items-center gap-2 text-sm">
          <label htmlFor="llm-enabled">Use my LLM for scans</label>
          <Switch id="llm-enabled" checked={settings.enabled} disabled={busy}
            onCheckedChange={onToggle} aria-label="Use my LLM for scans" />
        </span>
      </div>

      <div className="space-y-1 text-xs text-muted-foreground">
        {settings.consent.given && (
          <p>
            Data sharing confirmed for <strong>{settings.consent.host}</strong>
            {settings.consent.at ? ` on ${new Date(settings.consent.at).toLocaleString()}` : ''}
            {' '}({settings.consent.reports ? 'verification and mitigation advice' : 'verification only'}).{' '}
            <button type="button" className="underline"
              onClick={() => void run({ consent: false }, 'Consent withdrawn; AI verification is off', 'Could not withdraw consent')}>
              Withdraw
            </button>
          </p>
        )}
        {settings.last_test.at && (
          <p>
            Last check {new Date(settings.last_test.at).toLocaleString()}:{' '}
            {settings.last_test.ok ? 'worked' : `failed${settings.last_test.error ? ` — ${settings.last_test.error}` : ''}`}
          </p>
        )}
      </div>

      <Dialog open={consentOpen} onOpenChange={setConsentOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Send code excerpts to {formHost || 'this host'}?</DialogTitle>
            <DialogDescription>
              {local
                ? 'This LLM runs on this machine, so excerpts stay local.'
                : 'This LLM is on another machine or a cloud service. Excerpts leave this computer.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 text-sm">
            <div>
              <p className="font-medium">What is sent for each finding</p>
              <ul className="list-disc pl-5">{settings.disclosure.sent.map((t) => <li key={t}>{t}</li>)}</ul>
            </div>
            {form.enrich_reports && (
              <div>
                <p className="font-medium">Also sent to write mitigation advice</p>
                <ul className="list-disc pl-5">
                  {settings.disclosure.sent_for_mitigation.map((t) => <li key={t}>{t}</li>)}
                </ul>
              </div>
            )}
            <div>
              <p className="font-medium">What is not sent</p>
              <ul className="list-disc pl-5">{settings.disclosure.not_sent.map((t) => <li key={t}>{t}</li>)}</ul>
            </div>
            {settings.disclosure.key_note && <p className="text-muted-foreground">{settings.disclosure.key_note}</p>}
            <label className="flex items-start gap-2">
              <input type="checkbox" className="mt-1" checked={understood}
                onChange={(e) => setUnderstood(e.target.checked)} />
              <span>I understand and allow Code Sense to send this to {formHost || 'this host'}.</span>
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConsentOpen(false)}>Cancel</Button>
            <Button disabled={!understood || busy} onClick={() => void onConsent()}>
              {settings.enabled ? 'Confirm' : 'Turn on AI verification'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
