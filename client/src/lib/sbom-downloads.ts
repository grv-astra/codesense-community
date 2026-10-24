import { scanService } from '@/services/scan.service';
import type { SbomScanDetails } from '@/types/scan';

export interface SbomDownloadOption {
  key: string;
  label: string;
  /** "report" = findings export, "file" = the SBOM itself. */
  group: 'report' | 'file';
  filename: string;
  request: () => Promise<Blob>;
}

/** A scan name made safe to use as a file name (names are free text typed by the user). */
export function safeFileName(name: string): string {
  const cleaned = name.trim().replace(/[^\w.-]+/g, '_').replace(/^_+|_+$/g, '');
  return cleaned || 'sbom-scan';
}

/**
 * What can be downloaded for a scan. The signed bundle is offered only when the scan was actually
 * signed (Pro / Enterprise); everything else is available in every edition.
 */
export function sbomDownloadOptions(
  scan: Pick<SbomScanDetails, 'id' | 'scan_name' | 'signing'>,
): SbomDownloadOption[] {
  const base = safeFileName(scan.scan_name);
  const report = (kind: 'vulnerabilities' | 'licenses', format: 'csv' | 'json'): SbomDownloadOption => ({
    key: `${kind}-${format}`,
    label: `${kind === 'vulnerabilities' ? 'Vulnerabilities' : 'Licenses'} (${format.toUpperCase()})`,
    group: 'report',
    filename: `${base}_${kind}.${format}`,
    request: () => scanService.downloadSbomReport(scan.id, kind, format),
  });
  const options: SbomDownloadOption[] = [
    report('vulnerabilities', 'csv'),
    report('vulnerabilities', 'json'),
    report('licenses', 'csv'),
    report('licenses', 'json'),
    {
      key: 'sbom',
      label: 'SBOM (JSON)',
      group: 'file',
      filename: `${base}_sbom.json`,
      request: () => scanService.downloadSbomFile(scan.id, 'sbom'),
    },
  ];
  if (scan.signing?.signed) {
    options.push({
      key: 'signed',
      label: 'Signed SBOM + signature (ZIP)',
      group: 'file',
      filename: `${base}_sbom_signed.zip`,
      request: () => scanService.downloadSbomFile(scan.id, 'signed'),
    });
  }
  return options;
}

/** Hand a blob to the browser as a download. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

function readBlobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

/**
 * Message for a failed download. Blob requests deliver an error body as a Blob, so read the
 * server's `error` text out of it when there is one (e.g. "The SBOM file ... is no longer available").
 */
export async function downloadErrorMessage(error: unknown): Promise<string> {
  const data = (error as { response?: { data?: unknown } })?.response?.data;
  if (data instanceof Blob) {
    try {
      const parsed = JSON.parse(await readBlobText(data));
      if (typeof parsed?.error === 'string') return parsed.error;
    } catch {
      /* not JSON: fall through to the generic text */
    }
  }
  return 'Could not download the file. Please try again.';
}
