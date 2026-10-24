import { beforeEach, describe, expect, it, vi } from 'vitest';

const { downloadSbomReport, downloadSbomFile } = vi.hoisted(() => ({
  downloadSbomReport: vi.fn(),
  downloadSbomFile: vi.fn(),
}));
vi.mock('@/services/scan.service', () => ({ scanService: { downloadSbomReport, downloadSbomFile } }));

import { downloadErrorMessage, safeFileName, sbomDownloadOptions } from './sbom-downloads';

const unsigned = { id: 's1', scan_name: 'My scan / v2', signing: null };
const signed = {
  id: 's1',
  scan_name: 'My scan / v2',
  signing: { signed: true, verified: true, verified_at: null, algorithm: 'cosign', skipped_reason: null },
};

describe('safeFileName', () => {
  it('keeps letters, digits, dots and dashes and replaces the rest', () => {
    expect(safeFileName('My scan / v2')).toBe('My_scan_v2');
    expect(safeFileName('..\\evil:name')).toBe('.._evil_name');
  });

  it('never returns an empty name', () => {
    expect(safeFileName('   ')).toBe('sbom-scan');
    expect(safeFileName('///')).toBe('sbom-scan');
  });
});

describe('sbomDownloadOptions', () => {
  beforeEach(() => vi.clearAllMocks());

  it('offers both reports in both formats plus the SBOM for any edition', () => {
    const options = sbomDownloadOptions(unsigned);
    expect(options.map((o) => o.label)).toEqual([
      'Vulnerabilities (CSV)', 'Vulnerabilities (JSON)', 'Licenses (CSV)', 'Licenses (JSON)', 'SBOM (JSON)',
    ]);
    expect(options.map((o) => o.filename)).toEqual([
      'My_scan_v2_vulnerabilities.csv', 'My_scan_v2_vulnerabilities.json',
      'My_scan_v2_licenses.csv', 'My_scan_v2_licenses.json', 'My_scan_v2_sbom.json',
    ]);
  });

  it('adds the signed bundle only when the scan was signed', () => {
    const options = sbomDownloadOptions(signed);
    expect(options.at(-1)).toMatchObject({ key: 'signed', filename: 'My_scan_v2_sbom_signed.zip', group: 'file' });
    expect(sbomDownloadOptions({ ...unsigned, signing: { ...signed.signing, signed: false } })
      .some((o) => o.key === 'signed')).toBe(false);
  });

  it('requests the matching report or file from the server', async () => {
    const blob = new Blob(['x']);
    downloadSbomReport.mockResolvedValue(blob);
    downloadSbomFile.mockResolvedValue(blob);
    const byKey = Object.fromEntries(sbomDownloadOptions(signed).map((o) => [o.key, o]));

    await byKey['licenses-json'].request();
    expect(downloadSbomReport).toHaveBeenCalledWith('s1', 'licenses', 'json');
    await byKey['vulnerabilities-csv'].request();
    expect(downloadSbomReport).toHaveBeenCalledWith('s1', 'vulnerabilities', 'csv');
    await byKey.sbom.request();
    expect(downloadSbomFile).toHaveBeenCalledWith('s1', 'sbom');
    await byKey.signed.request();
    expect(downloadSbomFile).toHaveBeenCalledWith('s1', 'signed');
  });
});

describe('downloadErrorMessage', () => {
  it("reads the server's message out of a blob error body", async () => {
    const body = new Blob([JSON.stringify({ error: 'The SBOM file for this scan is no longer available.' })]);
    expect(await downloadErrorMessage({ response: { data: body } }))
      .toBe('The SBOM file for this scan is no longer available.');
  });

  it('falls back to a generic message', async () => {
    expect(await downloadErrorMessage(new Error('network'))).toMatch(/Could not download/);
    expect(await downloadErrorMessage({ response: { data: new Blob(['<html>']) } })).toMatch(/Could not download/);
  });
});
