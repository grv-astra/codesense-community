import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

const { request, saveBlob, toast } = vi.hoisted(() => ({ request: vi.fn(), saveBlob: vi.fn(), toast: vi.fn() }));
vi.mock('sonner', () => ({ toast }));
vi.mock('@/lib/sbom-downloads', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/sbom-downloads')>();
  return {
    ...actual,
    saveBlob,
    sbomDownloadOptions: () => [
      { key: 'a', label: 'Vulnerabilities (CSV)', group: 'report', filename: 'a.csv', request },
      { key: 'b', label: 'SBOM (JSON)', group: 'file', filename: 'b.json', request },
    ],
  };
});

import { SbomDownloadMenu } from './sbom-download-menu';

const scan = { id: 's1', scan_name: 'scan', signing: null };

const openMenu = () => {
  const trigger = screen.getByRole('button', { name: /download/i });
  fireEvent.keyDown(trigger, { key: 'Enter' });
};

describe('SbomDownloadMenu', () => {
  beforeEach(() => vi.clearAllMocks());

  it('lists the downloads once opened', async () => {
    render(<SbomDownloadMenu scan={scan} />);
    openMenu();
    expect(await screen.findByText('Vulnerabilities (CSV)')).toBeInTheDocument();
    expect(screen.getByText('SBOM (JSON)')).toBeInTheDocument();
  });

  it('saves the file the server returns and confirms it', async () => {
    const blob = new Blob(['data']);
    request.mockResolvedValue(blob);
    render(<SbomDownloadMenu scan={scan} />);
    openMenu();
    fireEvent.click(await screen.findByText('Vulnerabilities (CSV)'));
    await waitFor(() => expect(saveBlob).toHaveBeenCalledWith(blob, 'a.csv'));
    expect(toast).toHaveBeenCalledWith('Download complete', expect.anything());
  });

  it('reports the server message when the download fails', async () => {
    const body = new Blob([JSON.stringify({ error: 'The SBOM file for this scan is no longer available.' })]);
    request.mockRejectedValue({ response: { data: body } });
    render(<SbomDownloadMenu scan={scan} />);
    openMenu();
    fireEvent.click(await screen.findByText('SBOM (JSON)'));
    await waitFor(() => expect(toast).toHaveBeenCalledWith('Download failed', {
      description: 'The SBOM file for this scan is no longer available.',
    }));
    expect(saveBlob).not.toHaveBeenCalled();
  });
});
