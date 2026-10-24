import { useState } from 'react';
import { Download } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/atomic/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/atomic/dropdown-menu';
import {
  downloadErrorMessage,
  saveBlob,
  sbomDownloadOptions,
  type SbomDownloadOption,
} from '@/lib/sbom-downloads';
import type { SbomScanDetails } from '@/types/scan';

interface Props {
  scan: Pick<SbomScanDetails, 'id' | 'scan_name' | 'signing'>;
}

export function SbomDownloadMenu({ scan }: Props) {
  const [busy, setBusy] = useState(false);
  const options = sbomDownloadOptions(scan);

  const run = async (option: SbomDownloadOption) => {
    setBusy(true);
    try {
      saveBlob(await option.request(), option.filename);
      // The packaged desktop app has no browser download bar, so this toast is the only
      // confirmation that the file was saved.
      toast('Download complete', { description: `${option.filename} saved to your Downloads folder.` });
    } catch (error) {
      toast('Download failed', { description: await downloadErrorMessage(error) });
    } finally {
      setBusy(false);
    }
  };

  const items = (group: SbomDownloadOption['group']) =>
    options
      .filter((o) => o.group === group)
      .map((o) => (
        <DropdownMenuItem key={o.key} onSelect={() => run(o)}>
          {o.label}
        </DropdownMenuItem>
      ));

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" disabled={busy}>
          <Download className="w-4 h-4" />
          {busy ? 'Preparing…' : 'Download'}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>Reports</DropdownMenuLabel>
        {items('report')}
        <DropdownMenuSeparator />
        <DropdownMenuLabel>SBOM</DropdownMenuLabel>
        {items('file')}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
