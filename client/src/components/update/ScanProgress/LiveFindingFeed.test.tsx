import { render, screen, fireEvent } from '@testing-library/react';
import { describe, test, expect } from 'vitest';
import { LiveFindingFeed } from './LiveFindingFeed';
import type { FindingDetails } from '@/types/finding';

function makeFinding(over: Partial<FindingDetails>): FindingDetails {
  return {
    id: 'f1', scan_id: 's1', created_by: '', cwe: 'CWE-89', cvss_vector: '', cvss_score: '',
    code: '', title: 'sql-injection', description: '', severity: 'high', file_path: 'app.py',
    code_snip: '', security_risk: '', mitigation: '', status: 'open', deleted: false,
    approved: false, reference: '', created_at: '2026-08-25T00:00:00.000Z',
    ...over,
  };
}

describe('LiveFindingFeed', () => {
  test('shows a waiting message when no findings have arrived yet', () => {
    render(<LiveFindingFeed findings={[]} newFindingIds={new Set()} />);
    expect(screen.getByText(/Waiting for the first finding/)).toBeInTheDocument();
  });

  test('caps the visible list to 5 and offers a "show all" expand', () => {
    const findings = Array.from({ length: 9 }, (_, i) => makeFinding({ id: `f${i}`, title: `finding-${i}` }));
    render(<LiveFindingFeed findings={findings} newFindingIds={new Set()} />);
    expect(screen.getAllByText(/^finding-/)).toHaveLength(5);
    const button = screen.getByRole('button', { name: 'Show all 9 loaded' });
    fireEvent.click(button);
    expect(screen.getAllByText(/^finding-/)).toHaveLength(9);
  });

  test('flags a new Critical/High finding but not a new Medium/Low one', () => {
    const findings = [
      makeFinding({ id: 'f1', title: 'crit-one', severity: 'critical' }),
      makeFinding({ id: 'f2', title: 'medium-one', severity: 'medium' }),
    ];
    render(<LiveFindingFeed findings={findings} newFindingIds={new Set(['f1', 'f2'])} />);
    expect(screen.getByText('New critical')).toBeInTheDocument();
    expect(screen.queryByText('New medium')).not.toBeInTheDocument();
  });
});
