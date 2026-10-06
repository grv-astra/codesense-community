import { afterEach, describe, expect, it, vi } from 'vitest';

import { http } from '@/lib/api';
import { scanService } from './scan.service';

describe('scanService.startGithubScan', () => {
  afterEach(() => vi.restoreAllMocks());

  // Regression: this used to POST to api/scans/create/ -- the zip-upload view,
  // whose serializer requires `zip_file` -- so every GitHub scan started from the
  // UI came back 400. The GitHub clone view is mounted at api/scans/github/.
  it('posts to the GitHub-clone endpoint, not the zip-upload endpoint', async () => {
    const post = vi.spyOn(http, 'post').mockResolvedValue({ data: { detail: 'GitHub scan started' } });
    const payload = {
      scan_name: 'Test-GH',
      project_id: 'p1',
      scan_type: 'sca',
      git_token: 'ghp_fake_token_for_tests',
      git_repo: 'codesense',
      git_rowner: 'grv-astra',
    };

    await scanService.startGithubScan(payload);

    expect(post).toHaveBeenCalledTimes(1);
    expect(post.mock.calls[0][0]).toBe('api/scans/github/');
    expect(post.mock.calls[0][1]).toEqual(payload);
  });
});
