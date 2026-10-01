import { BaseApiClient } from '@/lib/api';
import type { EditionStatus, EditionsCatalog } from '@/types/edition';

class EditionService extends BaseApiClient {
  async getStatus(): Promise<EditionStatus> {
    return this.get<EditionStatus>('/api/edition/');
  }

  async getCatalog(): Promise<EditionsCatalog> {
    return this.get<EditionsCatalog>('/api/editions/');
  }
}

export const editionService = new EditionService();
