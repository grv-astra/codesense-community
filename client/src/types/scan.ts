import type { LlmScanMetrics } from './llm';

interface FindingsProgress {
    total: number,
    processed: number,
}
interface FolderMetrics {
    total_loc: number,
    total_functions: number,
    languages: string[],
    findings_progress?: FindingsProgress,
    /** How AI verification went for this scan (absent on scans from before it was recorded). */
    llm?: LlmScanMetrics,
}
export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export const SEVERITY_ORDER: (keyof SeverityCounts)[] = ['critical', 'high', 'medium', 'low'];

export interface IncrementalInfo {
  is_incremental: boolean;
  unchanged: number;
  changed: number;
}

export interface ScanDetails {
  id: string;
  project_id: string;
  scan_name: string;
  status: string;
  findings: number;
  total_files: number;
  files_scanned: number;
  created_at: string;
  end_time: string | null;
  triggered_by: string;
  metrics: FolderMetrics;
  error?: string;
  severity_counts?: SeverityCounts;
  // True from the moment "Cancel" is clicked, well before `status` itself
  // flips to 'cancelled' -- the running scan can lag behind the click since
  // in-flight LLM calls can't be forcibly interrupted. Lets the UI show a
  // "stopping" state instead of looking like the click did nothing.
  cancel_requested?: boolean;
  // Set once, early in the "Analyzing" phase -- whether this scan reused a
  // baseline from a prior completed scan, and how many files were unchanged
  // (reused) vs. changed/new (re-analyzed). See scanner/rag/incremental.py.
  incremental_info?: IncrementalInfo;
}
 
export interface SbomScanDetails {
  id: string;
  project_id: string;
  scan_name: string;
  status: string;
  vulnerabilities: number;
  total_files: number;
  dependencies_scanned: number;
  /** Distinct vulnerable packages (`vulnerabilities` counts CVEs). Absent on older servers. */
  affected_dependencies?: number;
  severity_counts: {
    critical: number,
    high: number,
    medium: number,
    low: number,
    negligible: number
  };
  sbom_format: string;
  ecosystems: string[];
  created_at: string;
  end_time: string | null;
  triggered_by: string;
}

export interface CreateScanDetails {
  project_id: string;
  scan_type: string;
  scan_name: string;
  zip_file: File | null;
  zip_error?: string;
}

export interface CreateSBOMScanForm {
  project_id: string;
  scan_name: string;
  file: File | null;
  file_error?: string;
}
 
export interface CreateGithubScans {
  project_id: string;
  scan_name: string;
  scan_type: string;
  git_token: string;
  git_repo: string;
  git_rowner: string;
}
 
export interface UpdateProjectDetails {
  name?: string;
  preset?: string;
  description?: string;
}
 
export interface ScanListResponse {
  scans: ScanDetails[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    pages: number;
  }
}

export interface SbomScanListResponse {
  scans: SbomScanDetails[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    pages: number;
  }
}