import axios, { type AxiosInstance, type AxiosResponse, AxiosError } from 'axios';

// Fixed loopback backend. Works both in the dev browser and inside the Tauri
// webview, whose origin is tauri://localhost — so window.location.hostname
// (the old value) resolved to "tauri.localhost" and broke every request.
// Overridable at build/runtime via VITE_BACKEND_URL.
const port = 8585;
const envBackendUrl = import.meta.env.VITE_BACKEND_URL as string | undefined;
// VITE_BACKEND_URL="" (same-origin deployments, e.g. behind nginx) must NOT
// resolve to the empty string here: axios treats a falsy baseURL as "skip
// path-joining" and hands request paths straight to the browser as relative
// URLs, which then resolve against whatever page is currently open instead
// of the site root -- e.g. from /project/list, a service call to
// "api/projects/" (every service file omits the leading slash, safe only
// with an absolute baseURL) would resolve to /project/list/api/projects/.
// Resolving to window.location.origin keeps BACKEND_URL a real absolute URL,
// so axios's own combineURLs() does the joining correctly regardless.
export const BACKEND_URL =
  envBackendUrl !== undefined
    ? envBackendUrl || (typeof window !== 'undefined' ? window.location.origin : '')
    : `http://127.0.0.1:${port}`;

const TOKEN_KEY = 'auth_token';

// ONE axios instance for the whole app. Every service used to `extends
// BaseApiClient`, and the constructor called `axios.create()` + registered a
// request/response interceptor pair — so the ~11 service singletons each held
// their own instance and every request ran through 11 duplicate interceptor
// chains. Now the instance and its interceptors are created once, at module load.
export const http: AxiosInstance = axios.create({
  baseURL: BACKEND_URL,
  headers: { 'Content-Type': 'application/json' },
});

http.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    // Let the browser set the multipart boundary itself for FormData bodies.
    if (
      config.data instanceof FormData &&
      config.headers &&
      config.headers['Content-Type']
    ) {
      delete config.headers['Content-Type'];
    }
    return config;
  },
  (error) => Promise.reject(error),
);

http.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      window.location.href = '/login';
    }
    return Promise.reject(error);
  },
);

export function setAuthToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAuthToken() {
  localStorage.removeItem(TOKEN_KEY);
}

// Thin base every service still extends. It no longer owns an axios instance —
// `axiosInstance` points at the shared `http` singleton (kept for the couple of
// services that reach for it directly, e.g. blob downloads). The token is read
// per-request by the interceptor above, so setToken/clearToken only touch
// storage; no per-instance header bookkeeping.
export class BaseApiClient {
  protected axiosInstance: AxiosInstance = http;

  setToken(token: string) {
    setAuthToken(token);
  }

  clearToken() {
    clearAuthToken();
  }

  protected async get<T>(endpoint: string, params?: unknown): Promise<T> {
    const response = await http.get<T>(endpoint, { params: params as object });
    return response.data;
  }

  protected async post<T>(
    endpoint: string,
    data?: unknown,
    customHeaders?: Record<string, string>,
  ): Promise<T> {
    const isFormData = typeof FormData !== 'undefined' && data instanceof FormData;
    const headers = {
      ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
      ...customHeaders,
    };
    const response = await http.post<T>(endpoint, data, { headers });
    return response.data;
  }

  protected async put<T>(endpoint: string, data?: unknown): Promise<T> {
    const response = await http.put<T>(endpoint, data);
    return response.data;
  }

  protected async patch<T>(endpoint: string, data?: unknown): Promise<T> {
    const response = await http.patch<T>(endpoint, data);
    return response.data;
  }

  protected async delete<T>(endpoint: string): Promise<T> {
    const response = await http.delete<T>(endpoint);
    return response.data;
  }
}
