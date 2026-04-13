import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || '/api/v1/';

const api = axios.create({
  baseURL: apiBaseUrl,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(async (config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response ? error.response.status : null;
    
    if (status === 401) {
      localStorage.removeItem('access_token');
      const base = import.meta.env.BASE_URL || '/';
      const currentPath = window.location.pathname;
      if (!currentPath.includes('/login')) {
        window.location.href = `${base}login`.replace(/\/+/g, '/');
      }
    }
    
    let message = error.response?.data?.message || error.response?.data?.detail || "Network Operational Failure";
    if (typeof message === 'object') {
      message = JSON.stringify(message);
    }
    console.error(`[API ERROR] ${status || 'CONN'}: ${message}`);
    
    return Promise.reject({
      ...error,
      message,
      status
    });
  }
);

// Response type helpers
export interface PaginatedResponse<T> {
  [key: string]: T[] | number;
  total: number;
  page: number;
  limit: number;
  pages: number;
}

export const authApi = {
  login: (data: any) => api.post('auth/login', data),
  signup: (data: any) => api.post('auth/signup', data),
  verifyTotp: (data: any) => api.post('auth/totp/verify', data),
  requestReset: (email: string) => api.post('auth/password/reset-request', { email }),
  completeReset: (token: string, password: any) => api.post('auth/password/reset-complete', { token, password }),
  getMe: () => api.get('auth/me'),
};

// Entity API Methods
export const targetsApi = {
  list: (params?: any) => api.get<PaginatedResponse<any>>('targets', { params }),
  get: (id: string) => api.get(`targets/${id}`),
  create: (data: any) => api.post('targets', data),
  update: (id: string, data: any) => api.put(`targets/${id}`, data),
  delete: (id: string) => api.delete(`targets/${id}`),
  validate: (url: string) => api.get('targets/validate', { params: { url } }),
};

export const scansApi = {
  list: (params?: any) => api.get<PaginatedResponse<any>>('scans', { params }),
  get: (id: string) => api.get(`scans/${id}`),
  create: (data: any) => api.post('scans', data),
  cancel: (id: string) => api.post(`scans/${id}/cancel`),
  recover: (id: string) => api.post(`scans/${id}/recover`),
  getStatus: (id: string) => api.get(`scans/${id}/status`),
  getStats: () => api.get('scans/stats'),
  getRecentFindings: (limit = 5) => api.get('scans/findings/recent', { params: { limit } }),
};

export const reportsApi = {
  list: (params?: any) => api.get<PaginatedResponse<any>>('reports', { params }),
  get: (id: string) => api.get(`reports/${id}`),
  create: (data: any) => api.post('reports', data),
  download: (id: string, format: string) =>
    api.get(`reports/${id}/download/${format}`, { responseType: 'blob' }),
};

export const schedulesApi = {
  list: () => api.get('schedules'),
  get: (id: string) => api.get(`schedules/${id}`),
  create: (data: {
    name: string;
    target_id: string;
    frequency: 'daily' | 'weekly' | 'monthly' | 'once';
    config_overrides?: Record<string, any>;
    enabled?: boolean;
  }) => api.post('schedules', data),
  update: (id: string, data: any) => api.put(`schedules/${id}`, data),
  delete: (id: string) => api.delete(`schedules/${id}`),
};

export const webhooksApi = {
  list: () => api.get('webhooks'),
  get: (id: string) => api.get(`webhooks/${id}`),
  create: (data: {
    url: string;
    name: string;
    secret?: string;
    enabled?: boolean;
    events?: string[];
  }) => api.post('webhooks', data),
  update: (id: string, data: any) => api.put(`webhooks/${id}`, data),
  delete: (id: string) => api.delete(`webhooks/${id}`),
  ping: (id: string) => api.post(`webhooks/${id}/ping`),
};

export const teamsApi = {
  list: () => api.get('teams'),
  get: (id: string) => api.get(`teams/${id}`),
  create: (data: { name: string; description?: string }) => api.post('teams', data),
};

export const proxyApi = {
  setMode: (intercept_enabled: boolean) => api.post('proxy/mode', { intercept_enabled }),
  forward: (id: string) => api.post(`proxy/forward/${id}`),
  drop: (id: string) => api.post(`proxy/drop/${id}`),
  getStatus: () => api.get('proxy/status'),
  getPayloads: () => api.get('proxy/payloads'),
};

export const settingsApi = {
  get: () => api.get('settings'),
  update: (data: any) => api.put('settings', data),
  reset: () => api.post('settings/reset'),
  get2fa: () => api.get('auth/totp/qr'),
};

export const complianceApi = {
  get: () => api.get('compliance'),
  recalculate: () => api.post('compliance/recalculate'),
  export: () => api.get('compliance/export', { responseType: 'blob' }),
};

export default api;
