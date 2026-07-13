import axios from "axios";

import { useAuthStore } from "@/store/authStore";

/**
 * Shared API client. Attaches the session bearer token issued by
 * POST /api/v1/auth/login (see backend/app/api/v1/auth.py) to every
 * request, and clears local auth state on a 401 so the UI falls back to
 * the login page instead of silently failing.
 */
export const apiClient = axios.create({
  baseURL: "/api/v1",
});

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout();
    }
    return Promise.reject(error);
  },
);
