import { apiClient } from "./client";
import type { Role } from "@/store/authStore";

export interface LoginResponse {
  access_token: string;
  token_type: string;
  username: string;
  role: Role;
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>("/auth/login", { username, password });
  return data;
}
