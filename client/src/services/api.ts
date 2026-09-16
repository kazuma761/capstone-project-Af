//@ts-ignore
import axios from "axios";
import { API_URL } from "../config";

export const api = axios.create({
  baseURL: API_URL,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("auth-storage");
  if (token) {
    const parsed = JSON.parse(token);
    if (parsed.state?.token) {
      config.headers.Authorization = `Bearer ${parsed.state.token}`;
    }
  }
  return config;
});

export const authAPI = {
  signup: (data: { email: string; password: string; name: string }) =>
    api.post("/api/auth/signup", data),
  login: (data: { email: string; password: string }) =>
    api.post("/api/auth/login", data),
};

export const scanAPI = {
  scanURL: (url: string) => api.post("/api/scan/url", { url }),
  scanPDF: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return api.post("/api/scan/pdf", formData);
  },
  scanFile: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return api.post("/api/scan/file", formData);
  },
  scanImage: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return api.post("/api/scan/image", formData);
  },
  scanMessage: (message: string) => api.post("/api/scan/message", { message }),
  getHistory: () => api.get("/api/scan/history"),
  getScan: (scanId: string) => api.get(`/api/scan/${scanId}`),
};

export const behavioralAPI = {
  start: () => api.post("/api/behavioral/start"),
  stop: () => api.post("/api/behavioral/stop"),
  getStatus: () => api.get("/api/behavioral/status"),
  getProcesses: (tier?: string) =>
    api.get("/api/behavioral/processes", { params: { tier } }),
  getAlerts: (limit?: number) =>
    api.get("/api/behavioral/alerts", { params: { limit } }),
  getBaseline: (processName: string) =>
    api.get(`/api/behavioral/baseline/${processName}`),
  killProcess: (pid: number) => api.post(`/api/behavioral/kill/${pid}`),
  getStats: () => api.get("/api/behavioral/stats"),
};
