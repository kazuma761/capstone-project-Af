// Central place for backend endpoints. Both are read from Vite env vars at
// build time so a deployed bundle can point at a non-localhost backend.
export const API_URL: string = (
  import.meta.env.VITE_API_URL || "http://localhost:8000"
).replace(/\/+$/, "");

export const WS_URL: string = (
  import.meta.env.VITE_WS_URL || API_URL.replace(/^http/, "ws")
).replace(/\/+$/, "");
