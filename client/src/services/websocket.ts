import { WS_URL } from "../config";

export class WebSocketService {
  private ws: WebSocket | null = null;
  private listeners: Map<string, (data: any) => void> = new Map();

  connect(userId: string) {
    this.ws = new WebSocket(`${WS_URL}/ws/${userId}`);

    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.listeners.forEach((callback) => callback(data));
    };

    this.ws.onerror = (error) => {
      console.error("WebSocket error:", error);
    };

    this.ws.onclose = () => {
      console.log("WebSocket closed");
      setTimeout(() => this.connect(userId), 3000);
    };
  }

  subscribe(id: string, callback: (data: any) => void) {
    this.listeners.set(id, callback);
  }

  unsubscribe(id: string) {
    this.listeners.delete(id);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

export const wsService = new WebSocketService();
