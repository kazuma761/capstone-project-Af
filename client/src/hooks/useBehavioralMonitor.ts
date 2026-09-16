import { useState, useEffect, useCallback, useRef } from "react";

interface ProcessFeatures {
  fe: number;
  fa: number;
  fn: number;
  fc: number;
}

interface ProcessData {
  pid: number;
  name: string;
  features: ProcessFeatures;
  risk_score: number;
  tier: "CLEAN" | "MONITOR" | "SUSPICIOUS" | "ALERT";
  last_updated: string;
}

interface BehavioralUpdate {
  type: "behavioral_update";
  process_count: number;
  alert_count: number;
  timestamp: string;
}

interface BehavioralAlert {
  type: "behavioral_alert";
  process: ProcessData;
  timestamp: string;
}

type WebSocketMessage = BehavioralUpdate | BehavioralAlert;

interface UseBehavioralMonitorOptions {
  autoConnect?: boolean;
  onAlert?: (alert: BehavioralAlert) => void;
}

export const useBehavioralMonitor = (
  options: UseBehavioralMonitorOptions = {}
) => {
  const { autoConnect = true, onAlert } = options;

  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<BehavioralUpdate | null>(null);
  const [alerts, setAlerts] = useState<BehavioralAlert[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const connect = useCallback(() => {
    // @ts-ignore
    const wsUrl = import.meta.env.VITE_WS_URL || "ws://localhost:8000";
    const clientId = `behavioral_${Date.now()}`;

    try {
      wsRef.current = new WebSocket(`${wsUrl}/ws/${clientId}`);

      wsRef.current.onopen = () => {
        setIsConnected(true);
        console.log("Behavioral monitor WebSocket connected");
      };

      wsRef.current.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);

          if (message.type === "behavioral_update") {
            setLastUpdate(message);
          } else if (message.type === "behavioral_alert") {
            setAlerts((prev) => [message, ...prev].slice(0, 100));
            onAlert?.(message);
          }
        } catch (e) {
          console.error("Failed to parse WebSocket message:", e);
        }
      };

      wsRef.current.onclose = () => {
        setIsConnected(false);
        console.log("Behavioral monitor WebSocket disconnected");

        // Attempt to reconnect after 3 seconds
        if (autoConnect) {
          reconnectTimeoutRef.current = setTimeout(connect, 3000);
        }
      };

      wsRef.current.onerror = (error) => {
        console.error("WebSocket error:", error);
      };
    } catch (error) {
      console.error("Failed to connect WebSocket:", error);
    }
  }, [autoConnect, onAlert]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [autoConnect, connect, disconnect]);

  return {
    isConnected,
    lastUpdate,
    alerts,
    connect,
    disconnect,
    clearAlerts: () => setAlerts([]),
  };
};

export default useBehavioralMonitor;
