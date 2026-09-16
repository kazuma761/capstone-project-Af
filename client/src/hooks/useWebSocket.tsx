import { useEffect, useRef } from "react";
import { wsService } from "../services/websocket";
import { useAuthStore } from "../store/authStore";

export function useWebSocket(onMessage: (data: any) => void) {
  const { user } = useAuthStore();
  const callbackRef = useRef(onMessage);

  useEffect(() => {
    callbackRef.current = onMessage;
  }, [onMessage]);

  useEffect(() => {
    if (!user?.id) return;

    const handleMessage = (data: any) => {
      callbackRef.current(data);
    };

    wsService.connect(user.id);
    const subscriptionId = `hook-${Date.now()}`;
    wsService.subscribe(subscriptionId, handleMessage);

    return () => {
      wsService.unsubscribe(subscriptionId);
    };
  }, [user?.id]);

  return {
    sendMessage: (data: any) => {
      // Can be extended to send messages if needed
      console.log("Send message:", data);
    },
  };
}
