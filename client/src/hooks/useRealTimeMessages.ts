import { useState, useEffect, useCallback, useRef } from 'react';
import { messageService, Message } from '../services/messageService';
import { useMessageEncryption } from './useEncryption';
import { useAuth } from '../contexts/AuthContext';

export type ConnectionStatus = 'connected' | 'disconnected' | 'connecting';
export type ConnectionMode = 'sse' | 'polling' | 'none';

interface UseRealTimeMessagesState {
  messages: Message[];
  connectionStatus: ConnectionStatus;
  connectionMode: ConnectionMode;
  isLoading: boolean;
  error: string | null;
  isSending: boolean;
}

interface UseRealTimeMessagesReturn {
  // State
  state: UseRealTimeMessagesState;
  
  // Actions
  sendMessage: (content: string) => Promise<boolean>;
  loadMessageHistory: (page?: number, limit?: number) => Promise<void>;
  connect: (preferSSE?: boolean) => void;
  disconnect: () => void;
  clearMessages: () => void;
  clearError: () => void;
  
  // Connection management
  reconnect: () => void;
  switchToPolling: () => void;
  switchToSSE: () => void;
}

/**
 * Custom React hook for real-time messaging functionality
 * Handles SSE connection, polling fallback, message encryption, and state management
 */
export function useRealTimeMessages(): UseRealTimeMessagesReturn {
  const { user } = useAuth();
  const { getSessionKey, createSessionKey, encryptWithSessionKey } = useMessageEncryption();
  
  const [state, setState] = useState<UseRealTimeMessagesState>({
    messages: [],
    connectionStatus: 'disconnected',
    connectionMode: 'none',
    isLoading: false,
    error: null,
    isSending: false
  });

  const mountedRef = useRef(true);
  const lastMessageIdRef = useRef<string>('');

  // Helper to safely update state only if component is mounted
  const safeSetState = useCallback((updates: Partial<UseRealTimeMessagesState>) => {
    if (mountedRef.current) {
      setState(prev => ({ ...prev, ...updates }));
    }
  }, []);

  // Initialize session key for encryption
  const initializeEncryption = useCallback(() => {
    if (!getSessionKey()) {
      const sessionKey = createSessionKey();
      if (sessionKey) {
        messageService.setSessionKey(sessionKey);
      }
    } else {
      messageService.setSessionKey(getSessionKey()!);
    }
  }, [getSessionKey, createSessionKey]);

  // Handle new incoming messages
  const handleNewMessage = useCallback((message: Message) => {
    if (!mountedRef.current) return;
    
    // Avoid duplicate messages
    if (message.id === lastMessageIdRef.current) return;
    lastMessageIdRef.current = message.id;

    safeSetState({
      messages: prev => {
        // Check if message already exists
        const existingIndex = prev.findIndex(m => m.id === message.id);
        if (existingIndex >= 0) {
          // Update existing message
          const updated = [...prev];
          updated[existingIndex] = message;
          return updated;
        } else {
          // Add new message
          return [...prev, message];
        }
      }
    });
  }, [safeSetState]);

  // Handle connection status changes
  const handleConnectionStatus = useCallback((status: ConnectionStatus) => {
    if (!mountedRef.current) return;
    safeSetState({ connectionStatus: status });
  }, [safeSetState]);

  // Connect to real-time messaging
  const connect = useCallback((preferSSE = true) => {
    if (!user) {
      safeSetState({ error: 'Authentication required for real-time messaging' });
      return;
    }

    initializeEncryption();
    safeSetState({ connectionStatus: 'connecting', error: null });

    try {
      if (preferSSE && window.EventSource) {
        messageService.connectSSE();
        safeSetState({ connectionMode: 'sse' });
      } else {
        messageService.startPolling();
        safeSetState({ connectionMode: 'polling' });
      }
    } catch (error) {
      console.error('Failed to connect:', error);
      safeSetState({ 
        error: 'Failed to establish real-time connection',
        connectionStatus: 'disconnected' 
      });
      
      // Fall back to polling if SSE fails
      if (preferSSE) {
        setTimeout(() => {
          if (mountedRef.current) {
            messageService.startPolling();
            safeSetState({ connectionMode: 'polling' });
          }
        }, 1000);
      }
    }
  }, [user, initializeEncryption, safeSetState]);

  // Disconnect from real-time messaging
  const disconnect = useCallback(() => {
    messageService.disconnect();
    safeSetState({ 
      connectionStatus: 'disconnected',
      connectionMode: 'none' 
    });
  }, [safeSetState]);

  // Reconnect with current mode
  const reconnect = useCallback(() => {
    disconnect();
    setTimeout(() => {
      if (mountedRef.current) {
        connect(state.connectionMode === 'sse');
      }
    }, 1000);
  }, [disconnect, connect, state.connectionMode]);

  // Switch to polling mode
  const switchToPolling = useCallback(() => {
    messageService.disconnectSSE();
    messageService.startPolling();
    safeSetState({ connectionMode: 'polling' });
  }, [safeSetState]);

  // Switch to SSE mode
  const switchToSSE = useCallback(() => {
    if (!window.EventSource) {
      safeSetState({ error: 'Server-Sent Events not supported in this browser' });
      return;
    }
    
    messageService.stopPolling();
    messageService.connectSSE();
    safeSetState({ connectionMode: 'sse' });
  }, [safeSetState]);

  // Send a message
  const sendMessage = useCallback(async (content: string): Promise<boolean> => {
    if (!content.trim()) {
      safeSetState({ error: 'Message content cannot be empty' });
      return false;
    }

    if (!user) {
      safeSetState({ error: 'Authentication required to send messages' });
      return false;
    }

    safeSetState({ isSending: true, error: null });

    try {
      const sessionKey = getSessionKey();
      await messageService.sendMessage(content, sessionKey || undefined);
      
      safeSetState({ isSending: false });
      return true;
    } catch (error: any) {
      const errorMessage = error?.message || 'Failed to send message';
      console.error('Error sending message:', error);
      safeSetState({ 
        error: errorMessage,
        isSending: false 
      });
      return false;
    }
  }, [user, getSessionKey, safeSetState]);

  // Load message history
  const loadMessageHistory = useCallback(async (page = 1, limit = 50): Promise<void> => {
    safeSetState({ isLoading: true, error: null });

    try {
      initializeEncryption();
      const response = await messageService.getMessageHistory(page, limit);
      
      if (page === 1) {
        // Replace messages for first page
        safeSetState({ 
          messages: response.messages,
          isLoading: false 
        });
      } else {
        // Append messages for subsequent pages
        safeSetState({ 
          messages: prev => [...response.messages, ...prev],
          isLoading: false 
        });
      }
    } catch (error: any) {
      const errorMessage = error?.message || 'Failed to load message history';
      console.error('Error loading message history:', error);
      safeSetState({ 
        error: errorMessage,
        isLoading: false 
      });
    }
  }, [initializeEncryption, safeSetState]);

  // Clear messages
  const clearMessages = useCallback(() => {
    safeSetState({ messages: [] });
    lastMessageIdRef.current = '';
  }, [safeSetState]);

  // Clear error
  const clearError = useCallback(() => {
    safeSetState({ error: null });
  }, [safeSetState]);

  // Set up event listeners on mount
  useEffect(() => {
    const unsubscribeMessage = messageService.onMessage(handleNewMessage);
    const unsubscribeStatus = messageService.onConnectionStatus(handleConnectionStatus);

    return () => {
      unsubscribeMessage();
      unsubscribeStatus();
    };
  }, [handleNewMessage, handleConnectionStatus]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      mountedRef.current = false;
      messageService.disconnect();
    };
  }, []);

  // Auto-connect when user is available
  useEffect(() => {
    if (user && state.connectionStatus === 'disconnected' && state.connectionMode === 'none') {
      // Auto-connect with SSE first, fallback to polling
      connect(true);
    }
  }, [user, connect, state.connectionStatus, state.connectionMode]);

  return {
    state,
    sendMessage,
    loadMessageHistory,
    connect,
    disconnect,
    clearMessages,
    clearError,
    reconnect,
    switchToPolling,
    switchToSSE
  };
}

/**
 * Simplified hook for basic messaging functionality
 */
export function useSimpleMessaging() {
  const realTimeMessages = useRealTimeMessages();
  
  return {
    messages: realTimeMessages.state.messages,
    isConnected: realTimeMessages.state.connectionStatus === 'connected',
    isLoading: realTimeMessages.state.isLoading,
    isSending: realTimeMessages.state.isSending,
    error: realTimeMessages.state.error,
    sendMessage: realTimeMessages.sendMessage,
    loadHistory: realTimeMessages.loadMessageHistory,
    clearError: realTimeMessages.clearError
  };
}

export default useRealTimeMessages;