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
  const { getSessionKey, createSessionKey } = useMessageEncryption();
  
  const [state, setState] = useState<UseRealTimeMessagesState>({
    messages: [], // Ensure this is always an array
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
    console.log('🔄 safeSetState called with:', updates, '| mounted:', mountedRef.current);
    // Be more permissive with state updates
    setState(prev => {
      const newState = { ...prev, ...updates };
      console.log('📊 State transition:', prev, '→', newState);
      return newState;
    });
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

    setState(prev => {
      // Check if message already exists
      const existingIndex = prev.messages.findIndex((m: Message) => m.id === message.id);
      if (existingIndex >= 0) {
        // Update existing message
        const updated = [...prev.messages];
        updated[existingIndex] = message;
        return { ...prev, messages: updated };
      } else {
        // Add new message
        return { ...prev, messages: [...prev.messages, message] };
      }
    });
  }, [safeSetState]);

  // Handle connection status changes
  const handleConnectionStatus = useCallback((status: ConnectionStatus) => {
    console.log('🎯 Hook received connection status:', status, '| Mounted:', mountedRef.current, '| Current state:', state.connectionStatus);
    
    // Always try to update state - let safeSetState handle the mounted check
    console.log('📝 Updating React state to:', status);
    safeSetState({ connectionStatus: status });
    
    // Verify the state update took effect
    setTimeout(() => {
      console.log('✅ State update check - status should be:', status);
    }, 100);
  }, [safeSetState, state.connectionStatus]);

  // Connect to real-time messaging
  const connect = useCallback((preferSSE = true) => {
    if (!user) {
      safeSetState({ error: 'Authentication required for real-time messaging' });
      return;
    }

    console.log('🔌 Starting connection process - preferSSE:', preferSSE, '| EventSource available:', !!window.EventSource);
    
    initializeEncryption();
    safeSetState({ connectionStatus: 'connecting', error: null });

    try {
      if (preferSSE && window.EventSource) {
        console.log('📡 Attempting SSE connection...');
        messageService.connectSSE();
        safeSetState({ connectionMode: 'sse' });
      } else {
        console.log('🔄 Starting polling connection...');
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
    console.log('🔌 Disconnecting...');
    messageService.disconnect();
    safeSetState({ 
      connectionStatus: 'disconnected',
      connectionMode: 'none' 
    });
  }, [safeSetState]);

  // Reconnect with current mode
  const reconnect = useCallback(() => {
    console.log('🔄 Reconnect called, current state:', { status: state.connectionStatus, mode: state.connectionMode });
    messageService.disconnect();
    safeSetState({ 
      connectionStatus: 'disconnected',
      connectionMode: 'none' 
    });
    
    setTimeout(() => {
      if (mountedRef.current && user) {
        console.log('🚀 Direct reconnect attempt');
        safeSetState({ connectionStatus: 'connecting', error: null });
        
        // Try SSE first
        try {
          messageService.connectSSE();
          safeSetState({ connectionMode: 'sse' });
        } catch (error) {
          console.error('SSE failed, trying polling:', error);
          messageService.startPolling();
          safeSetState({ connectionMode: 'polling' });
        }
      }
    }, 500);
  }, [user, safeSetState]);

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
    // Prevent multiple simultaneous requests
    if (state.isLoading) {
      console.log('⏸️ Message history request already in progress, skipping...');
      return;
    }

    safeSetState({ isLoading: true, error: null });

    try {
      initializeEncryption();
      const response = await messageService.getMessageHistory(page, limit);
      
      if (page === 1) {
        // Replace messages for first page
        safeSetState({ 
          messages: response.messages || [],
          isLoading: false 
        });
      } else {
        // Append messages for subsequent pages
        setState(prev => ({
          ...prev,
          messages: [...response.messages, ...prev.messages],
          isLoading: false 
        }));
      }
    } catch (error: any) {
      let errorMessage = 'Failed to load message history';
      
      // Handle rate limit specifically
      if (error?.status === 429) {
        errorMessage = 'Too many requests. Please wait a moment and try again.';
        console.warn('⚠️ Rate limit hit for message history');
        // Don't retry automatically for rate limits
      } else {
        errorMessage = error?.message || errorMessage;
        console.error('Error loading message history:', error);
      }
      
      safeSetState({ 
        error: errorMessage,
        isLoading: false 
      });
    }
  }, [initializeEncryption, safeSetState, state.isLoading]);

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
    console.log('🎧 Setting up message service listeners...');
    const unsubscribeMessage = messageService.onMessage(handleNewMessage);
    const unsubscribeStatus = messageService.onConnectionStatus(handleConnectionStatus);
    console.log('✅ Listeners registered - message listeners:', (messageService as any).messageListeners.size, 'status listeners:', (messageService as any).connectionStatusListeners.size);

    return () => {
      console.log('🧹 Cleaning up listeners...');
      unsubscribeMessage();
      unsubscribeStatus();
    };
  }, []); // Remove dependencies to prevent re-mounting

  // Cleanup on unmount - be more careful about when we disconnect
  useEffect(() => {
    mountedRef.current = true; // Ensure this is set to true on mount
    
    return () => {
      console.log('🔄 Component unmounting...');
      mountedRef.current = false;
      // Don't disconnect immediately - give some time for remount
      setTimeout(() => {
        if (!mountedRef.current) {
          console.log('🧹 Component confirmed unmounted, disconnecting...');
          messageService.disconnect();
        }
      }, 100);
    };
  }, []);

  // Auto-connect when user is available
  useEffect(() => {
    if (user && state.connectionStatus === 'disconnected' && state.connectionMode === 'none') {
      console.log('🚀 Auto-connecting for user:', user.username, '| Status:', state.connectionStatus, '| Mode:', state.connectionMode);
      // Auto-connect with SSE first, fallback to polling
      connect(true);
    }
  }, [user, connect, state.connectionStatus, state.connectionMode]);

  // Fallback to polling if SSE connection is stuck in connecting state
  useEffect(() => {
    if (state.connectionStatus === 'connecting' && state.connectionMode === 'sse') {
      const fallbackTimer = setTimeout(() => {
        if (mountedRef.current && state.connectionStatus === 'connecting') {
          console.log('⏰ SSE connection timeout, falling back to polling');
          messageService.disconnectSSE();
          messageService.startPolling();
          safeSetState({ connectionMode: 'polling' });
        }
      }, 1000); // Reduced to 1 second timeout for faster debugging

      return () => clearTimeout(fallbackTimer);
    }
  }, [state.connectionStatus, state.connectionMode, safeSetState]);

  // Emergency fallback - if still connecting after 10 seconds, force polling
  useEffect(() => {
    if (state.connectionStatus === 'connecting') {
      const emergencyTimer = setTimeout(() => {
        if (mountedRef.current && state.connectionStatus === 'connecting') {
          console.log('🚨 Emergency fallback: forcing polling connection');
          messageService.disconnect();
          setTimeout(() => {
            if (mountedRef.current) {
              messageService.startPolling();
              safeSetState({ connectionMode: 'polling', connectionStatus: 'connecting' });
            }
          }, 500);
        }
      }, 10000); // 10 second emergency timeout

      return () => clearTimeout(emergencyTimer);
    }
  }, [state.connectionStatus, safeSetState]);

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