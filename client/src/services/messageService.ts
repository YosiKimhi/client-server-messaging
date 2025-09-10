// Message service for handling real-time messaging API communication
import { authService } from './authService';
import { encryptMessageForSending, decryptReceivedMessage, MessageEncryptionData } from '../utils/encryption';

const API_BASE_URL = 'http://localhost:3001/api';

export interface Message {
  id: string;
  username: string;
  content: string;
  timestamp: string;
  encrypted_content?: string;
  iv?: string;
}

export interface SendMessageRequest {
  content?: string;
  encrypted_content?: string;
  iv?: string;
}

export interface SendMessageResponse {
  success: boolean;
  message: Message;
}

export interface MessageHistoryResponse {
  messages: Message[];
  total: number;
  page: number;
  limit: number;
}

export interface ApiError {
  message: string;
  status: number;
}

class MessageService {
  private eventSource: EventSource | null = null;
  private pollingInterval: number | null = null;
  private isPolling = false;
  private messageListeners: Set<(message: Message) => void> = new Set();
  private connectionStatusListeners: Set<(status: 'connected' | 'disconnected' | 'connecting') => void> = new Set();
  private currentSessionKey: string | null = null;

  // API helper with authentication
  private async makeRequest(url: string, options: RequestInit = {}): Promise<any> {
    const token = authService.getToken();
    
    const config: RequestInit = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
    };

    try {
      const response = await fetch(`${API_BASE_URL}${url}`, config);
      
      if (!response.ok) {
        let errorMessage = 'An error occurred';
        let errorDetails = {};
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorData.error?.message || errorMessage;
          errorDetails = errorData;
          console.error('📋 Server error details:', errorData);
        } catch {
          errorMessage = response.statusText;
        }
        
        const error: ApiError = {
          message: errorMessage,
          status: response.status,
        };
        console.error('❌ HTTP Error:', response.status, errorMessage, errorDetails);
        throw error;
      }

      return await response.json();
    } catch (error) {
      if (error instanceof Error && !('status' in error)) {
        throw {
          message: 'Network error. Please check your connection.',
          status: 0,
        } as ApiError;
      }
      throw error;
    }
  }

  // Send a message
  async sendMessage(content: string, sessionKey?: string): Promise<SendMessageResponse> {
    console.log('🚨 SENDMESSAGE CALLED! Content:', JSON.stringify(content), 'SessionKey:', !!sessionKey);
    try {
      console.log('📤 Sending message:', { 
        contentLength: content.length, 
        hasSessionKey: !!sessionKey,
        contentPreview: content.substring(0, 50) + (content.length > 50 ? '...' : '')
      });

      let messageData: SendMessageRequest = { content };

      // Encrypt message if session key is provided
      if (sessionKey) {
        console.log('🔐 Encrypting message with session key...', {
          content,
          sessionKey,
          sessionKeyLength: sessionKey.length
        });
        const encrypted = encryptMessageForSending(content, sessionKey);
        messageData = {
          encrypted_content: encrypted.encryptedContent,
          iv: encrypted.iv
        };
        // Don't include content field when sending encrypted data
        this.currentSessionKey = sessionKey;
        console.log('✅ Message encrypted:', { 
          encryptedContent: encrypted.encryptedContent.substring(0, 20) + '...',
          iv: encrypted.iv,
          ivLength: encrypted.iv.length
        });
      }

      console.log('🌐 Sending request data:', messageData);
      console.log('🌐 JSON stringified data:', JSON.stringify(messageData));

      const response = await this.makeRequest('/messages/send', {
        method: 'POST',
        body: JSON.stringify(messageData),
      });

      console.log('✅ Message sent successfully:', response);
      return response;
    } catch (error) {
      console.error('❌ Error sending message:', error);
      throw error;
    }
  }

  // Get message history
  async getMessageHistory(page = 1, limit = 50): Promise<MessageHistoryResponse> {
    try {
      const response = await this.makeRequest(
        `/messages/history?page=${page}&limit=${limit}`
      );

      // Decrypt messages if we have a session key
      if (this.currentSessionKey && response.messages) {
        response.messages = response.messages.map((msg: Message) => {
          if (msg.encrypted_content && msg.iv) {
            try {
              const encryptedData: MessageEncryptionData = {
                encryptedContent: msg.encrypted_content,
                iv: msg.iv,
                timestamp: Date.now()
              };
              msg.content = decryptReceivedMessage(encryptedData, this.currentSessionKey!);
            } catch (error) {
              console.warn('Failed to decrypt message:', msg.id, error);
              msg.content = '[Encrypted message - unable to decrypt]';
            }
          }
          return msg;
        });
      }

      return response;
    } catch (error) {
      console.error('Error fetching message history:', error);
      throw error;
    }
  }

  // Set session key for encryption/decryption
  setSessionKey(sessionKey: string): void {
    this.currentSessionKey = sessionKey;
  }

  // Get current session key
  getSessionKey(): string | null {
    return this.currentSessionKey;
  }

  // Real-time connection management
  private notifyConnectionStatus(status: 'connected' | 'disconnected' | 'connecting'): void {
    console.log('🔔 Notifying connection status:', status, 'to', this.connectionStatusListeners.size, 'listeners');
    this.connectionStatusListeners.forEach(listener => listener(status));
  }

  private notifyNewMessage(message: Message): void {
    // Decrypt message if we have session key
    if (this.currentSessionKey && message.encrypted_content && message.iv) {
      try {
        console.log('🔓 Attempting to decrypt message:', {
          messageId: message.id,
          sessionKey: this.currentSessionKey,
          encryptedContent: message.encrypted_content.substring(0, 20) + '...',
          iv: message.iv,
          sessionKeyLength: this.currentSessionKey.length
        });

        const encryptedData: MessageEncryptionData = {
          encryptedContent: message.encrypted_content,
          iv: message.iv,
          timestamp: Date.now()
        };
        message.content = decryptReceivedMessage(encryptedData, this.currentSessionKey);
        console.log('✅ Successfully decrypted message:', message.content);
      } catch (error) {
        console.warn('❌ Failed to decrypt received message:', error);
        console.log('🔍 Debug info:', {
          sessionKey: this.currentSessionKey,
          sessionKeyLength: this.currentSessionKey?.length,
          encryptedContent: message.encrypted_content,
          iv: message.iv
        });
        message.content = '[Encrypted message - unable to decrypt]';
      }
    }

    this.messageListeners.forEach(listener => listener(message));
  }

  // Server-Sent Events connection
  connectSSE(): void {
    if (this.eventSource) {
      this.disconnectSSE();
    }

    const token = authService.getToken();
    console.log('🔑 Auth token check:', {
      hasToken: !!token,
      tokenLength: token?.length || 0,
      tokenPreview: token ? token.substring(0, 20) + '...' : 'none',
      isIncognito: this.isIncognitoMode()
    });
    
    if (!token) {
      console.error('❌ No authentication token available');
      throw new Error('Authentication required for real-time connection');
    }

    console.log('🔄 Starting SSE connection...');
    this.notifyConnectionStatus('connecting');

    try {
      const sseUrl = `${API_BASE_URL}/stream/events?token=${encodeURIComponent(token)}`;
      console.log('🌐 SSE URL:', sseUrl);
      
      // Test the endpoint first
      console.log('🧪 Testing SSE endpoint accessibility...');
      fetch(`${API_BASE_URL}/stream/status`, {
        headers: { Authorization: `Bearer ${token}` }
      }).then(r => console.log('📊 Stream status endpoint:', r.status, r.ok))
       .catch(e => console.error('❌ Stream status test failed:', e));
      
      this.eventSource = new EventSource(sseUrl);
      console.log('📡 EventSource created, readyState:', this.eventSource.readyState);

      this.eventSource.onopen = () => {
        console.log('✅ SSE connection opened successfully!');
        this.notifyConnectionStatus('connected');
      };

      // Handle named SSE events
      this.eventSource.addEventListener('connected', (event) => {
        console.log('SSE connection confirmed by server:', event.data);
        this.notifyConnectionStatus('connected');
      });

      this.eventSource.addEventListener('heartbeat', () => {
        // Update connection status on heartbeat
        this.notifyConnectionStatus('connected');
      });

      this.eventSource.addEventListener('message', (event) => {
        try {
          const data = JSON.parse(event.data);
          this.notifyNewMessage(data);
        } catch (error) {
          console.error('Error parsing message event:', error);
        }
      });

      this.eventSource.addEventListener('user_joined', (event) => {
        console.log('User joined:', event.data);
      });

      this.eventSource.addEventListener('user_left', (event) => {
        console.log('User left:', event.data);
      });

      // Keep the default onmessage handler as fallback for unnamed events
      this.eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // Handle different event types
          if (data.type === 'message' && data.message) {
            this.notifyNewMessage(data.message);
          } else if (data.type === 'connected') {
            console.log('SSE connection confirmed by server (fallback):', data);
            this.notifyConnectionStatus('connected');
          } else if (data.type === 'heartbeat') {
            // Update connection status on heartbeat
            this.notifyConnectionStatus('connected');
          } else if (data.type === 'user_joined' || data.type === 'user_left') {
            // Handle user presence events
            console.log('User presence update:', data);
          }
        } catch (error) {
          console.error('Error parsing SSE message:', error);
        }
      };

      this.eventSource.onerror = (error) => {
        console.error('❌ SSE connection error:', error);
        console.error('📊 SSE readyState:', this.eventSource?.readyState);
        console.error('📋 EventSource states:', { CONNECTING: EventSource.CONNECTING, OPEN: EventSource.OPEN, CLOSED: EventSource.CLOSED });
        this.notifyConnectionStatus('disconnected');
        
        // Attempt to reconnect after 3 seconds
        setTimeout(() => {
          if (this.eventSource?.readyState === EventSource.CLOSED) {
            console.log('🔄 Attempting to reconnect SSE...');
            this.connectSSE();
          }
        }, 3000);
      };

    } catch (error) {
      console.error('Failed to establish SSE connection:', error);
      this.notifyConnectionStatus('disconnected');
      // Fall back to polling
      this.startPolling();
    }
  }

  // Disconnect SSE
  disconnectSSE(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    this.notifyConnectionStatus('disconnected');
  }

  // Long polling fallback
  private async pollMessages(): Promise<void> {
    if (!this.isPolling) return;

    try {
      const response = await this.makeRequest('/stream/poll');
      if (response.messages && response.messages.length > 0) {
        response.messages.forEach((message: Message) => {
          this.notifyNewMessage(message);
        });
      }
    } catch (error) {
      console.error('Polling error:', error);
    }
  }

  startPolling(interval = 2000): void {
    if (this.pollingInterval) {
      this.stopPolling();
    }

    console.log('🔄 Starting polling with interval:', interval);
    this.isPolling = true;
    this.notifyConnectionStatus('connecting');

    this.pollingInterval = window.setInterval(() => {
      this.pollMessages();
    }, interval);

    // Initial poll
    console.log('📊 Running initial poll...');
    this.pollMessages().then(() => {
      console.log('✅ Initial poll successful - setting status to connected');
      this.notifyConnectionStatus('connected');
    }).catch((error) => {
      console.error('❌ Initial poll failed:', error);
      this.notifyConnectionStatus('disconnected');
    });

    console.log('🕐 Started message polling with interval:', interval);
  }

  stopPolling(): void {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
    this.isPolling = false;
    this.notifyConnectionStatus('disconnected');
  }

  // Event listeners
  onMessage(listener: (message: Message) => void): () => void {
    this.messageListeners.add(listener);
    return () => this.messageListeners.delete(listener);
  }

  onConnectionStatus(listener: (status: 'connected' | 'disconnected' | 'connecting') => void): () => void {
    this.connectionStatusListeners.add(listener);
    return () => this.connectionStatusListeners.delete(listener);
  }

  // Cleanup
  disconnect(): void {
    this.disconnectSSE();
    this.stopPolling();
    this.messageListeners.clear();
    this.connectionStatusListeners.clear();
    this.currentSessionKey = null;
  }

  // Check if connected
  isConnected(): boolean {
    return !!(this.eventSource?.readyState === EventSource.OPEN || this.isPolling);
  }

  // Detect incognito mode
  private isIncognitoMode(): boolean {
    try {
      // Check if localStorage throws an error (common in incognito)
      localStorage.setItem('test', 'test');
      localStorage.removeItem('test');
      
      // Check for reduced storage quota (another incognito indicator)
      if ('storage' in navigator && 'estimate' in navigator.storage) {
        return false; // More detailed check could be added here
      }
      
      return false;
    } catch {
      return true; // Likely incognito mode
    }
  }
}

// Export singleton instance
export const messageService = new MessageService();

// Add debug function to global scope
if (typeof window !== 'undefined') {
  (window as any).debugMessageService = {
    status: () => ({
      isConnected: messageService.isConnected(),
      eventSourceState: (messageService as any).eventSource?.readyState,
      isPolling: (messageService as any).isPolling,
      listeners: {
        message: (messageService as any).messageListeners.size,
        status: (messageService as any).connectionStatusListeners.size
      }
    }),
    forceReconnect: () => {
      console.log('🔌 Force reconnecting...');
      messageService.disconnect();
      setTimeout(() => messageService.connectSSE(), 1000);
    },
    forcePolling: () => {
      console.log('🔄 Force polling...');
      messageService.disconnect();
      setTimeout(() => messageService.startPolling(), 1000);
    }
  };
}

export default messageService;