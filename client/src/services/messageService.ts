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
  content: string;
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
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorMessage;
        } catch {
          errorMessage = response.statusText;
        }
        
        const error: ApiError = {
          message: errorMessage,
          status: response.status,
        };
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
    try {
      let messageData: SendMessageRequest = { content };

      // Encrypt message if session key is provided
      if (sessionKey) {
        const encrypted = encryptMessageForSending(content, sessionKey);
        messageData = {
          content: '', // Clear text content when encrypted
          encrypted_content: encrypted.encryptedContent,
          iv: encrypted.iv
        };
        this.currentSessionKey = sessionKey;
      }

      const response = await this.makeRequest('/messages/send', {
        method: 'POST',
        body: JSON.stringify(messageData),
      });

      return response;
    } catch (error) {
      console.error('Error sending message:', error);
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
    this.connectionStatusListeners.forEach(listener => listener(status));
  }

  private notifyNewMessage(message: Message): void {
    // Decrypt message if we have session key
    if (this.currentSessionKey && message.encrypted_content && message.iv) {
      try {
        const encryptedData: MessageEncryptionData = {
          encryptedContent: message.encrypted_content,
          iv: message.iv,
          timestamp: Date.now()
        };
        message.content = decryptReceivedMessage(encryptedData, this.currentSessionKey);
      } catch (error) {
        console.warn('Failed to decrypt received message:', error);
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
    if (!token) {
      throw new Error('Authentication required for real-time connection');
    }

    this.notifyConnectionStatus('connecting');

    try {
      this.eventSource = new EventSource(
        `${API_BASE_URL}/stream/events?token=${encodeURIComponent(token)}`
      );

      this.eventSource.onopen = () => {
        console.log('SSE connection opened');
        this.notifyConnectionStatus('connected');
      };

      this.eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'message' && data.message) {
            this.notifyNewMessage(data.message);
          }
        } catch (error) {
          console.error('Error parsing SSE message:', error);
        }
      };

      this.eventSource.onerror = (error) => {
        console.error('SSE connection error:', error);
        this.notifyConnectionStatus('disconnected');
        
        // Attempt to reconnect after 3 seconds
        setTimeout(() => {
          if (this.eventSource?.readyState === EventSource.CLOSED) {
            console.log('Attempting to reconnect SSE...');
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

    this.isPolling = true;
    this.notifyConnectionStatus('connecting');

    this.pollingInterval = window.setInterval(() => {
      this.pollMessages();
    }, interval);

    // Initial poll
    this.pollMessages().then(() => {
      this.notifyConnectionStatus('connected');
    }).catch(() => {
      this.notifyConnectionStatus('disconnected');
    });

    console.log('Started message polling with interval:', interval);
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
}

// Export singleton instance
export const messageService = new MessageService();
export default messageService;