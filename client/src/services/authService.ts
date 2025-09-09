// Authentication service for API communication
import { storeUserPrivateKey, parseEncryptedPrivateKeyData, cleanupEncryptionData } from '../utils/encryption';

const API_BASE_URL = 'http://localhost:3001/api';

export interface User {
  id: string;
  username: string;
  email: string;
  private_key_encrypted?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  public_key: string;
  private_key_encrypted: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface ApiError {
  message: string;
  status: number;
}

class AuthService {
  private tokenKey = 'auth_token';
  private userKey = 'auth_user';

  // Token management
  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  setToken(token: string): void {
    localStorage.setItem(this.tokenKey, token);
  }

  removeToken(): void {
    const currentUser = this.getUser();
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.userKey);
    
    // Clean up encryption data when token is removed
    if (currentUser) {
      try {
        cleanupEncryptionData(currentUser.id);
      } catch (error) {
        console.error('Failed to cleanup encryption data during token removal:', error);
      }
    }
  }

  // User management
  getUser(): User | null {
    const userStr = localStorage.getItem(this.userKey);
    return userStr ? JSON.parse(userStr) : null;
  }

  setUser(user: User): void {
    localStorage.setItem(this.userKey, JSON.stringify(user));
  }

  // Check if user is authenticated
  isAuthenticated(): boolean {
    const token = this.getToken();
    const user = this.getUser();
    return !!(token && user);
  }

  // API helper with authentication
  private async makeRequest(url: string, options: RequestInit = {}): Promise<any> {
    const token = this.getToken();
    
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

  // Authentication methods
  async login(credentials: LoginRequest): Promise<AuthResponse> {
    const response = await this.makeRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });

    // Extract auth data from server response (server wraps response in data field)
    const authData = response.data || response;

    // Store token and user data
    this.setToken(authData.token);
    this.setUser(authData.user);

    // Store encrypted private key locally if returned from server
    if (authData.user.private_key_encrypted) {
      try {
        const encryptedPrivateKeyData = parseEncryptedPrivateKeyData(authData.user.private_key_encrypted);
        storeUserPrivateKey(authData.user.id, encryptedPrivateKeyData);
      } catch (error) {
        console.error('Failed to store encrypted private key during login:', error);
        // Don't fail login if key storage fails, just log the error
      }
    }

    return authData;
  }

  async register(userData: RegisterRequest): Promise<AuthResponse> {
    const response = await this.makeRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });

    // Extract auth data from server response (server wraps response in data field)
    const authData = response.data || response;

    // Store token and user data
    this.setToken(authData.token);
    this.setUser(authData.user);

    // Store encrypted private key locally for this user
    try {
      const encryptedPrivateKeyData = parseEncryptedPrivateKeyData(userData.private_key_encrypted);
      storeUserPrivateKey(authData.user.id, encryptedPrivateKeyData);
    } catch (error) {
      console.error('Failed to store encrypted private key:', error);
      // Don't fail registration if key storage fails, just log the error
    }

    return authData;
  }

  async logout(): Promise<void> {
    const currentUser = this.getUser();
    
    try {
      // Call logout endpoint if authenticated
      if (this.isAuthenticated()) {
        await this.makeRequest('/auth/logout', {
          method: 'POST',
        });
      }
    } catch (error) {
      // Continue with logout even if API call fails
      console.warn('Logout API call failed:', error);
    } finally {
      // Always clear local storage
      this.removeToken();
      
      // Clean up encryption data for the current user
      if (currentUser) {
        try {
          cleanupEncryptionData(currentUser.id);
        } catch (error) {
          console.error('Failed to cleanup encryption data:', error);
        }
      }
    }
  }

  async getProfile(): Promise<User> {
    const response = await this.makeRequest('/auth/profile');
    
    // Extract data from server response (server wraps response in data field)
    const userData = response.data || response.user || response;
    
    // Update stored user data
    this.setUser(userData);
    
    return userData;
  }

  // Utility method to handle token expiry
  async validateToken(): Promise<boolean> {
    if (!this.isAuthenticated()) {
      return false;
    }

    try {
      await this.getProfile();
      return true;
    } catch (error) {
      // If token is invalid, clear it
      this.removeToken();
      return false;
    }
  }
}

// Export singleton instance
export const authService = new AuthService();
export default authService;