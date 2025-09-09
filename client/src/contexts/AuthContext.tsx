import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authService, User, LoginRequest, RegisterRequest, ApiError } from '../services/authService';

export interface AuthContextType {
  // State
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  
  // Actions
  login: (credentials: LoginRequest) => Promise<void>;
  register: (userData: RegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize authentication state
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        setIsLoading(true);
        
        // Check if user has valid token
        const isValidToken = await authService.validateToken();
        
        if (isValidToken) {
          const userData = authService.getUser();
          setUser(userData);
        } else {
          // Clear any invalid data
          authService.removeToken();
          setUser(null);
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        // Clear invalid data on error
        authService.removeToken();
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []);

  const login = async (credentials: LoginRequest): Promise<void> => {
    try {
      const response = await authService.login(credentials);
      setUser(response.user);
    } catch (error) {
      // Re-throw error to be handled by the component
      throw error as ApiError;
    }
  };

  const register = async (userData: RegisterRequest): Promise<void> => {
    try {
      const response = await authService.register(userData);
      setUser(response.user);
    } catch (error) {
      // Re-throw error to be handled by the component
      throw error as ApiError;
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await authService.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Always clear user state
      setUser(null);
    }
  };

  const refreshUser = async (): Promise<void> => {
    try {
      const userData = await authService.getProfile();
      setUser(userData);
    } catch (error) {
      console.error('User refresh error:', error);
      // If refresh fails, user might be logged out
      setUser(null);
      authService.removeToken();
      throw error as ApiError;
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    register,
    logout,
    refreshUser,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;