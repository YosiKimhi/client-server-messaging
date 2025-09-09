import React, { useEffect } from 'react'
import {
  Box,
  Paper,
  Typography,
  AppBar,
  Toolbar,
  IconButton,
  Alert,
  Button
} from '@mui/material'
import { ExitToApp as LogoutIcon, Refresh as RefreshIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { useRealTimeMessages } from '../hooks/useRealTimeMessages'
import MessageList from '../components/MessageList'
import MessageInput from '../components/MessageInput'
import ConnectionStatus from '../components/ConnectionStatus'

const Chat: React.FC = () => {
  const navigate = useNavigate()
  const { logout, user } = useAuth()
  const realTimeMessages = useRealTimeMessages()

  const {
    state: {
      messages,
      connectionStatus,
      connectionMode,
      isLoading,
      error,
      isSending
    },
    sendMessage,
    loadMessageHistory,
    clearError,
    reconnect,
    switchToSSE,
    switchToPolling
  } = realTimeMessages

  // Load message history on mount
  useEffect(() => {
    if (user) {
      loadMessageHistory()
    }
  }, [user, loadMessageHistory])

  const handleSendMessage = async (content: string): Promise<boolean> => {
    return await sendMessage(content)
  }

  const handleLogout = async () => {
    try {
      await logout()
      navigate('/login', { replace: true })
    } catch (error) {
      console.error('Logout error:', error)
      // Force navigation even if logout fails
      navigate('/login', { replace: true })
    }
  }

  const handleRetry = () => {
    clearError()
    loadMessageHistory()
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      {/* Chat Header */}
      <AppBar position="static" color="default" elevation={1}>
        <Toolbar variant="dense">
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Secure Chat Room
          </Typography>
          
          {/* Connection Status */}
          <Box sx={{ mr: 2 }}>
            <ConnectionStatus
              status={connectionStatus}
              mode={connectionMode}
              onSwitchToSSE={switchToSSE}
              onSwitchToPolling={switchToPolling}
              onReconnect={reconnect}
              compact
            />
          </Box>

          {/* User info */}
          <Typography variant="body2" sx={{ mr: 2, opacity: 0.8 }}>
            {user?.username}
          </Typography>

          <IconButton 
            edge="end" 
            color="inherit" 
            onClick={handleLogout}
            title="Logout"
          >
            <LogoutIcon />
          </IconButton>
        </Toolbar>
      </AppBar>

      {/* Error Alert */}
      {error && (
        <Alert 
          severity="error" 
          onClose={clearError}
          action={
            <Button color="inherit" size="small" onClick={handleRetry}>
              <RefreshIcon fontSize="small" sx={{ mr: 0.5 }} />
              Retry
            </Button>
          }
          sx={{ m: 1 }}
        >
          {error}
        </Alert>
      )}

      {/* Messages Area */}
      <Paper
        sx={{
          flex: 1,
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          m: 1,
          mb: 0
        }}
        elevation={2}
      >
        <MessageList
          messages={messages}
          isLoading={isLoading}
          error={connectionStatus === 'disconnected' ? 'Connection lost - messages may not be current' : null}
          onRetry={handleRetry}
          showEncryptionStatus={true}
        />
      </Paper>

      {/* Message Input */}
      <MessageInput
        onSendMessage={handleSendMessage}
        disabled={!user}
        isSending={isSending}
        placeholder={user ? "Type your encrypted message..." : "Please log in to send messages"}
        connectionStatus={connectionStatus}
        isEncrypted={true}
        showEncryptionStatus={true}
      />
    </Box>
  )
}

export default Chat