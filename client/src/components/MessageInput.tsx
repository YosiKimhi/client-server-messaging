import React, { useState, useRef, useCallback } from 'react';
import {
  Box,
  TextField,
  Button,
  Paper,
  IconButton,
  Tooltip,
  CircularProgress,
  Chip,
  Typography
} from '@mui/material';
import {
  Send as SendIcon,
  AttachFile as AttachIcon,
  EmojiEmotions as EmojiIcon,
  Lock as EncryptedIcon,
  LockOpen as UnencryptedIcon,
  KeyboardReturn as EnterIcon
} from '@mui/icons-material';

interface MessageInputProps {
  onSendMessage: (content: string) => Promise<boolean>;
  disabled?: boolean;
  isSending?: boolean;
  placeholder?: string;
  maxLength?: number;
  showEncryptionStatus?: boolean;
  isEncrypted?: boolean;
  connectionStatus?: 'connected' | 'disconnected' | 'connecting';
}

const MessageInput: React.FC<MessageInputProps> = ({
  onSendMessage,
  disabled = false,
  isSending = false,
  placeholder = "Type your message...",
  maxLength = 1000,
  showEncryptionStatus = true,
  isEncrypted = true,
  connectionStatus = 'connected'
}) => {
  const [message, setMessage] = useState('');
  const [isMultiline, setIsMultiline] = useState(false);
  const textFieldRef = useRef<HTMLTextAreaElement>(null);

  // Handle message sending
  const handleSendMessage = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!message.trim() || isSending || disabled) {
      return;
    }

    const messageToSend = message.trim();
    setMessage(''); // Clear input immediately for better UX
    
    try {
      const success = await onSendMessage(messageToSend);
      if (!success) {
        // Restore message if sending failed
        setMessage(messageToSend);
      }
    } catch (error) {
      // Restore message if sending failed
      setMessage(messageToSend);
      console.error('Error sending message:', error);
    }
  }, [message, isSending, disabled, onSendMessage]);

  // Handle key press events
  const handleKeyPress = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      if (e.shiftKey) {
        // Shift+Enter: Add new line
        setIsMultiline(true);
      } else if (!e.ctrlKey && !e.altKey) {
        // Enter: Send message
        e.preventDefault();
        handleSendMessage(e);
      }
    }
  }, [handleSendMessage]);

  // Handle input change
  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    
    // Respect max length
    if (value.length <= maxLength) {
      setMessage(value);
    }
    
    // Update multiline state based on content
    setIsMultiline(value.includes('\n') || value.length > 50);
  }, [maxLength]);

  // Character count color
  const getCharCountColor = () => {
    const remaining = maxLength - message.length;
    if (remaining < 50) return 'error';
    if (remaining < 100) return 'warning';
    return 'text.secondary';
  };

  // Connection status message
  const getConnectionMessage = () => {
    switch (connectionStatus) {
      case 'connecting':
        return 'Connecting...';
      case 'disconnected':
        return 'Disconnected - messages may not be delivered';
      case 'connected':
        return null;
      default:
        return null;
    }
  };

  const connectionMessage = getConnectionMessage();
  const isConnected = connectionStatus === 'connected';
  const canSend = message.trim() && !isSending && !disabled && isConnected;

  return (
    <Paper 
      elevation={2} 
      sx={{ 
        p: 2,
        borderTop: 1,
        borderColor: 'divider'
      }}
    >
      {/* Connection status warning */}
      {connectionMessage && (
        <Box sx={{ mb: 1 }}>
          <Chip
            label={connectionMessage}
            size="small"
            color={connectionStatus === 'connecting' ? 'info' : 'error'}
            variant="outlined"
            sx={{ fontSize: '0.75rem' }}
          />
        </Box>
      )}

      <form onSubmit={handleSendMessage}>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-end' }}>
          {/* Message input field */}
          <Box sx={{ flex: 1, position: 'relative' }}>
            <TextField
              inputRef={textFieldRef}
              fullWidth
              variant="outlined"
              placeholder={disabled ? "Chat is disabled" : placeholder}
              value={message}
              onChange={handleInputChange}
              onKeyDown={handleKeyPress}
              disabled={disabled || !isConnected}
              size="small"
              multiline
              minRows={1}
              maxRows={isMultiline ? 4 : 1}
              sx={{
                '& .MuiOutlinedInput-root': {
                  paddingRight: '50px', // Space for character count
                },
              }}
            />
            
            {/* Character count */}
            {maxLength > 0 && (
              <Typography
                variant="caption"
                sx={{
                  position: 'absolute',
                  bottom: 8,
                  right: 12,
                  color: getCharCountColor(),
                  fontSize: '0.7rem',
                  userSelect: 'none',
                  pointerEvents: 'none'
                }}
              >
                {message.length}/{maxLength}
              </Typography>
            )}
          </Box>

          {/* Additional action buttons */}
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
            {/* Encryption status */}
            {showEncryptionStatus && (
              <Tooltip 
                title={isEncrypted ? "Messages are encrypted" : "Messages are not encrypted"}
              >
                <IconButton size="small" disabled>
                  {isEncrypted ? (
                    <EncryptedIcon fontSize="small" color="success" />
                  ) : (
                    <UnencryptedIcon fontSize="small" color="warning" />
                  )}
                </IconButton>
              </Tooltip>
            )}
          </Box>

          {/* Send button */}
          <Button
            type="submit"
            variant="contained"
            disabled={!canSend}
            sx={{
              minWidth: 'auto',
              px: 2,
              height: 40,
              alignSelf: 'flex-end'
            }}
          >
            {isSending ? (
              <CircularProgress size={20} color="inherit" />
            ) : (
              <SendIcon fontSize="small" />
            )}
          </Button>
        </Box>

        {/* Keyboard shortcuts help */}
        {message.length === 0 && (
          <Box
            sx={{
              mt: 1,
              display: 'flex',
              justifyContent: 'center',
              gap: 2
            }}
          >
            <Chip
              icon={<EnterIcon sx={{ fontSize: '14px !important' }} />}
              label="Send"
              size="small"
              variant="outlined"
              sx={{ fontSize: '0.7rem', height: 20 }}
            />
            <Chip
              label="Shift+Enter for new line"
              size="small"
              variant="outlined"
              sx={{ fontSize: '0.7rem', height: 20 }}
            />
          </Box>
        )}
      </form>
    </Paper>
  );
};

export default MessageInput;