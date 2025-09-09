import React, { useEffect, useRef } from 'react';
import {
  Box,
  List,
  ListItem,
  ListItemText,
  Typography,
  Divider,
  Paper,
  Avatar,
  Chip,
  CircularProgress,
  Button
} from '@mui/material';
import {
  LockOutlined as EncryptedIcon,
  Person as PersonIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { Message } from '../services/messageService';
import { useAuth } from '../contexts/AuthContext';

interface MessageListProps {
  messages: Message[];
  isLoading?: boolean;
  error?: string | null;
  onLoadMore?: () => void;
  onRetry?: () => void;
  showEncryptionStatus?: boolean;
}

const MessageList: React.FC<MessageListProps> = ({
  messages,
  isLoading = false,
  error = null,
  onLoadMore,
  onRetry,
  showEncryptionStatus = true
}) => {
  const { user } = useAuth();
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const listContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Format timestamp
  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffInHours = (now.getTime() - date.getTime()) / (1000 * 60 * 60);

    if (diffInHours < 1) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (diffInHours < 24) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else {
      return date.toLocaleDateString([], { 
        month: 'short', 
        day: 'numeric',
        hour: '2-digit', 
        minute: '2-digit' 
      });
    }
  };

  // Get initials from username
  const getUserInitials = (username: string): string => {
    return username
      .split(' ')
      .map(name => name.charAt(0))
      .slice(0, 2)
      .join('')
      .toUpperCase();
  };

  // Check if message is from current user
  const isMyMessage = (message: Message): boolean => {
    return user?.username === message.username;
  };

  // Check if message is encrypted
  const isEncrypted = (message: Message): boolean => {
    return !!(message.encrypted_content && message.iv);
  };

  // Handle scroll to detect when user scrolls to top
  const handleScroll = () => {
    if (listContainerRef.current && onLoadMore) {
      const { scrollTop } = listContainerRef.current;
      if (scrollTop === 0 && !isLoading) {
        onLoadMore();
      }
    }
  };

  // Empty state
  if (messages.length === 0 && !isLoading && !error) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100%',
          p: 3,
          textAlign: 'center'
        }}
      >
        <PersonIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
        <Typography variant="h6" color="text.secondary" gutterBottom>
          No messages yet
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Start the conversation by sending your first message!
        </Typography>
      </Box>
    );
  }

  // Error state
  if (error && messages.length === 0) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100%',
          p: 3,
          textAlign: 'center'
        }}
      >
        <Typography variant="h6" color="error" gutterBottom>
          Failed to load messages
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {error}
        </Typography>
        {onRetry && (
          <Button 
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={onRetry}
          >
            Retry
          </Button>
        )}
      </Box>
    );
  }

  return (
    <Box
      ref={listContainerRef}
      sx={{ 
        flex: 1, 
        overflow: 'auto', 
        p: 1,
        '&::-webkit-scrollbar': {
          width: '6px',
        },
        '&::-webkit-scrollbar-track': {
          background: 'rgba(0,0,0,0.1)',
        },
        '&::-webkit-scrollbar-thumb': {
          background: 'rgba(0,0,0,0.3)',
          borderRadius: '3px',
        },
      }}
      onScroll={handleScroll}
    >
      {/* Loading indicator at top */}
      {isLoading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 2 }}>
          <CircularProgress size={24} />
        </Box>
      )}

      <List sx={{ p: 0 }}>
        {messages.map((message, index) => {
          const isMe = isMyMessage(message);
          const showDivider = index < messages.length - 1;
          const encrypted = isEncrypted(message);

          return (
            <React.Fragment key={message.id}>
              <ListItem
                sx={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: isMe ? 'flex-end' : 'flex-start',
                  px: 1,
                  py: 1.5,
                }}
              >
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    flexDirection: isMe ? 'row-reverse' : 'row',
                    width: '100%',
                    maxWidth: '85%',
                    gap: 1
                  }}
                >
                  {/* Avatar */}
                  <Avatar
                    sx={{
                      width: 32,
                      height: 32,
                      fontSize: '0.875rem',
                      bgcolor: isMe ? 'primary.main' : 'secondary.main',
                      flexShrink: 0
                    }}
                  >
                    {getUserInitials(message.username)}
                  </Avatar>

                  {/* Message bubble */}
                  <Paper
                    elevation={1}
                    sx={{
                      p: 1.5,
                      bgcolor: isMe ? 'primary.main' : 'background.paper',
                      color: isMe ? 'primary.contrastText' : 'text.primary',
                      borderRadius: 2,
                      borderTopLeftRadius: isMe ? 2 : 0.5,
                      borderTopRightRadius: isMe ? 0.5 : 2,
                      maxWidth: '100%',
                      wordBreak: 'break-word',
                      position: 'relative'
                    }}
                  >
                    {/* Username and timestamp */}
                    <Box
                      sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        mb: 0.5,
                        gap: 1
                      }}
                    >
                      <Typography
                        variant="caption"
                        sx={{
                          fontWeight: 600,
                          opacity: 0.9,
                          color: isMe ? 'primary.contrastText' : 'text.secondary'
                        }}
                      >
                        {isMe ? 'You' : message.username}
                      </Typography>
                      
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        {/* Encryption indicator */}
                        {showEncryptionStatus && encrypted && (
                          <EncryptedIcon
                            sx={{
                              fontSize: 12,
                              color: isMe ? 'primary.contrastText' : 'text.secondary',
                              opacity: 0.7
                            }}
                          />
                        )}
                        
                        <Typography
                          variant="caption"
                          sx={{
                            opacity: 0.7,
                            fontSize: '0.75rem',
                            color: isMe ? 'primary.contrastText' : 'text.secondary'
                          }}
                        >
                          {formatTimestamp(message.timestamp)}
                        </Typography>
                      </Box>
                    </Box>

                    {/* Message content */}
                    <Typography
                      variant="body2"
                      sx={{
                        color: isMe ? 'primary.contrastText' : 'text.primary',
                        whiteSpace: 'pre-wrap'
                      }}
                    >
                      {message.content}
                    </Typography>

                    {/* Encryption status chip */}
                    {showEncryptionStatus && encrypted && (
                      <Chip
                        label="Encrypted"
                        size="small"
                        icon={<EncryptedIcon sx={{ fontSize: '12px !important' }} />}
                        sx={{
                          mt: 1,
                          height: 18,
                          fontSize: '0.6875rem',
                          bgcolor: isMe ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.1)',
                          color: isMe ? 'primary.contrastText' : 'text.secondary',
                          '& .MuiChip-icon': {
                            color: 'inherit'
                          }
                        }}
                      />
                    )}
                  </Paper>
                </Box>
              </ListItem>
              
              {showDivider && (
                <Divider 
                  sx={{ 
                    my: 0.5,
                    opacity: 0.3 
                  }} 
                />
              )}
            </React.Fragment>
          );
        })}
      </List>

      {/* Error message overlay */}
      {error && messages.length > 0 && (
        <Box
          sx={{
            position: 'sticky',
            bottom: 0,
            bgcolor: 'error.main',
            color: 'error.contrastText',
            p: 1,
            textAlign: 'center',
            zIndex: 1
          }}
        >
          <Typography variant="caption">
            {error}
          </Typography>
        </Box>
      )}

      {/* Scroll anchor */}
      <div ref={messagesEndRef} />
    </Box>
  );
};

export default MessageList;