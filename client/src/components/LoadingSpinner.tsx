import React from 'react';
import {
  Box,
  Skeleton,
  Avatar,
  Paper,
  useTheme,
  useMediaQuery
} from '@mui/material';

interface MessageSkeletonProps {
  isMe?: boolean;
}

const MessageSkeleton: React.FC<MessageSkeletonProps> = ({ isMe = false }) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'flex-start',
        flexDirection: isMe ? 'row-reverse' : 'row',
        width: '100%',
        maxWidth: '85%',
        gap: 1,
        mb: 2,
        alignSelf: isMe ? 'flex-end' : 'flex-start'
      }}
    >
      {/* Avatar skeleton */}
      <Avatar
        sx={{
          width: isMobile ? 28 : 32,
          height: isMobile ? 28 : 32,
          flexShrink: 0
        }}
      >
        <Skeleton variant="circular" width="100%" height="100%" />
      </Avatar>

      {/* Message bubble skeleton */}
      <Paper
        elevation={1}
        sx={{
          p: 1.5,
          bgcolor: 'background.paper',
          borderRadius: 2,
          borderTopLeftRadius: isMe ? 2 : 0.5,
          borderTopRightRadius: isMe ? 0.5 : 2,
          maxWidth: '100%',
          minWidth: 120
        }}
      >
        {/* Header with username and timestamp */}
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            mb: 0.5,
            gap: 1
          }}
        >
          <Skeleton variant="text" width={60} height={14} />
          <Skeleton variant="text" width={40} height={12} />
        </Box>

        {/* Message content */}
        <Skeleton variant="text" width="100%" height={16} />
        <Skeleton variant="text" width="80%" height={16} />
      </Paper>
    </Box>
  );
};

interface MessageListSkeletonProps {
  count?: number;
}

export const MessageListSkeleton: React.FC<MessageListSkeletonProps> = ({ 
  count = 5 
}) => {
  return (
    <Box sx={{ p: 1 }}>
      {Array.from({ length: count }).map((_, index) => (
        <MessageSkeleton 
          key={index} 
          isMe={Math.random() > 0.5} // Random message direction
        />
      ))}
    </Box>
  );
};

interface MessageSendingIndicatorProps {
  username: string;
}

export const MessageSendingIndicator: React.FC<MessageSendingIndicatorProps> = ({
  username
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'flex-start',
        flexDirection: 'row-reverse',
        width: '100%',
        maxWidth: '85%',
        gap: 1,
        mb: 2,
        alignSelf: 'flex-end',
        opacity: 0.7
      }}
    >
      <Avatar
        sx={{
          width: isMobile ? 28 : 32,
          height: isMobile ? 28 : 32,
          bgcolor: 'primary.main',
          flexShrink: 0
        }}
      >
        {username?.charAt(0)?.toUpperCase() || 'U'}
      </Avatar>

      <Paper
        elevation={1}
        sx={{
          p: 1.5,
          bgcolor: 'primary.main',
          color: 'primary.contrastText',
          borderRadius: 2,
          borderTopRightRadius: 0.5,
          position: 'relative'
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <Box sx={{ display: 'flex', gap: 0.5 }}>
            {[0, 1, 2].map((i) => (
              <Box
                key={i}
                sx={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  bgcolor: 'primary.contrastText',
                  animation: 'pulse 1.4s infinite',
                  animationDelay: `${i * 0.2}s`,
                  '@keyframes pulse': {
                    '0%, 80%, 100%': {
                      opacity: 0.3,
                      transform: 'scale(1)'
                    },
                    '40%': {
                      opacity: 1,
                      transform: 'scale(1.2)'
                    }
                  }
                }}
              />
            ))}
          </Box>
          <Box
            component="span"
            sx={{
              ml: 1,
              fontSize: '0.75rem',
              opacity: 0.8
            }}
          >
            Sending...
          </Box>
        </Box>
      </Paper>
    </Box>
  );
};

interface LoadingSpinnerProps {
  size?: number;
  message?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  size = 40, 
  message = 'Loading...' 
}) => {
  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        p: 3,
        gap: 2
      }}
    >
      <Box
        sx={{
          width: size,
          height: size,
          border: '3px solid',
          borderColor: 'primary.light',
          borderTopColor: 'primary.main',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          '@keyframes spin': {
            '0%': {
              transform: 'rotate(0deg)'
            },
            '100%': {
              transform: 'rotate(360deg)'
            }
          }
        }}
      />
      {message && (
        <Box
          component="span"
          sx={{
            fontSize: '0.875rem',
            color: 'text.secondary'
          }}
        >
          {message}
        </Box>
      )}
    </Box>
  );
};

export default LoadingSpinner;