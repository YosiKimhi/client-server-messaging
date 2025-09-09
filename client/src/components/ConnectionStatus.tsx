import React from 'react';
import {
  Box,
  Chip,
  IconButton,
  Menu,
  MenuItem,
  Typography,
  Divider,
  Tooltip,
  Alert
} from '@mui/material';
import {
  Wifi as ConnectedIcon,
  WifiOff as DisconnectedIcon,
  Sync as ConnectingIcon,
  Settings as SettingsIcon,
  SignalWifi4Bar as SSEIcon,
  Refresh as PollingIcon,
  Warning as WarningIcon
} from '@mui/icons-material';
import { ConnectionStatus as StatusType, ConnectionMode } from '../hooks/useRealTimeMessages';

interface ConnectionStatusProps {
  status: StatusType;
  mode: ConnectionMode;
  onSwitchToSSE?: () => void;
  onSwitchToPolling?: () => void;
  onReconnect?: () => void;
  showDetails?: boolean;
  compact?: boolean;
}

const ConnectionStatus: React.FC<ConnectionStatusProps> = ({
  status,
  mode,
  onSwitchToSSE,
  onSwitchToPolling,
  onReconnect,
  showDetails = false,
  compact = false
}) => {
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleSwitchMode = (newMode: 'sse' | 'polling') => {
    if (newMode === 'sse' && onSwitchToSSE) {
      onSwitchToSSE();
    } else if (newMode === 'polling' && onSwitchToPolling) {
      onSwitchToPolling();
    }
    handleClose();
  };

  const handleReconnect = () => {
    if (onReconnect) {
      onReconnect();
    }
    handleClose();
  };

  // Get status configuration
  const getStatusConfig = () => {
    switch (status) {
      case 'connected':
        return {
          color: 'success' as const,
          icon: <ConnectedIcon fontSize="small" />,
          label: 'Connected',
          description: 'Real-time messaging is active'
        };
      case 'connecting':
        return {
          color: 'info' as const,
          icon: <ConnectingIcon fontSize="small" className="rotating" />,
          label: 'Connecting',
          description: 'Establishing connection...'
        };
      case 'disconnected':
        return {
          color: 'error' as const,
          icon: <DisconnectedIcon fontSize="small" />,
          label: 'Disconnected',
          description: 'Real-time messaging is unavailable'
        };
      default:
        return {
          color: 'default' as const,
          icon: <WarningIcon fontSize="small" />,
          label: 'Unknown',
          description: 'Connection status unknown'
        };
    }
  };

  // Get mode configuration
  const getModeConfig = () => {
    switch (mode) {
      case 'sse':
        return {
          icon: <SSEIcon fontSize="small" />,
          label: 'Server-Sent Events',
          description: 'Low latency, real-time updates'
        };
      case 'polling':
        return {
          icon: <PollingIcon fontSize="small" />,
          label: 'Polling',
          description: 'Periodic updates, compatible fallback'
        };
      case 'none':
        return {
          icon: <DisconnectedIcon fontSize="small" />,
          label: 'No Connection',
          description: 'Not connected to real-time updates'
        };
      default:
        return {
          icon: <WarningIcon fontSize="small" />,
          label: 'Unknown',
          description: 'Connection mode unknown'
        };
    }
  };

  const statusConfig = getStatusConfig();
  const modeConfig = getModeConfig();

  if (compact) {
    return (
      <Tooltip title={`${statusConfig.label} (${modeConfig.label})`}>
        <Chip
          icon={statusConfig.icon}
          label={statusConfig.label}
          color={statusConfig.color}
          size="small"
          variant="outlined"
          sx={{ fontSize: '0.75rem' }}
        />
      </Tooltip>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        {/* Status chip */}
        <Chip
          icon={statusConfig.icon}
          label={statusConfig.label}
          color={statusConfig.color}
          size="small"
          variant={status === 'connected' ? 'filled' : 'outlined'}
        />

        {/* Mode indicator */}
        <Tooltip title={modeConfig.description}>
          <Chip
            icon={modeConfig.icon}
            label={modeConfig.label}
            size="small"
            variant="outlined"
            sx={{ fontSize: '0.75rem' }}
          />
        </Tooltip>

        {/* Settings button */}
        <IconButton
          size="small"
          onClick={handleClick}
          sx={{ ml: 0.5 }}
        >
          <SettingsIcon fontSize="small" />
        </IconButton>
      </Box>

      {/* Connection settings menu */}
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        PaperProps={{
          sx: { minWidth: 250 }
        }}
      >
        <Box sx={{ p: 2 }}>
          <Typography variant="subtitle2" gutterBottom>
            Connection Status
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            {statusConfig.description}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Mode: {modeConfig.description}
          </Typography>
        </Box>

        <Divider />

        {/* Connection actions */}
        <MenuItem onClick={handleReconnect} disabled={status === 'connecting'}>
          <ConnectingIcon sx={{ mr: 1 }} />
          Reconnect
        </MenuItem>

        <Divider />

        {/* Mode switching */}
        <Box sx={{ p: 1 }}>
          <Typography variant="subtitle2" sx={{ px: 1, py: 0.5 }}>
            Connection Mode
          </Typography>
        </Box>

        <MenuItem
          onClick={() => handleSwitchMode('sse')}
          disabled={!window.EventSource || mode === 'sse'}
          selected={mode === 'sse'}
        >
          <SSEIcon sx={{ mr: 1 }} />
          <Box>
            <Typography variant="body2">Server-Sent Events</Typography>
            <Typography variant="caption" color="text.secondary">
              {!window.EventSource ? 'Not supported' : 'Recommended for real-time updates'}
            </Typography>
          </Box>
        </MenuItem>

        <MenuItem
          onClick={() => handleSwitchMode('polling')}
          disabled={mode === 'polling'}
          selected={mode === 'polling'}
        >
          <PollingIcon sx={{ mr: 1 }} />
          <Box>
            <Typography variant="body2">Long Polling</Typography>
            <Typography variant="caption" color="text.secondary">
              Fallback mode, universal compatibility
            </Typography>
          </Box>
        </MenuItem>
      </Menu>

      {/* Detailed status information */}
      {showDetails && (
        <Box sx={{ mt: 1 }}>
          {status === 'disconnected' && (
            <Alert severity="warning" sx={{ fontSize: '0.875rem' }}>
              Real-time messaging is disconnected. Messages may not appear immediately.
            </Alert>
          )}
          
          {status === 'connecting' && (
            <Alert severity="info" sx={{ fontSize: '0.875rem' }}>
              Establishing connection for real-time updates...
            </Alert>
          )}

          {mode === 'polling' && status === 'connected' && (
            <Alert severity="info" sx={{ fontSize: '0.875rem' }}>
              Using polling mode. Messages may have a slight delay.
            </Alert>
          )}
        </Box>
      )}

      {/* CSS for rotating animation */}
      <style>
        {`
          @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
          .rotating {
            animation: rotate 1s linear infinite;
          }
        `}
      </style>
    </Box>
  );
};

export default ConnectionStatus;