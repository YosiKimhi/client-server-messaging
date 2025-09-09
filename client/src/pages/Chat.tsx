import React, { useState, useRef, useEffect } from 'react'
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  List,
  ListItem,
  ListItemText,
  Divider,
  AppBar,
  Toolbar,
  IconButton
} from '@mui/material'
import { Send as SendIcon, ExitToApp as LogoutIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'

interface Message {
  id: string
  username: string
  content: string
  timestamp: Date
}

const Chat: React.FC = () => {
  const navigate = useNavigate()
  const [message, setMessage] = useState('')
  const [messages, setMessages] = useState<Message[]>([])
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!message.trim()) return

    // TODO: Implement message sending logic
    const newMessage: Message = {
      id: Date.now().toString(),
      username: 'Current User', // TODO: Get from auth context
      content: message,
      timestamp: new Date()
    }

    setMessages(prev => [...prev, newMessage])
    setMessage('')
    
    console.log('Sending message:', message)
  }

  const handleLogout = () => {
    // TODO: Implement logout logic
    navigate('/login')
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '80vh' }}>
      {/* Chat Header */}
      <AppBar position="static" color="default" elevation={1}>
        <Toolbar variant="dense">
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Chat Room
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

      {/* Messages Area */}
      <Paper
        sx={{
          flex: 1,
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          mb: 2
        }}
        elevation={2}
      >
        <Box sx={{ flex: 1, overflow: 'auto', p: 1 }}>
          {messages.length === 0 ? (
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: '100%'
              }}
            >
              <Typography variant="body2" color="text.secondary">
                No messages yet. Start the conversation!
              </Typography>
            </Box>
          ) : (
            <List>
              {messages.map((msg, index) => (
                <React.Fragment key={msg.id}>
                  <ListItem alignItems="flex-start">
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                          <Typography component="span" variant="subtitle2">
                            {msg.username}
                          </Typography>
                          <Typography component="span" variant="caption" color="text.secondary">
                            {msg.timestamp.toLocaleTimeString()}
                          </Typography>
                        </Box>
                      }
                      secondary={
                        <Typography
                          component="span"
                          variant="body2"
                          color="text.primary"
                          sx={{ wordWrap: 'break-word' }}
                        >
                          {msg.content}
                        </Typography>
                      }
                    />
                  </ListItem>
                  {index < messages.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          )}
          <div ref={messagesEndRef} />
        </Box>
      </Paper>

      {/* Message Input */}
      <Paper elevation={2} sx={{ p: 2 }}>
        <form onSubmit={handleSendMessage}>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <TextField
              fullWidth
              variant="outlined"
              placeholder="Type your message..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              size="small"
              multiline
              maxRows={3}
            />
            <Button
              type="submit"
              variant="contained"
              endIcon={<SendIcon />}
              disabled={!message.trim()}
              sx={{ minWidth: 'auto', px: 3 }}
            >
              Send
            </Button>
          </Box>
        </form>
      </Paper>
    </Box>
  )
}

export default Chat