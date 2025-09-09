import React from 'react'
import { AppBar, Toolbar, Typography, Container, Box, Button } from '@mui/material'
import { useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'

interface LayoutProps {
  children: React.ReactNode
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation()
  const navigate = useNavigate()
  const { isAuthenticated, user, logout } = useAuth()
  
  const getPageTitle = () => {
    switch (location.pathname) {
      case '/login':
        return 'Login'
      case '/register':
        return 'Register'
      case '/chat':
        return 'Secure Messaging'
      default:
        return 'Secure Messaging'
    }
  }

  const handleLogout = async () => {
    try {
      await logout()
      navigate('/login', { replace: true })
    } catch (error) {
      console.error('Logout error:', error)
      // Navigate to login even if logout API fails
      navigate('/login', { replace: true })
    }
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            {getPageTitle()}
          </Typography>
          
          {isAuthenticated && user && (
            <>
              <Typography variant="body2" sx={{ mr: 2 }}>
                Welcome, {user.username}
              </Typography>
              <Button 
                color="inherit" 
                onClick={handleLogout}
                variant="outlined"
                size="small"
              >
                Logout
              </Button>
            </>
          )}
        </Toolbar>
      </AppBar>
      
      <Container 
        maxWidth="lg" 
        sx={{ 
          flex: 1, 
          display: 'flex', 
          flexDirection: 'column',
          py: 2 
        }}
      >
        {children}
      </Container>
    </Box>
  )
}

export default Layout