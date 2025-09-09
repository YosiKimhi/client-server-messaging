import React from 'react'
import { AppBar, Toolbar, Typography, Container, Box } from '@mui/material'
import { useLocation } from 'react-router-dom'

interface LayoutProps {
  children: React.ReactNode
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation()
  
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

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            {getPageTitle()}
          </Typography>
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