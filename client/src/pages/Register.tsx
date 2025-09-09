import React, { useState, useEffect } from 'react'
import {
  Paper,
  TextField,
  Button,
  Typography,
  Box,
  Link,
  Alert
} from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { ApiError } from '../services/authService'

const Register: React.FC = () => {
  const navigate = useNavigate()
  const { register, isAuthenticated } = useAuth()
  
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/chat', { replace: true })
    }
  }, [isAuthenticated, navigate])

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
    setError('')
  }

  const validateForm = () => {
    if (!formData.username.trim()) {
      setError('Username is required')
      return false
    }
    
    if (formData.username.trim().length < 3) {
      setError('Username must be at least 3 characters long')
      return false
    }
    
    if (!formData.email.trim()) {
      setError('Email is required')
      return false
    }
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(formData.email.trim())) {
      setError('Please enter a valid email address')
      return false
    }
    
    if (!formData.password) {
      setError('Password is required')
      return false
    }
    
    // Enhanced password validation matching server requirements
    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long')
      return false
    }
    
    const hasLowercase = /[a-z]/.test(formData.password)
    const hasUppercase = /[A-Z]/.test(formData.password)
    const hasNumber = /[0-9]/.test(formData.password)
    const hasSpecialChar = /[@$!%*?&]/.test(formData.password)
    
    if (!hasLowercase) {
      setError('Password must contain at least one lowercase letter')
      return false
    }
    
    if (!hasUppercase) {
      setError('Password must contain at least one uppercase letter')
      return false
    }
    
    if (!hasNumber) {
      setError('Password must contain at least one number')
      return false
    }
    
    if (!hasSpecialChar) {
      setError('Password must contain at least one special character (@$!%*?&)')
      return false
    }
    
    // Check for repeated characters
    const hasRepeatedChars = /(..).*\1/.test(formData.password)
    if (hasRepeatedChars) {
      setError('Password cannot contain repeated character sequences')
      return false
    }
    
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match')
      return false
    }
    
    return true
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!validateForm()) {
      return
    }

    setLoading(true)
    setError('')
    
    try {
      await register({
        username: formData.username.trim(),
        email: formData.email.trim(),
        password: formData.password,
        public_key: '', // Placeholder until RSA implementation
        private_key_encrypted: '' // Placeholder until RSA implementation
      })
      
      // Navigation will be handled by the useEffect above
      // when isAuthenticated becomes true
      
    } catch (err) {
      const error = err as ApiError
      setError(error.message || 'Registration failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Box
      sx={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        flex: 1,
      }}
    >
      <Paper
        elevation={3}
        sx={{
          p: 4,
          maxWidth: 400,
          width: '100%',
        }}
      >
        <Typography variant="h4" component="h1" gutterBottom align="center">
          Register
        </Typography>
        
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleSubmit}>
          <TextField
            name="username"
            label="Username"
            type="text"
            fullWidth
            required
            value={formData.username}
            onChange={handleChange}
            margin="normal"
            autoComplete="username"
            disabled={loading}
            error={error.includes('Username')}
            helperText={error.includes('Username') ? '' : 'Username must be at least 3 characters long'}
          />
          
          <TextField
            name="email"
            label="Email Address"
            type="email"
            fullWidth
            required
            value={formData.email}
            onChange={handleChange}
            margin="normal"
            autoComplete="email"
            disabled={loading}
            error={error.includes('Email') || error.includes('email')}
            helperText={error.includes('Email') || error.includes('email') ? '' : 'Enter a valid email address'}
          />
          
          <TextField
            name="password"
            label="Password"
            type="password"
            fullWidth
            required
            value={formData.password}
            onChange={handleChange}
            margin="normal"
            autoComplete="new-password"
            disabled={loading}
            error={error.includes('Password') && !error.includes('match')}
            helperText={
              error.includes('Password') && !error.includes('match') 
                ? '' 
                : 'Must be 8+ chars with uppercase, lowercase, number, and special char (@$!%*?&)'
            }
          />

          <TextField
            name="confirmPassword"
            label="Confirm Password"
            type="password"
            fullWidth
            required
            value={formData.confirmPassword}
            onChange={handleChange}
            margin="normal"
            autoComplete="new-password"
            disabled={loading}
            error={error.includes('match')}
          />

          <Button
            type="submit"
            fullWidth
            variant="contained"
            sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </Button>

          <Box textAlign="center">
            <Typography variant="body2">
              Already have an account?{' '}
              <Link
                component="button"
                variant="body2"
                onClick={(e) => {
                  e.preventDefault()
                  navigate('/login')
                }}
                disabled={loading}
              >
                Sign in here
              </Link>
            </Typography>
          </Box>
        </form>
      </Paper>
    </Box>
  )
}

export default Register