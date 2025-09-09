# Secure Messaging Client

A React TypeScript frontend application for secure messaging with end-to-end encryption.

## Features

- **React 18** with TypeScript for type safety
- **Material-UI (MUI)** for modern, responsive UI components
- **React Router** for client-side routing
- **Vite** for fast development and building
- **ESLint** for code quality

## Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Lint code
npm run lint
```

## Application Structure

```
src/
├── components/          # Reusable UI components
│   └── Layout.tsx      # Main app layout component
├── pages/              # Page components
│   ├── Login.tsx       # User login page
│   ├── Register.tsx    # User registration page
│   └── Chat.tsx        # Main chat interface
├── contexts/           # React contexts (for state management)
├── hooks/              # Custom React hooks
├── services/           # API services and utilities
├── utils/              # Utility functions
├── App.tsx             # Main application component
├── main.tsx            # Application entry point
└── index.css           # Global styles
```

## Available Routes

- `/` - Redirects to login
- `/login` - User authentication
- `/register` - User registration
- `/chat` - Main chat interface

## Development Server

The development server runs on `http://localhost:5173` and includes:
- Hot module replacement
- TypeScript compilation
- Proxy configuration for backend API calls to `http://localhost:3000`

## Next Steps

1. Implement authentication service integration
2. Add message encryption/decryption logic
3. Implement real-time messaging with Server-Sent Events
4. Add user context for state management
5. Implement error boundary components