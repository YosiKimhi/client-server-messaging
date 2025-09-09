import React, { useState } from 'react';
import { 
  Box, 
  Button, 
  Typography, 
  Alert, 
  Card, 
  CardContent, 
  Divider, 
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { useRegistrationEncryption } from '../hooks/useEncryption';
import { isCryptoSupported } from '../utils/encryption';
import { testEncryptionFlow, testBrowserSupport, testKeyGenerationPerformance } from '../tests/encryption.test';

interface TestResults {
  browserSupport?: any;
  encryptionFlow?: boolean;
  performance?: number[];
  keyGeneration?: any;
}

const EncryptionTest: React.FC = () => {
  const [testResults, setTestResults] = useState<TestResults>({});
  const [isRunning, setIsRunning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const { generateAndFormatKeys, state } = useRegistrationEncryption();

  const addLog = (message: string) => {
    setLogs(prev => [...prev, `${new Date().toLocaleTimeString()}: ${message}`]);
  };

  const runBrowserSupportTest = () => {
    addLog('Running browser support test...');
    const results = testBrowserSupport();
    setTestResults(prev => ({ ...prev, browserSupport: results }));
    addLog('Browser support test completed');
  };

  const runEncryptionFlowTest = async () => {
    setIsRunning(true);
    addLog('Running encryption flow test...');
    
    try {
      const success = await testEncryptionFlow();
      setTestResults(prev => ({ ...prev, encryptionFlow: success }));
      addLog(`Encryption flow test ${success ? 'PASSED' : 'FAILED'}`);
    } catch (error) {
      addLog(`Encryption flow test ERROR: ${error}`);
      setTestResults(prev => ({ ...prev, encryptionFlow: false }));
    }
    
    setIsRunning(false);
  };

  const runPerformanceTest = async () => {
    setIsRunning(true);
    addLog('Running performance test...');
    
    try {
      const times = await testKeyGenerationPerformance();
      setTestResults(prev => ({ ...prev, performance: times }));
      addLog('Performance test completed');
    } catch (error) {
      addLog(`Performance test ERROR: ${error}`);
    }
    
    setIsRunning(false);
  };

  const testKeyGeneration = async () => {
    setIsRunning(true);
    addLog('Testing key generation with registration hook...');
    
    try {
      const startTime = performance.now();
      const result = await generateAndFormatKeys('TestPassword123!');
      const endTime = performance.now();
      
      if (result) {
        addLog(`Key generation SUCCESS in ${(endTime - startTime).toFixed(2)}ms`);
        addLog(`Public key length: ${result.public_key.length}`);
        addLog(`Private key data length: ${result.private_key_encrypted.length}`);
        setTestResults(prev => ({ 
          ...prev, 
          keyGeneration: { 
            success: true, 
            time: endTime - startTime,
            result 
          }
        }));
      } else {
        addLog('Key generation FAILED - returned null');
        setTestResults(prev => ({ 
          ...prev, 
          keyGeneration: { success: false }
        }));
      }
    } catch (error) {
      addLog(`Key generation ERROR: ${error}`);
      setTestResults(prev => ({ 
        ...prev, 
        keyGeneration: { success: false, error: String(error) }
      }));
    }
    
    setIsRunning(false);
  };

  const clearTests = () => {
    setTestResults({});
    setLogs([]);
  };

  const cryptoSupported = isCryptoSupported();

  return (
    <Box sx={{ p: 3, maxWidth: 800, mx: 'auto' }}>
      <Typography variant="h5" gutterBottom>
        Encryption Test Suite
      </Typography>
      
      {!cryptoSupported && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Crypto API is not supported in this browser!
        </Alert>
      )}

      {state.error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Encryption Hook Error: {state.error}
        </Alert>
      )}

      <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <Button 
          variant="contained" 
          onClick={runBrowserSupportTest}
          disabled={isRunning}
        >
          Test Browser Support
        </Button>
        
        <Button 
          variant="contained" 
          onClick={runEncryptionFlowTest}
          disabled={isRunning || !cryptoSupported}
        >
          {isRunning ? <CircularProgress size={20} /> : 'Test Encryption Flow'}
        </Button>
        
        <Button 
          variant="contained" 
          onClick={testKeyGeneration}
          disabled={isRunning || !cryptoSupported}
        >
          Test Key Generation
        </Button>
        
        <Button 
          variant="contained" 
          onClick={runPerformanceTest}
          disabled={isRunning || !cryptoSupported}
        >
          Test Performance
        </Button>
        
        <Button 
          variant="outlined" 
          onClick={clearTests}
          disabled={isRunning}
        >
          Clear Tests
        </Button>
      </Box>

      {/* Test Results */}
      <Box sx={{ mb: 3 }}>
        {testResults.browserSupport && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography>Browser Support Results</Typography>
              <Chip 
                label={Object.values(testResults.browserSupport).every(v => v) ? 'PASS' : 'FAIL'} 
                color={Object.values(testResults.browserSupport).every(v => v) ? 'success' : 'error'}
                size="small"
                sx={{ ml: 2 }}
              />
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                {Object.entries(testResults.browserSupport).map(([key, value]) => (
                  <Box key={key} sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                    <Typography>{key}:</Typography>
                    <Chip 
                      label={value ? 'Supported' : 'Not Supported'} 
                      color={value ? 'success' : 'error'} 
                      size="small" 
                    />
                  </Box>
                ))}
              </Box>
            </AccordionDetails>
          </Accordion>
        )}

        {testResults.encryptionFlow !== undefined && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography>Encryption Flow Test</Typography>
              <Chip 
                label={testResults.encryptionFlow ? 'PASS' : 'FAIL'} 
                color={testResults.encryptionFlow ? 'success' : 'error'}
                size="small"
                sx={{ ml: 2 }}
              />
            </AccordionSummary>
            <AccordionDetails>
              <Typography>
                Full encryption flow test {testResults.encryptionFlow ? 'passed' : 'failed'}.
                Check browser console for detailed logs.
              </Typography>
            </AccordionDetails>
          </Accordion>
        )}

        {testResults.keyGeneration && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography>Key Generation Test</Typography>
              <Chip 
                label={testResults.keyGeneration.success ? 'PASS' : 'FAIL'} 
                color={testResults.keyGeneration.success ? 'success' : 'error'}
                size="small"
                sx={{ ml: 2 }}
              />
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" gutterBottom>
                  Success: {testResults.keyGeneration.success ? 'Yes' : 'No'}
                </Typography>
                {testResults.keyGeneration.time && (
                  <Typography variant="body2" gutterBottom>
                    Generation Time: {testResults.keyGeneration.time.toFixed(2)}ms
                  </Typography>
                )}
                {testResults.keyGeneration.error && (
                  <Typography variant="body2" color="error">
                    Error: {testResults.keyGeneration.error}
                  </Typography>
                )}
              </Box>
            </AccordionDetails>
          </Accordion>
        )}

        {testResults.performance && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography>Performance Test</Typography>
              <Chip 
                label={`Avg: ${(testResults.performance.reduce((a, b) => a + b) / testResults.performance.length).toFixed(0)}ms`}
                color="info"
                size="small"
                sx={{ ml: 2 }}
              />
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" gutterBottom>
                  Key generation times:
                </Typography>
                {testResults.performance.map((time, index) => (
                  <Typography key={index} variant="body2">
                    Run {index + 1}: {time.toFixed(2)}ms
                  </Typography>
                ))}
                <Typography variant="body2" sx={{ mt: 1, fontWeight: 'bold' }}>
                  Average: {(testResults.performance.reduce((a, b) => a + b) / testResults.performance.length).toFixed(2)}ms
                </Typography>
              </Box>
            </AccordionDetails>
          </Accordion>
        )}
      </Box>

      {/* Console Logs */}
      {logs.length > 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Test Console
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Box sx={{ 
              maxHeight: 300, 
              overflow: 'auto', 
              bgcolor: 'grey.100', 
              p: 2, 
              borderRadius: 1,
              fontFamily: 'monospace'
            }}>
              {logs.map((log, index) => (
                <Typography key={index} variant="body2" sx={{ fontSize: '0.8rem', mb: 0.5 }}>
                  {log}
                </Typography>
              ))}
            </Box>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default EncryptionTest;