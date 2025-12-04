/**
 * Application Configuration
 * WARNING: This file contains sensitive information!
 */

// VULNERABLE: Hardcoded API keys and secrets
window.API_CONFIG = {
    // Production API endpoints
    apiBaseUrl: 'https://api.example.com/v1',
    
    // EXPOSED: Third-party API keys
    googleMapsApiKey: 'AIzaSyBNLrJhOMz6idD05pzfn5lhA-TAw-mAZCU',
    stripePublishableKey: 'pk_live_51H1234567890abcdefghijklmnop',
    
    // EXPOSED: Internal API key
    internalApiKey: 'sk_internal_9f8e7d6c5b4a3210fedcba0987654321',
    
    // EXPOSED: Firebase config
    firebase: {
        apiKey: 'AIzaSyDOCAbC123dEf456GhI789jKl01-MnsT23',
        authDomain: 'my-app-12345.firebaseapp.com',
        projectId: 'my-app-12345',
        storageBucket: 'my-app-12345.appspot.com',
        messagingSenderId: '123456789012',
        appId: '1:123456789012:web:abc123def456'
    },
    
    // EXPOSED: AWS credentials (should never be in frontend!)
    aws: {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-east-1'
    }
};

// Debug mode - exposes additional info
window.DEBUG = true;
window.APP_VERSION = '2.1.0';
window.BUILD_TIME = '2024-01-15T10:30:00Z';

console.log('Config loaded:', window.API_CONFIG);

