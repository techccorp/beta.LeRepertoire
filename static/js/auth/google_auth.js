/**
 * Google Authentication functionality for Le Repertoire
 */

/**
 * Initialize Google Sign-In
 */
function initGoogleSignIn() {
    gapi.load('auth2', () => {
        gapi.auth2.init({
            client_id: document.querySelector('meta[name="google-signin-client_id"]').getAttribute('content')
        });
    });
}

/**
 * Handle Google Sign-In button click
 */
function handleGoogleSignIn() {
    const loadingOverlay = document.getElementById('loading-overlay');
    loadingOverlay.classList.remove('hidden');
    
    const auth2 = gapi.auth2.getAuthInstance();
    
    auth2.signIn().then(
        googleUser => {
            // Get ID token
            const idToken = googleUser.getAuthResponse().id_token;
            
            // Send to backend
            sendGoogleTokenToBackend(idToken);
        },
        error => {
            loadingOverlay.classList.add('hidden');
            console.error('Google Sign-In Error:', error);
            
            let errorMessage = 'Google Sign-In failed';
            if (error.error === 'popup_closed_by_user') {
                errorMessage = 'Sign-in was cancelled';
            } else if (error.error === 'access_denied') {
                errorMessage = 'Access was denied';
            }
            
            showError('Authentication Error', errorMessage);
        }
    );
}

/**
 * Send Google ID token to backend for verification
 * @param {string} idToken - Google ID token
 */
async function sendGoogleTokenToBackend(idToken) {
    const loadingOverlay = document.getElementById('loading-overlay');
    
    try {
        const response = await fetch('/auth/google-login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
            },
            body: JSON.stringify({ 
                id_token: idToken 
            })
        });
        
        if (response.redirected) {
            window.location.href = response.url;
            return;
        }
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Google authentication failed');
        }
        
        // Success - redirect to dashboard
        window.location.href = data.redirect || '/dashboard';
        
    } catch (error) {
        loadingOverlay.classList.add('hidden');
        console.error('Backend Authentication Error:', error);
        
        showError(
            'Authentication Error', 
            error.message || 'An error occurred during Google authentication'
        );
    }
}

// Initialize Google Sign-In when the API loads
if (typeof gapi !== 'undefined') {
    gapi.load('auth2', initGoogleSignIn);
} else {
    // If Google API is not available yet, wait for it to load
    window.addEventListener('load', () => {
        if (typeof gapi !== 'undefined') {
            initGoogleSignIn();
        } else {
            console.error('Google API not loaded');
        }
    });
}
