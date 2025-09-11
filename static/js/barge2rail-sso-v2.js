/**
 * Barge2Rail SSO Client Library v2
 * Enhanced with Google Sign-In and Anonymous Authentication
 */

class Barge2RailSSO {
    constructor(ssoUrl = 'http://127.0.0.1:8000', appSlug = 'default') {
        this.ssoUrl = ssoUrl;
        this.appSlug = appSlug;
        this.tokenKey = 'barge2rail_access_token';
        this.refreshKey = 'barge2rail_refresh_token';
        this.userKey = 'barge2rail_user';
    }

    // Email/Password login
    async loginEmail(email, password) {
        try {
            const response = await fetch(`${this.ssoUrl}/api/auth/login/email/`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            return await this.handleAuthResponse(response);
        } catch (error) {
            console.error('Email login error:', error);
            return { success: false, error: 'Network error' };
        }
    }

    // Google Sign-In
    async loginGoogle(googleToken) {
        try {
            const response = await fetch(`${this.ssoUrl}/api/auth/login/google/`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: googleToken })
            });

            return await this.handleAuthResponse(response);
        } catch (error) {
            console.error('Google login error:', error);
            return { success: false, error: 'Network error' };
        }
    }

    // Anonymous login (existing user)
    async loginAnonymous(username, pin) {
        try {
            const response = await fetch(`${this.ssoUrl}/api/auth/login/anonymous/`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, pin })
            });

            return await this.handleAuthResponse(response);
        } catch (error) {
            console.error('Anonymous login error:', error);
            return { success: false, error: 'Network error' };
        }
    }

    // Create new anonymous account
    async createAnonymousAccount() {
        try {
            const response = await fetch(`${this.ssoUrl}/api/auth/login/anonymous/`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}) // Empty body creates new account
            });

            return await this.handleAuthResponse(response);
        } catch (error) {
            console.error('Create anonymous error:', error);
            return { success: false, error: 'Network error' };
        }
    }

    // Register new email account
    async registerEmail(email, password, displayName = '', firstName = '', lastName = '') {
        try {
            const response = await fetch(`${this.ssoUrl}/api/auth/register/email/`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email,
                    password,
                    display_name: displayName,
                    first_name: firstName,
                    last_name: lastName
                })
            });

            return await this.handleAuthResponse(response);
        } catch (error) {
            console.error('Registration error:', error);
            return { success: false, error: 'Network error' };
        }
    }

    async handleAuthResponse(response) {
        const data = await response.json();

        if (response.ok) {
            this.setTokens(data.access_token, data.refresh_token);
            this.setUser(data.user);
            
            return { 
                success: true, 
                user: data.user,
                message: data.message,
                anonymous_credentials: data.anonymous_credentials
            };
        } else {
            return { success: false, error: data.error || 'Authentication failed' };
        }
    }

    // Logout
    async logout() {
        const refreshToken = this.getRefreshToken();
        
        if (refreshToken) {
            try {
                await fetch(`${this.ssoUrl}/api/auth/logout/`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.getAccessToken()}`
                    },
                    body: JSON.stringify({ refresh: refreshToken })
                });
            } catch (error) {
                console.error('Logout error:', error);
            }
        }
        
        this.clearAuth();
    }

    // Refresh access token
    async refreshToken() {
        const refreshToken = this.getRefreshToken();
        
        if (!refreshToken) {
            throw new Error('No refresh token available');
        }
        
        try {
            const response = await fetch(`${this.ssoUrl}/api/auth/refresh/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ refresh: refreshToken })
            });
            
            if (!response.ok) {
                throw new Error('Token refresh failed');
            }
            
            const data = await response.json();
            this.setTokens(data.access, data.refresh || refreshToken);
            
            return data.access;
        } catch (error) {
            console.error('Token refresh error:', error);
            this.clearAuth();
            throw error;
        }
    }

    // Make authenticated request
    async authenticatedRequest(url, options = {}) {
        const token = this.getAccessToken();
        
        if (!token) {
            throw new Error('Not authenticated');
        }
        
        const fullUrl = url.startsWith('http') ? url : `${this.ssoUrl}${url}`;
        
        const requestOptions = {
            ...options,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        };
        
        let response = await fetch(fullUrl, requestOptions);
        
        // If token expired, try to refresh
        if (response.status === 401) {
            try {
                await this.refreshToken();
                // Retry with new token
                requestOptions.headers['Authorization'] = `Bearer ${this.getAccessToken()}`;
                response = await fetch(fullUrl, requestOptions);
            } catch (error) {
                this.clearAuth();
                throw new Error('Session expired');
            }
        }
        
        if (!response.ok) {
            throw new Error(`Request failed: ${response.statusText}`);
        }
        
        return response.json();
    }

    // Token and user management
    setTokens(accessToken, refreshToken) {
        if (accessToken) {
            localStorage.setItem(this.tokenKey, accessToken);
        }
        if (refreshToken) {
            localStorage.setItem(this.refreshKey, refreshToken);
        }
    }

    setUser(user) {
        localStorage.setItem(this.userKey, JSON.stringify(user));
    }

    getAccessToken() {
        return localStorage.getItem(this.tokenKey);
    }

    getRefreshToken() {
        return localStorage.getItem(this.refreshKey);
    }

    getUser() {
        const userData = localStorage.getItem(this.userKey);
        return userData ? JSON.parse(userData) : null;
    }

    clearAuth() {
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.refreshKey);
        localStorage.removeItem(this.userKey);
    }

    // Utility methods
    isAuthenticated() {
        return !!this.getAccessToken();
    }

    getUserDisplayName() {
        const user = this.getUser();
        return user ? (user.display_name || user.display_identifier || user.email) : '';
    }

    isAnonymousUser() {
        const user = this.getUser();
        return user ? user.is_anonymous : false;
    }

    getAuthType() {
        const user = this.getUser();
        return user ? user.auth_type : null;
    }

    getUserRole(appSlug = null) {
        const user = this.getUser();
        if (!user || !user.roles) return null;
        
        const slug = appSlug || this.appSlug;
        return user.roles[slug] || null;
    }

    hasPermission(permission, appSlug = null) {
        const role = this.getUserRole(appSlug);
        if (!role) return false;
        
        return role.permissions && role.permissions[permission] === true;
    }

    // JWT token utilities
    decodeToken(token) {
        try {
            const base64Url = (token || this.getAccessToken()).split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            
            return JSON.parse(jsonPayload);
        } catch (error) {
            console.error('Token decode error:', error);
            return null;
        }
    }

    isTokenExpired(token) {
        const decoded = this.decodeToken(token || this.getAccessToken());
        if (!decoded || !decoded.exp) {
            return true;
        }
        
        const currentTime = Date.now() / 1000;
        return decoded.exp < currentTime;
    }

    // Setup automatic token refresh
    setupAutoRefresh(intervalMs = 60000) {
        setInterval(async () => {
            const token = this.getAccessToken();
            if (token) {
                const decoded = this.decodeToken(token);
                if (decoded && decoded.exp) {
                    const currentTime = Date.now() / 1000;
                    const timeUntilExpiry = decoded.exp - currentTime;
                    
                    // Refresh if less than 5 minutes until expiry
                    if (timeUntilExpiry < 300) {
                        try {
                            await this.refreshToken();
                            console.log('Token refreshed automatically');
                        } catch (error) {
                            console.error('Auto refresh failed:', error);
                        }
                    }
                }
            }
        }, intervalMs);
    }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Barge2RailSSO;
} else if (typeof define === 'function' && define.amd) {
    define([], function() {
        return Barge2RailSSO;
    });
} else if (typeof window !== 'undefined') {
    window.Barge2RailSSO = Barge2RailSSO;
}