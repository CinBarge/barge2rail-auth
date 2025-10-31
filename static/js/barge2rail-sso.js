/**
 * Barge2Rail SSO Client Library
 * For integrating with Barge2Rail centralized authentication
 */

(function(window) {
    'use strict';

    const Barge2RailSSO = {
        config: {
            ssoUrl: 'https://sso.barge2rail.com',
            tokenKey: 'barge2rail_access_token',
            refreshKey: 'barge2rail_refresh_token',
            userKey: 'barge2rail_user'
        },

        /**
         * Initialize SSO with custom configuration
         */
        init: function(options) {
            Object.assign(this.config, options);
        },

        /**
         * Login with email and password
         */
        login: async function(email, password) {
            try {
                const response = await fetch(`${this.config.ssoUrl}/api/auth/login/`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password })
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.message || 'Login failed');
                }

                const data = await response.json();
                this.saveTokens(data.tokens);
                this.saveUser(data.user);

                return data;
            } catch (error) {
                console.error('Login error:', error);
                throw error;
            }
        },

        /**
         * Register new user
         */
        register: async function(userData) {
            try {
                const response = await fetch(`${this.config.ssoUrl}/api/auth/register/`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(userData)
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.message || 'Registration failed');
                }

                const data = await response.json();
                this.saveTokens(data.tokens);
                this.saveUser(data.user);

                return data;
            } catch (error) {
                console.error('Registration error:', error);
                throw error;
            }
        },

        /**
         * Logout and clear tokens
         */
        logout: async function() {
            const refreshToken = this.getRefreshToken();

            if (refreshToken) {
                try {
                    await fetch(`${this.config.ssoUrl}/api/auth/logout/`, {
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
        },

        /**
         * Refresh access token
         */
        refreshToken: async function() {
            const refreshToken = this.getRefreshToken();

            if (!refreshToken) {
                throw new Error('No refresh token available');
            }

            try {
                const response = await fetch(`${this.config.ssoUrl}/api/auth/refresh/`, {
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
                this.saveTokens(data);

                return data.access;
            } catch (error) {
                console.error('Token refresh error:', error);
                this.clearAuth();
                throw error;
            }
        },

        /**
         * Validate current token
         */
        validateToken: async function() {
            const token = this.getAccessToken();

            if (!token) {
                return { valid: false };
            }

            try {
                const response = await fetch(`${this.config.ssoUrl}/api/auth/validate/`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ token })
                });

                const data = await response.json();

                if (data.valid) {
                    this.saveUser(data.user);
                }

                return data;
            } catch (error) {
                console.error('Token validation error:', error);
                return { valid: false };
            }
        },

        /**
         * Get current user profile
         */
        getProfile: async function() {
            try {
                const response = await this.authenticatedRequest('/api/auth/profile/');
                return response;
            } catch (error) {
                console.error('Profile fetch error:', error);
                throw error;
            }
        },

        /**
         * Make authenticated request
         */
        authenticatedRequest: async function(url, options = {}) {
            const token = this.getAccessToken();

            if (!token) {
                throw new Error('Not authenticated');
            }

            const fullUrl = url.startsWith('http') ? url : `${this.config.ssoUrl}${url}`;

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
        },

        /**
         * Check if user is authenticated
         */
        isAuthenticated: function() {
            return !!this.getAccessToken();
        },

        /**
         * Get access token
         */
        getAccessToken: function() {
            return localStorage.getItem(this.config.tokenKey);
        },

        /**
         * Get refresh token
         */
        getRefreshToken: function() {
            return localStorage.getItem(this.config.refreshKey);
        },

        /**
         * Get current user
         */
        getUser: function() {
            const userStr = localStorage.getItem(this.config.userKey);
            return userStr ? JSON.parse(userStr) : null;
        },

        /**
         * Save tokens
         */
        saveTokens: function(tokens) {
            if (tokens.access) {
                localStorage.setItem(this.config.tokenKey, tokens.access);
            }
            if (tokens.refresh) {
                localStorage.setItem(this.config.refreshKey, tokens.refresh);
            }
        },

        /**
         * Save user data
         */
        saveUser: function(user) {
            localStorage.setItem(this.config.userKey, JSON.stringify(user));
        },

        /**
         * Clear authentication data
         */
        clearAuth: function() {
            localStorage.removeItem(this.config.tokenKey);
            localStorage.removeItem(this.config.refreshKey);
            localStorage.removeItem(this.config.userKey);
        },

        /**
         * Decode JWT token
         */
        decodeToken: function(token) {
            try {
                const base64Url = token.split('.')[1];
                const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                }).join(''));

                return JSON.parse(jsonPayload);
            } catch (error) {
                console.error('Token decode error:', error);
                return null;
            }
        },

        /**
         * Check if token is expired
         */
        isTokenExpired: function(token) {
            const decoded = this.decodeToken(token || this.getAccessToken());
            if (!decoded || !decoded.exp) {
                return true;
            }

            const currentTime = Date.now() / 1000;
            return decoded.exp < currentTime;
        },

        /**
         * Setup automatic token refresh
         */
        setupAutoRefresh: function() {
            setInterval(async () => {
                const token = this.getAccessToken();
                if (token && this.isTokenExpired(token)) {
                    try {
                        await this.refreshToken();
                    } catch (error) {
                        console.error('Auto refresh failed:', error);
                    }
                }
            }, 60000); // Check every minute
        }
    };

    // Export for different module systems
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = Barge2RailSSO;
    } else if (typeof define === 'function' && define.amd) {
        define([], function() {
            return Barge2RailSSO;
        });
    } else {
        window.Barge2RailSSO = Barge2RailSSO;
    }
})(typeof window !== 'undefined' ? window : this);
