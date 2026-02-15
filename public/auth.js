// =============================================
//  Auth Utilities — Shared across all pages
//  Manages JWT tokens and user state
// =============================================

const AUTH = {
    TOKEN_KEY: 'authToken',
    USER_KEY: 'authUser',

    getToken() {
        return localStorage.getItem(this.TOKEN_KEY);
    },

    getUser() {
        const raw = localStorage.getItem(this.USER_KEY);
        try {
            return raw ? JSON.parse(raw) : null;
        } catch {
            return null;
        }
    },

    isLoggedIn() {
        return !!this.getToken();
    },

    setAuth(token, user) {
        localStorage.setItem(this.TOKEN_KEY, token);
        localStorage.setItem(this.USER_KEY, JSON.stringify(user));
    },

    logout() {
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.removeItem(this.USER_KEY);
    },

    // Get auth headers for API calls
    getHeaders() {
        const headers = { 'Content-Type': 'application/json' };
        const token = this.getToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        return headers;
    },

    // Verify token is still valid
    async verify() {
        const token = this.getToken();
        if (!token) return null;

        try {
            const res = await fetch(`/api/auth/me?t=${Date.now()}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (!res.ok) {
                this.logout();
                return null;
            }

            const data = await res.json();
            this.setAuth(data.token, data.user);
            return data.user;

        } catch (err) {
            console.error('Auth verify error:', err);
            return null;
        }
    }
};
