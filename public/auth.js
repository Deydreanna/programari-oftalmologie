// =============================================
//  Auth Utilities - Shared across all pages
//  Cookie session + CSRF transport helper
// =============================================

const AUTH = {
    USER_KEY: 'authUser',
    LEGACY_TOKEN_KEY: 'authToken',
    CSRF_COOKIE_NAME: '__Host-csrf',
    _refreshPromise: null,

    clearLegacyTokenStorage() {
        localStorage.removeItem(this.LEGACY_TOKEN_KEY);
        sessionStorage.removeItem(this.LEGACY_TOKEN_KEY);
    },

    getUser() {
        const raw = localStorage.getItem(this.USER_KEY);
        try {
            return raw ? JSON.parse(raw) : null;
        } catch {
            return null;
        }
    },

    setUser(user) {
        if (!user) {
            localStorage.removeItem(this.USER_KEY);
            return;
        }
        localStorage.setItem(this.USER_KEY, JSON.stringify(user));
    },

    isLoggedIn() {
        return !!this.getUser();
    },

    getCookie(name) {
        const cookies = document.cookie ? document.cookie.split('; ') : [];
        for (const item of cookies) {
            const idx = item.indexOf('=');
            if (idx < 0) continue;
            const key = item.slice(0, idx);
            if (key === name) {
                return decodeURIComponent(item.slice(idx + 1));
            }
        }
        return '';
    },

    getCsrfToken() {
        return this.getCookie(this.CSRF_COOKIE_NAME);
    },

    async refreshSession() {
        if (this._refreshPromise) {
            return this._refreshPromise;
        }

        this._refreshPromise = (async () => {
            try {
                const res = await this.apiFetch('/api/auth/refresh', {
                    method: 'POST',
                    skipRefresh: true
                });
                if (!res.ok) {
                    this.setUser(null);
                    return false;
                }
                return true;
            } catch (_) {
                this.setUser(null);
                return false;
            } finally {
                this._refreshPromise = null;
            }
        })();

        return this._refreshPromise;
    },

    async apiFetch(url, options = {}) {
        const method = String(options.method || 'GET').toUpperCase();
        const headers = new Headers(options.headers || {});
        if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
            headers.set('Content-Type', 'application/json');
        }

        if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
            const csrfToken = this.getCsrfToken();
            if (csrfToken) {
                headers.set('X-CSRF-Token', csrfToken);
            }
        }

        const requestOptions = {
            ...options,
            method,
            headers,
            credentials: 'include'
        };
        delete requestOptions.skipRefresh;

        const response = await fetch(url, requestOptions);
        const skipRefresh = Boolean(options.skipRefresh);
        const isAuthEndpoint = String(url).startsWith('/api/auth/');
        if (skipRefresh || response.status !== 401 || isAuthEndpoint) {
            return response;
        }

        const refreshed = await this.refreshSession();
        if (!refreshed) {
            return response;
        }

        const retryHeaders = new Headers(options.headers || {});
        if (options.body && !(options.body instanceof FormData) && !retryHeaders.has('Content-Type')) {
            retryHeaders.set('Content-Type', 'application/json');
        }
        if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
            const retryCsrfToken = this.getCsrfToken();
            if (retryCsrfToken) {
                retryHeaders.set('X-CSRF-Token', retryCsrfToken);
            }
        }

        const retryOptions = {
            ...options,
            method,
            headers: retryHeaders,
            credentials: 'include'
        };
        delete retryOptions.skipRefresh;
        return fetch(url, retryOptions);
    },

    async verify() {
        try {
            let res = await this.apiFetch(`/api/auth/me?t=${Date.now()}`, {
                method: 'GET',
                skipRefresh: true
            });

            if (res.status === 401) {
                const refreshed = await this.refreshSession();
                if (refreshed) {
                    res = await this.apiFetch(`/api/auth/me?t=${Date.now()}`, {
                        method: 'GET',
                        skipRefresh: true
                    });
                }
            }

            if (!res.ok) {
                this.setUser(null);
                return null;
            }

            const data = await res.json();
            this.setUser(data.user || null);
            return data.user || null;

        } catch (_) {
            this.setUser(null);
            return null;
        }
    },

    async logout() {
        try {
            await this.apiFetch('/api/auth/logout', {
                method: 'POST',
                skipRefresh: true
            });
        } catch (_) {
            // no-op
        } finally {
            this.setUser(null);
            this.clearLegacyTokenStorage();
        }
    }
};

AUTH.clearLegacyTokenStorage();
