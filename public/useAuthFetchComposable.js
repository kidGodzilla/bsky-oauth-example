/* ********************************************************************** */
/* useAuthFetch composable                                                */
/* Example Usage                                                          */
/* ********************************************************************** */
// import { onMounted, ref } from 'vue';
// import { useAuthFetch } from '@/composables/useAuthFetch';
//
// const { fetchWithAuth, loading, error } = useAuthFetch();
// const userData = ref(null);
//
// onMounted(async () => {
//     try {
//         userData.value = await fetchWithAuth('/me', { method: 'GET' });
//     } catch (err) {
//         console.error('Failed to fetch user data:', err);
//     }
// });
/* ********************************************************************** */

import { ref } from 'vue';

/**
 * Retrieves the value of a specified cookie.
 * @param {string} name - The name of the cookie to retrieve.
 * @returns {string|null} The cookie value if found, otherwise null.
 */
const getCookie = (name) => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
};

/**
 * Fetch with authentication in Vue 3 (script setup compatible).
 */
export function useAuthFetch() {
    const loading = ref(false);
    const error = ref(null);

    const fetchWithAuth = async (url, options = {}) => {
        loading.value = true;
        error.value = null;

        let token = sessionStorage.getItem('_token') || getCookie('token');

        const headers = {
            ...options.headers,
        };

        if (!options.plain) headers['Content-Type'] = 'application/json';
        else delete options.plain;

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const fetchOptions = {
            ...options,
            headers,
            credentials: 'include',
        };

        try {
            const response = await fetch(url, fetchOptions);

            if (response.status === 401 || response.status === 403) {
                sessionStorage.removeItem('_token');
                document.cookie = 'token=; Max-Age=0; path=/;';
                location.href = '/login';
                throw new Error('Authentication failed.');
            }

            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }

            return await response.json();
        } catch (err) {
            error.value = err.message;
            console.error(err);
            throw err;
        } finally {
            loading.value = false;
        }
    };

    return { fetchWithAuth, loading, error };
}
