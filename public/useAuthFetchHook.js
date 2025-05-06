/* ********************************************************************** */
/* useAuthFetch custom hook                                               */
/* Example Usage                                                          */
/* ********************************************************************** */
// import { useEffect, useState } from 'react';
// import { useAuthFetch } from '@/hooks/useAuthFetch';
//
// export default function UserProfile() {
//     const { fetchWithAuth, loading, error } = useAuthFetch();
//     const [userData, setUserData] = useState(null);
//
//     useEffect(() => {
//         async function fetchUser() {
//             try {
//                 const data = await fetchWithAuth('/me', { method: 'GET' });
//                 setUserData(data);
//             } catch (err) {
//                 console.error('Failed to fetch user data:', err);
//             }
//         }
//
//         fetchUser();
//     }, [fetchWithAuth]);
/* ********************************************************************** */

import { useState, useCallback } from 'react';

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
 * Custom React hook for making authenticated fetch requests.
 */
export function useAuthFetch() {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const fetchWithAuth = useCallback(async (url, options = {}) => {
        setLoading(true);
        setError(null);

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
                window.location.href = '/login';
                throw new Error('Authentication failed.');
            }

            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }

            return await response.json();
        } catch (err) {
            setError(err.message);
            console.error(err);
            throw err;
        } finally {
            setLoading(false);
        }
    }, []);

    return { fetchWithAuth, loading, error };
}
