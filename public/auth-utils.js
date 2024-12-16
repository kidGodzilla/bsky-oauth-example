const fetchWithAuth = async (url, options = {}) => {
    // Retrieve the token from sessionStorage
    const token = sessionStorage.getItem('_token');

    // Default headers
    const headers = {
        ...options.headers, // Include any additional headers provided
    };

    if (!options.plain) headers['Content-Type'] = 'application/json';
    else delete options.plain;

    // Add the Authorization header if the token exists
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    // Configure the fetch options
    const fetchOptions = {
        ...options,
        headers,
    };

    try {
        // Perform the fetch
        const response = await fetch(url, fetchOptions);

        // If the response is unauthorized or forbidden, clear the token
        if (response.status === 401 || response.status === 403) {
            sessionStorage.removeItem('_token');
            location.href = '/login';
            
            return console.warn('Authentication failed. Token has been removed.');
        }

        // Throw an error if the response is not ok (excluding 401/403 handled above)
        if (!response.ok) {
            console.warn(`HTTP error! status: ${response.status}`);
            return;
        }

        // Return the parsed response data
        return await response.json();
    } catch (error) {
        console.error(error);
        throw error; // Re-throw the error for upstream handling
    }
};

const stashQueryParamsInSessionStorage = () => {
    // Get the query string from the current URL
    const queryString = window.location.search;

    // Parse the query parameters
    const params = new URLSearchParams(queryString);

    // Check if the 'token' parameter exists
    if (!params.has('token')) {
        return; // Do nothing if there's no 'token'
    }

    // Define the keys you want to stash
    const keysToStash = ['token', 'did', 'handle', 'displayName', 'avatar'];

    // Loop through each key and store its value in sessionStorage
    keysToStash.forEach((key) => {
        const value = params.get(key);
        if (value) {
            sessionStorage.setItem(`_${ key }`, value);
        }
    });

    // Clean up the URL by removing query parameters without redirecting
    const newUrl = window.location.pathname + window.location.hash;
    window.history.replaceState(null, '', newUrl);
};

stashQueryParamsInSessionStorage();

function logout() {
    sessionStorage.removeItem('_token');
    location.href = '/login';
}

function isLoggedIn() {
    return !!sessionStorage.getItem('_token');
}

// EXAMPLES

// (async () => {
//     try {
//         const data = await fetchWithAuth('/me', {
//             method: 'GET', // Or 'POST', 'PUT', etc.
//         });
//
//         console.log('Response Data:', data);
//     } catch (error) {
//         console.error('Error fetching data:', error);
//     }
// })();

// if (isLoggedIn()) {
//
// } else {
//
// }
