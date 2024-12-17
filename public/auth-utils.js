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
 * Performs a fetch request with authentication.
 *
 * This function retrieves a JWT token from sessionStorage or cookies,
 * attaches it to the Authorization header if available, and executes the fetch request.
 * It handles unauthorized responses by clearing the token and redirecting to the login page.
 *
 * @param {string} url - The URL to which the request is sent.
 * @param {object} [options={}] - Optional configurations for the fetch request.
 * @param {boolean} [options.plain=false] - If true, omits the 'Content-Type' header.
 * @param {object} [options.headers={}] - Additional headers to include in the request.
 * @returns {Promise<object|undefined>} - Resolves with the parsed JSON response if successful, otherwise undefined.
 */
const fetchWithAuth = async (url, options = {}) => {
    // Retrieve the token from sessionStorage
    let token = sessionStorage.getItem('_token');

    // If not in sessionStorage, attempt to retrieve from cookies
    if (!token) {
        token = getCookie('token');
    }

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
        credentials: 'include', // Include cookies in requests
    };

    try {
        // Perform the fetch
        const response = await fetch(url, fetchOptions);

        // If the response is unauthorized or forbidden, clear the token
        if (response.status === 401 || response.status === 403) {
            sessionStorage.removeItem('_token');
            // Optionally, remove the cookie if accessible
            document.cookie = 'token=; Max-Age=0; path=/;';
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

/**
 * Stashes specific query parameters into sessionStorage.
 *
 * This function extracts designated parameters from the URL's query string
 * and stores their values in sessionStorage with a prefixed key.
 * After stashing, it cleans up the URL by removing the query parameters without reloading the page.
 */
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

// Execute the function to stash query parameters upon script load
stashQueryParamsInSessionStorage();

/**
 * Logs out the user by clearing authentication tokens and redirecting to the login page.
 *
 * This function removes the JWT token from sessionStorage and deletes the corresponding cookie.
 * After clearing the tokens, it redirects the user to the '/login' page.
 */
function logout() {
    // Remove the token from sessionStorage
    sessionStorage.removeItem('_token');

    // Remove the token cookie by setting its Max-Age to 0
    document.cookie = 'token=; Max-Age=0; path=/;';

    // Redirect to the login page
    location.href = '/login';
}

/**
 * Checks if the user is currently logged in.
 *
 * This function verifies the presence of a JWT token in sessionStorage.
 * If the token exists, it returns true, indicating that the user is logged in.
 * Otherwise, it returns false.
 *
 * @returns {boolean} True if the user is logged in, false otherwise.
 */
function isLoggedIn() {
    let token = sessionStorage.getItem('_token');
    if (!token) token = getCookie('token');
    return !!token;
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
