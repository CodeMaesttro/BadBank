// BadBank JavaScript - Minimal client-side functionality with DOM-based vulnerabilities
// This file contains intentionally vulnerable JS for training purposes

document.addEventListener('DOMContentLoaded', function() {
    console.log('BadBank loaded - Ready for security testing!');
    
    // DOM-based XSS vulnerability - unsafe innerHTML usage
    const urlParams = new URLSearchParams(window.location.search);
    const welcomeMsg = urlParams.get('welcome');
    if (welcomeMsg) {
        const welcomeDiv = document.createElement('div');
        welcomeDiv.className = 'welcome-message';
        welcomeDiv.innerHTML = 'Welcome: ' + welcomeMsg; // Unsafe!
        document.body.insertBefore(welcomeDiv, document.body.firstChild);
    }
    
    // Expose user information in global scope
    if (typeof userId !== 'undefined') {
        window.currentUser = {
            id: userId,
            isLoggedIn: true
        };
    }
    
    // Basic form validation (intentionally weak for training)
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            console.log('Form submitted:', form.id);
            
            // Log sensitive form data (bad practice)
            const formData = new FormData(form);
            for (let [key, value] of formData.entries()) {
                console.log(`${key}: ${value}`);
            }
        });
    });
    
    // Search functionality with DOM-based XSS
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function(e) {
            performSearch(e.target.value);
        });
    }
    
    // Handle hash-based navigation (DOM XSS vector)
    if (window.location.hash) {
        const hashContent = window.location.hash.substring(1);
        const contentDiv = document.getElementById('hash-content');
        if (contentDiv) {
            contentDiv.innerHTML = decodeURIComponent(hashContent); // Unsafe!
        }
    }
});

// Unsafe search function for DOM-based XSS
function performSearch(query) {
    if (!query) return;
    
    fetch(`/api/search?q=${encodeURIComponent(query)}`)
        .then(response => response.json())
        .then(data => {
            const resultsDiv = document.getElementById('search-results');
            if (resultsDiv) {
                // Unsafe innerHTML usage
                resultsDiv.innerHTML = `
                    <h3>Search Results</h3>
                    <p>${data.message}</p>
                    <div class="results">${data.results}</div>
                `;
            }
        })
        .catch(error => {
            console.error('Search error:', error);
        });
}

// Utility functions for future features
function showMessage(message, type = 'info') {
    // Unsafe message display function
    const messageDiv = document.createElement('div');
    messageDiv.className = `alert alert-${type}`;
    messageDiv.innerHTML = message; // Unsafe!
    document.body.appendChild(messageDiv);
    
    setTimeout(() => {
        messageDiv.remove();
    }, 5000);
}

function validateInput(input, pattern) {
    // Basic input validation (intentionally flawed)
    return pattern.test(input);
}

// Expose sensitive functions globally
window.BadBank = {
    showMessage: showMessage,
    performSearch: performSearch,
    validateInput: validateInput,
    currentUser: window.currentUser || null
};

// Auto-fill functionality that could be exploited
function autoFillForm(formId, data) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    Object.keys(data).forEach(key => {
        const input = form.querySelector(`[name="${key}"]`);
        if (input) {
            input.value = data[key];
        }
    });
}

// Expose auto-fill globally
window.autoFillForm = autoFillForm;
