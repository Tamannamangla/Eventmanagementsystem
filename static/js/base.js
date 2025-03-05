  // Handle logout confirmation and redirection
  document.getElementById('logoutButton').addEventListener('click', function (event) {
    event.preventDefault(); // Prevent default link behavior

    // Show confirmation pop-up
    if (confirm("Are you sure you want to log out?")) {
        // If user clicks "Yes", proceed with logout
        fetch("{{ url_for('logout') }}", {
            method: 'GET',
        }).then(response => {
            if (response.ok) {
                alert("Logged out successfully!"); // Show success pop-up
                setTimeout(function () {
                    window.location.href = "{{ url_for('index') }}"; // Redirect to index page after 5 seconds
                }, 5000); // 5 seconds delay
            }
        });
    }
});

const eventSearchInput = document.getElementById('event-search');
const locationSearchInput = document.getElementById('location-search');

eventSearchInput.addEventListener('input', function () {
    performSearch(eventSearchInput.value, locationSearchInput.value);
});

locationSearchInput.addEventListener('input', function () {
    performSearch(eventSearchInput.value, locationSearchInput.value);
});

function performSearch(eventQuery, locationQuery) {
    fetch(`/search?event=${eventQuery}&location=${locationQuery}`)
        .then(response => response.json())
        .then(data => {
            // Show search results dynamically
            let resultsHTML = '';
            if (data.events.length || data.locations.length) {
                if (data.events.length) {
                    resultsHTML += '<h3>Events</h3><ul>';
                    data.events.forEach(event => {
                        resultsHTML += `<li>${event.name} - ${event.location}</li>`;
                    });
                    resultsHTML += '</ul>';
                }
                if (data.locations.length) {
                    resultsHTML += '<h3>Locations</h3><ul>';
                    data.locations.forEach(location => {
                        resultsHTML += `<li>${location.name}</li>`;
                    });
                    resultsHTML += '</ul>';
                }
            } else {
                resultsHTML = '<p>No results found</p>';
            }
            document.getElementById('search-results').innerHTML = resultsHTML;
        })
        .catch(error => console.error('Error performing search:', error));
}