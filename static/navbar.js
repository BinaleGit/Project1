document.addEventListener("DOMContentLoaded", function() {
    // Fetch the navigation bar content and inject it into the navbar-container div
    fetch('navbar.html')
        .then(response => response.text())
        .then(data => {
            document.getElementById('navbar-container').innerHTML = data;
        });
});

// this is onlyworking not with flask
