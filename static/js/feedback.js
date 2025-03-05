 // Function to remove flash messages after 5 seconds
 setTimeout(function() {
    let flashMessages = document.querySelectorAll('.success');
    flashMessages.forEach(function(message) {
        message.remove();
    });
}, 5000); // 5000 milliseconds = 5 seconds