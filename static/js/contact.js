document.addEventListener('DOMContentLoaded', function() {
    // Get the "Send Message" button by its ID
    const sendMessageBtn = document.getElementById('sendMessageBtn');

    // Add a click event listener to the button
    sendMessageBtn.addEventListener('click', function(event) {
        // Prevent the form from submitting (optional)
        event.preventDefault();

        // Display the alert message
        alert('Message sent');
    });
});
    let slideIndex = 0;

    function moveSlide(direction) {
        let slides = document.querySelectorAll(".carousel-image");
        slideIndex += direction;

        if (slideIndex < 0) {
            slideIndex = slides.length - 1;
        } else if (slideIndex >= slides.length) {
            slideIndex = 0;
        }

        let offseta = -slideIndex * 100;
        document.querySelector(".carousel-slide").style.transform = "translateX(" + offset + "%)";
    }