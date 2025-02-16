// Pause and Resume Event Carousel on Hover
const eventCarousel = document.querySelector(".event-carousel");
if (eventCarousel) {
    eventCarousel.addEventListener("mouseover", () => eventCarousel.style.animationPlayState = "paused");
    eventCarousel.addEventListener("mouseleave", () => eventCarousel.style.animationPlayState = "running");
}

// Countdown Timer for Events
function updateCountdown() {
    const eventDate = new Date("2025-03-15T18:00:00").getTime();
    const now = new Date().getTime();
    const diff = eventDate - now;

    const countdownElement = document.getElementById("event-countdown");
    if (!countdownElement) return;

    if (diff < 0) {
        countdownElement.innerHTML = "Event Started!";
        return;
    }

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);

    countdownElement.innerHTML = `${days}d ${hours}h ${minutes}m ${seconds}s`;
}

setInterval(updateCountdown, 1000);
updateCountdown();

// Swiper Instances for Multiple Carousels
const eventSwiper1 = new Swiper('.swiper-1', { loop: true, autoplay: { delay: 3000 } });
const eventSwiper2 = new Swiper('.swiper-2', { loop: true, autoplay: { delay: 4000 } });
const eventSwiper3 = new Swiper('.swiper-3', { loop: true, autoplay: { delay: 5000 } });
const eventSwiper4 = new Swiper('.swiper-4', { loop: true, autoplay: { delay: 6000 } });

// Live Users Counter

function updateLiveUsers() {
    const liveUsersElement = document.getElementById("event-live-users");
    if (!liveUsersElement) return; // Prevent errors if the element is missing

    const liveUsers = Math.floor(Math.random() * 1000) + 50; // Generates a random number between 50 and 1050
    liveUsersElement.textContent = liveUsers;
}

// Update every 10 seconds
setInterval(updateLiveUsers, 10000);
updateLiveUsers(); // Initial call to set the first value


