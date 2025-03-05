document.addEventListener("DOMContentLoaded", () => {
    // Navbar Scroll Effect
    window.addEventListener("scroll", () => {
        const navbar = document.querySelector(".navbar");
        if (window.scrollY > 50) {
            navbar.style.background = "rgba(0, 0, 0, 0.9)";
        } else {
            navbar.style.background = "rgba(0, 0, 0, 0.85)";
        }
    });

    // Floating Bubbles
    const bubbles = document.querySelector(".bubbles");
    setInterval(() => {
        const bubble = document.createElement("span");
        bubble.classList.add("bubble");
        bubble.style.left = Math.random() * 100 + "vw";
        bubble.style.animationDuration = Math.random() * 5 + 3 + "s";
        bubbles.appendChild(bubble);
        setTimeout(() => bubble.remove(), 5000);
    }, 400);
});
