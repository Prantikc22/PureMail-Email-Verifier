document.addEventListener('DOMContentLoaded', () => {
    const track = document.querySelector('.testimonial-track');
    if (!track) return;

    // Clone the testimonials for seamless scrolling
    const testimonials = track.querySelectorAll('.testimonial-card');
    testimonials.forEach(testimonial => {
        const clone = testimonial.cloneNode(true);
        track.appendChild(clone);
    });

    // Pause animation on hover
    track.addEventListener('mouseenter', () => {
        track.style.animationPlayState = 'paused';
    });

    track.addEventListener('mouseleave', () => {
        track.style.animationPlayState = 'running';
    });

    // Reset animation when it ends
    track.addEventListener('animationend', () => {
        track.style.animation = 'none';
        track.offsetHeight; // Trigger reflow
        track.style.animation = 'scroll 30s linear infinite';
    });
});
