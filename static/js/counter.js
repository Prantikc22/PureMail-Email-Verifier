document.addEventListener('DOMContentLoaded', () => {
    const counters = document.querySelectorAll('.counter');
    
    const startCounting = (counter) => {
        const target = parseFloat(counter.dataset.target);
        const start = parseFloat(counter.dataset.start || '0');
        const duration = 2000; // 2 seconds
        const steps = 60;
        const increment = (target - start) / steps;
        let current = start;
        
        const updateCounter = () => {
            current += increment;
            if ((increment > 0 && current >= target) || (increment < 0 && current <= target)) {
                counter.textContent = target;
                return;
            }
            
            counter.textContent = current.toFixed(1);
            requestAnimationFrame(updateCounter);
        };
        
        updateCounter();
    };
    
    // Intersection Observer
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                startCounting(entry.target);
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.5
    });
    
    counters.forEach(counter => observer.observe(counter));
});
