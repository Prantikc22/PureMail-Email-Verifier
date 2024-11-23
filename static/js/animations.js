document.addEventListener('DOMContentLoaded', () => {
    // Register ScrollTrigger plugin
    gsap.registerPlugin(ScrollTrigger);

    // Navbar scroll effect
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    // Hero section animation
    gsap.from('.hero-section h1', {
        duration: 1,
        y: 50,
        opacity: 0,
        ease: 'power3.out'
    });

    gsap.from('.hero-section p', {
        duration: 1,
        y: 50,
        opacity: 0,
        delay: 0.3,
        ease: 'power3.out'
    });

    gsap.from('.hero-section .btn', {
        duration: 1,
        y: 50,
        opacity: 0,
        delay: 0.6,
        ease: 'power3.out'
    });

    // Initialize stats animation
    const stats = document.querySelectorAll('.stat-value');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const target = parseFloat(entry.target.getAttribute('data-value'));
                animateValue(entry.target, 0, target, 2000);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    stats.forEach(stat => observer.observe(stat));

    // Stats counter animation
    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            const value = progress * (end - start) + start;
            obj.textContent = value.toFixed(end % 1 === 0 ? 0 : 1);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }

    // Initialize particles for stats section
    if (document.getElementById('stats-particles')) {
        particlesJS('stats-particles', {
            particles: {
                number: {
                    value: 80,
                    density: {
                        enable: true,
                        value_area: 800
                    }
                },
                color: {
                    value: '#ffffff'
                },
                opacity: {
                    value: 0.1,
                    random: false
                },
                size: {
                    value: 3,
                    random: true
                },
                line_linked: {
                    enable: true,
                    distance: 150,
                    color: '#ffffff',
                    opacity: 0.1,
                    width: 1
                },
                move: {
                    enable: true,
                    speed: 2,
                    direction: 'none',
                    random: false,
                    straight: false,
                    out_mode: 'out',
                    bounce: false
                }
            },
            interactivity: {
                detect_on: 'canvas',
                events: {
                    onhover: {
                        enable: true,
                        mode: 'grab'
                    },
                    resize: true
                }
            },
            retina_detect: true
        });
    }

    // Scroll animations
    gsap.utils.toArray('.feature-card, .analysis-feature-item, .stat-item, .testimonial-card, .pricing-card').forEach(element => {
        gsap.from(element, {
            scrollTrigger: {
                trigger: element,
                start: 'top bottom-=100',
                toggleActions: 'play none none reverse'
            },
            y: 50,
            opacity: 0,
            duration: 1,
            ease: 'power3.out'
        });
    });

    // Progress rings animation
    document.querySelectorAll('.progress-ring').forEach((ring, index) => {
        const progress = [75, 90, 85, 95][index] || 80; // Default progress values
        
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        circle.setAttribute('viewBox', '0 0 36 36');
        circle.innerHTML = `
            <path d="M18 2.0845
                a 15.9155 15.9155 0 0 1 0 31.831
                a 15.9155 15.9155 0 0 1 0 -31.831"
                fill="none"
                stroke="#eee"
                stroke-width="3"
                stroke-dasharray="100, 100"/>
            <path d="M18 2.0845
                a 15.9155 15.9155 0 0 1 0 31.831
                a 15.9155 15.9155 0 0 1 0 -31.831"
                fill="none"
                stroke="#4a1f82"
                stroke-width="3"
                stroke-dasharray="0, 100"/>
        `;
        ring.appendChild(circle);

        gsap.to(circle.querySelector('path:last-child'), {
            scrollTrigger: {
                trigger: '.ai-analysis-section',
                start: 'top center'
            },
            strokeDasharray: `${progress}, 100`,
            duration: 1.5,
            ease: 'power2.out'
        });
    });

    // Email process animation in hero section
    const createEmailAnimation = () => {
        const container = document.querySelector('.email-process-animation');
        if (!container) return;

        const email = document.createElement('div');
        email.className = 'email-particle';
        container.appendChild(email);

        gsap.fromTo(email, 
            {
                x: -50,
                y: 'random(0, 100)',
                scale: 0,
                opacity: 0
            },
            {
                x: container.offsetWidth + 50,
                y: 'random(0, 100)',
                scale: 1,
                opacity: 1,
                duration: 'random(2, 3)',
                ease: 'power1.inOut',
                onComplete: () => {
                    email.remove();
                }
            }
        );
    };

    // Create email particles periodically
    setInterval(createEmailAnimation, 1000);
});
