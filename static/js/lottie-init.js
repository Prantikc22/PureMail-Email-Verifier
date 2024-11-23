document.addEventListener('DOMContentLoaded', function() {
    // Initialize hero animation
    const heroAnimation = document.querySelector('#hero-animation');
    if (heroAnimation) {
        heroAnimation.load('https://assets2.lottiefiles.com/packages/lf20_dzn5ys7x.json');
    }

    // Initialize AI animation
    const aiAnimation = document.querySelector('#ai-animation');
    if (aiAnimation) {
        aiAnimation.load('https://assets10.lottiefiles.com/packages/lf20_xyadoh9h.json');
    }
});
