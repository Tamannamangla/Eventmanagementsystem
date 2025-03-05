function createShapes(count) {
    const container = document.querySelector('.floating-shapes');
    for (let i = 0; i < count; i++) {
        let shape = document.createElement('div');
        shape.className = 'shape';
        shape.style.top = Math.random() * 100 + 'vh';
        shape.style.left = Math.random() * 100 + 'vw';
        shape.style.animationDelay = Math.random() * 5 + 's';
        container.appendChild(shape);
    }
}
createShapes(40);