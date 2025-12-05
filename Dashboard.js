// ======= USER INFO & CART =======
const userName = localStorage.getItem('userName') || 'User';
document.querySelector('.main-content h2').textContent = `Welcome Back,user`;

const cartIcon = document.querySelector('.cart-icon');
let cartCount = parseInt(localStorage.getItem('cartCount')) || 0;
cartIcon.textContent = `🛒 Cart (${cartCount})`;

// Function to update cart count globally
function updateCartCount(count) {
    localStorage.setItem('cartCount', count);
    cartIcon.textContent = `🛒 Cart (${count})`;
}

// ======= SEARCH FUNCTIONALITY =======
const searchInput = document.querySelector('.search-container input');
const searchButton = document.querySelector('.search-container button');

searchButton.addEventListener('click', () => {
    const query = searchInput.value.trim();
    if (query === '') {
        alert('Please type something to search!');
    } else {
        console.log('Searching for:', query);
        // Redirect to search page or filter products dynamically
        // window.location.href = `search.html?q=${encodeURIComponent(query)}`;
    }
});

// ======= SIDEBAR ACTIVE LINK =======
const sidebarLinks = document.querySelectorAll('.sidebar ul li a');
sidebarLinks.forEach(link => {
    if (link.href === window.location.href) {
        link.classList.add('active');
    }
});

// ======= DASHBOARD STATS =======
const ordersCount = parseInt(localStorage.getItem('ordersCount')) || 4;
const wishlistCount = parseInt(localStorage.getItem('wishlistCount')) || 2;

document.querySelector('.contents .content:nth-child(1) p').textContent = `${ordersCount} Orders in Progress`;
document.querySelector('.contents .content:nth-child(2) p').textContent = `${wishlistCount} Saved Items`;

// ======= RECENT ORDERS BUTTONS =======
document.querySelectorAll('.recent-orders button').forEach(button => {
    button.addEventListener('click', (e) => {
        const orderItem = e.target.closest('.order-item');
        const orderNumber = orderItem.querySelector('strong').textContent;

        if (button.textContent.includes('Track')) {
            // Redirect to tracking page
            window.location.href = `trackorder.html?order=${orderNumber}`;
        } else if (button.textContent.includes('View')) {
            // Redirect to order details page
            window.location.href = `orderdetails.html?order=${orderNumber}`;
        }
    });
});

document.querySelector('.cart-icon').addEventListener('click', () => {
    window.location.href = '../Cart/cart.html';
});

