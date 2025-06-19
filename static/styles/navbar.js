// Enhanced navbar.js with dropdown functionality
document.addEventListener('DOMContentLoaded', function() {
    // Variables for scroll detection
    let lastScrollTop = 0;
    const navbar = document.querySelector('.navbar-container');
    const scrollThreshold = 100; // Threshold in pixels
    
    // Function to handle scroll behavior
    function handleScroll() {
        const currentScroll = window.pageYOffset || document.documentElement.scrollTop;
        
        // Show navbar when user scrolls to the top
        if (currentScroll <= 10) {
            navbar.classList.remove('navbar-hidden');
            return;
        }
        
        // Show/hide navbar based on scroll direction
        if (currentScroll > lastScrollTop && currentScroll > scrollThreshold) {
            // Scrolling down
            navbar.classList.add('navbar-hidden');
        } else {
            // Scrolling up
            navbar.classList.remove('navbar-hidden');
        }
        
        lastScrollTop = currentScroll <= 0 ? 0 : currentScroll; // For Mobile or negative scrolling
    }
    
    // Toggle navbar visibility on hover at top of page
    function handleMouseAtTop(event) {
        if (event.clientY < 50) {
            navbar.classList.remove('navbar-hidden');
        }
    }
    
    // Add event listeners for scroll and mouse movement
    window.addEventListener('scroll', handleScroll, false);
    document.addEventListener('mousemove', handleMouseAtTop, false);
    
    // Mobile menu toggle
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const navLinks = document.querySelector('.nav-links');
    
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', function() {
            navLinks.classList.toggle('active');
        });
    }
    
    // Dropdown functionality
    const dropdowns = document.querySelectorAll('.dropdown');
    
    // Toggle dropdown visibility on click and handle outside clicks
    dropdowns.forEach(dropdown => {
        const dropdownLink = dropdown.querySelector('.nav-item') || dropdown.querySelector('.user-icon');
        const dropdownContent = dropdown.querySelector('.dropdown-content');
        
        if (dropdownLink && dropdownContent) {
            // Toggle on click
            dropdownLink.addEventListener('click', function(e) {
                e.preventDefault(); // Prevent navigation if it's a link
                
                // Close other open dropdowns first
                document.querySelectorAll('.dropdown-content.show').forEach(content => {
                    if (content !== dropdownContent) {
                        content.classList.remove('show');
                    }
                });
                
                // Toggle current dropdown
                dropdownContent.classList.toggle('show');
            });
        }
    });
    
    // Close dropdown when clicking outside
    window.addEventListener('click', function(e) {
        if (!e.target.matches('.nav-item') && !e.target.closest('.dropdown')) {
            const dropdowns = document.querySelectorAll('.dropdown-content');
            dropdowns.forEach(dropdown => {
                if (dropdown.classList.contains('show')) {
                    dropdown.classList.remove('show');
                }
            });
        }
    });
});

