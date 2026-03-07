/**
 * Navbar Toggle for Mobile Menu
 */
function toggleMenu() {
  const menu = document.getElementById('navbarMenu');
  if (menu) {
    menu.classList.toggle('active');
  }
}

/**
 * Toggle dropdown open/closed (used on mobile and as click fallback)
 * @param {HTMLElement} trigger - The dropdown trigger button
 */
function toggleDropdown(trigger) {
  const isExpanded = trigger.getAttribute('aria-expanded') === 'true';

  // Close all other dropdowns first
  document.querySelectorAll('.navbar-dropdown-trigger[aria-expanded="true"]').forEach(function(btn) {
    if (btn !== trigger) {
      btn.setAttribute('aria-expanded', 'false');
    }
  });

  trigger.setAttribute('aria-expanded', isExpanded ? 'false' : 'true');
}

export { toggleMenu, toggleDropdown };

// Close mobile menu when clicking outside
document.addEventListener('DOMContentLoaded', function() {
  const navbar = document.querySelector('.navbar');
  const navbarMenu = document.getElementById('navbarMenu');
  const navbarToggle = document.querySelector('.navbar-toggle');

  if (navbar && navbarMenu && navbarToggle) {
    document.addEventListener('click', function(event) {
      const isClickInside = navbar.contains(event.target);

      if (!isClickInside) {
        if (navbarMenu.classList.contains('active')) {
          navbarMenu.classList.remove('active');
        }
        // Close all dropdowns
        document.querySelectorAll('.navbar-dropdown-trigger[aria-expanded="true"]').forEach(function(btn) {
          btn.setAttribute('aria-expanded', 'false');
        });
      }
    });

    // Close menu when clicking on a link (not a dropdown trigger)
    const navLinks = navbarMenu.querySelectorAll('.navbar-link:not(.navbar-dropdown-trigger), .navbar-dropdown-item');
    navLinks.forEach(function(link) {
      link.addEventListener('click', function() {
        if (window.innerWidth <= 768) {
          navbarMenu.classList.remove('active');
        }
      });
    });
  }
});
