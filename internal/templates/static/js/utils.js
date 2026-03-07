/**
 * Utility Functions for AuthGate
 */

/**
 * Format timestamps to relative time
 */
function formatRelativeTime(timestamp) {
  const date = new Date(timestamp);
  const now = new Date();
  const diffInSeconds = Math.floor((now - date) / 1000);

  if (diffInSeconds < 60) return 'just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
  if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)} days ago`;

  return date.toLocaleDateString();
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() {
      showNotification('Copied to clipboard!', 'success');
    }).catch(function(err) {
      console.error('Failed to copy:', err);
      showNotification('Failed to copy', 'error');
    });
  } else {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();

    try {
      document.execCommand('copy');
      showNotification('Copied to clipboard!', 'success');
    } catch (err) {
      console.error('Failed to copy:', err);
      showNotification('Failed to copy', 'error');
    }

    document.body.removeChild(textarea);
  }
}

/**
 * Show temporary notification
 */
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `alert alert-${type}`;
  notification.textContent = message;
  notification.style.position = 'fixed';
  notification.style.top = '20px';
  notification.style.right = '20px';
  notification.style.zIndex = '9999';
  notification.style.minWidth = '250px';
  notification.style.animation = 'slideInRight 0.3s ease-out';

  document.body.appendChild(notification);

  setTimeout(function() {
    notification.style.animation = 'fadeOut 0.3s ease-out';
    setTimeout(function() {
      document.body.removeChild(notification);
    }, 300);
  }, 3000);
}

/**
 * Confirm action before proceeding
 */
function confirmAction(message) {
  return confirm(message);
}

/**
 * Toggle details visibility
 */
function toggleDetails(buttonElement) {
  const detailsContent = buttonElement.nextElementSibling;

  if (detailsContent) {
    const isHidden = detailsContent.style.display === 'none' || !detailsContent.style.display;

    detailsContent.style.display = isHidden ? 'block' : 'none';
    buttonElement.textContent = isHidden ? 'Hide Details' : 'Show Details';
  }
}

export { formatRelativeTime, copyToClipboard, showNotification, confirmAction, toggleDetails };

/**
 * Initialize tooltips (if needed)
 */
document.addEventListener('DOMContentLoaded', function() {
  // Add any initialization code here

  // Add keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    // ESC to close mobile menu
    if (e.key === 'Escape') {
      const navbarMenu = document.getElementById('navbarMenu');
      if (navbarMenu && navbarMenu.classList.contains('active')) {
        navbarMenu.classList.remove('active');
      }
    }
  });
});
