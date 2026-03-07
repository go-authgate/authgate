/**
 * Admin Pages JavaScript
 * Functions for admin interface interactions
 */

/**
 * Copy client secret to clipboard
 */
function copySecret() {
  const secretElement = document.getElementById('clientSecret');
  if (!secretElement) {
    console.error('Secret element not found');
    return;
  }

  const secret = secretElement.textContent;

  // Use modern clipboard API if available
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(secret)
      .then(function() {
        showNotification('Client secret copied to clipboard!', 'success');
      })
      .catch(function(err) {
        console.error('Failed to copy:', err);
        fallbackCopySecret(secret);
      });
  } else {
    // Fallback for older browsers
    fallbackCopySecret(secret);
  }
}

/**
 * Fallback method to copy text for older browsers
 */
function fallbackCopySecret(text) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();

  try {
    const successful = document.execCommand('copy');
    if (successful) {
      showNotification('Client secret copied to clipboard!', 'success');
    } else {
      showNotification('Failed to copy secret', 'error');
    }
  } catch (err) {
    console.error('Failed to copy:', err);
    showNotification('Failed to copy secret', 'error');
  }

  document.body.removeChild(textarea);
}

/**
 * Show notification (uses utils.js if available)
 */
function showNotification(message, type) {
  // Try to use the notification function from utils.js
  if (typeof window.showNotification === 'function') {
    window.showNotification(message, type);
    return;
  }

  // Fallback to alert if utils.js is not loaded
  alert(message);
}

/**
 * Toggle client description in table
 */
function toggleDescription(button) {
  const cell = button.closest('.client-name-cell');
  if (!cell) return;

  const description = cell.querySelector('.client-description');
  const icon = button.querySelector('.toggle-icon');

  if (!description) return;

  if (description.style.display === 'none' || !description.style.display) {
    // Show description
    description.style.display = 'block';
    button.classList.add('expanded');

    // Animate height
    description.style.maxHeight = '0';
    description.style.overflow = 'hidden';
    description.style.transition = 'max-height 0.3s ease-out';

    // Trigger reflow
    description.offsetHeight;

    description.style.maxHeight = description.scrollHeight + 'px';
  } else {
    // Hide description
    description.style.maxHeight = '0';
    button.classList.remove('expanded');

    setTimeout(function() {
      description.style.display = 'none';
    }, 300);
  }
}

/**
 * Confirm delete action
 */
function confirmDelete(clientName) {
  return confirm(
    'Are you sure you want to delete this client?\n\n' +
    'Client: ' + clientName + '\n\n' +
    'This action cannot be undone and will revoke all access tokens.'
  );
}

/**
 * Confirm regenerate secret
 */
function confirmRegenerateSecret() {
  return confirm(
    'Are you sure you want to regenerate the client secret?\n\n' +
    'This will invalidate the current secret and any applications using it will stop working until updated with the new secret.'
  );
}

export { copySecret, toggleDescription, confirmDelete, confirmRegenerateSecret };

/**
 * Initialize admin page interactions
 */
document.addEventListener('DOMContentLoaded', function() {
  // Add any initialization code here

  // Example: Auto-select secret on click
  const secretElements = document.querySelectorAll('.secret-value, .secret-value-enhanced');
  secretElements.forEach(function(element) {
    element.addEventListener('click', function() {
      const range = document.createRange();
      range.selectNodeContents(element);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    });
  });
});
