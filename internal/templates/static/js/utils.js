/**
 * Utility Functions for AuthGate
 */

/**
 * Format timestamps to relative time
 */
function formatRelativeTime(timestamp) {
  var date = new Date(timestamp);
  var now = new Date();
  var diffInSeconds = Math.floor((now - date) / 1000);

  if (diffInSeconds < 60) return 'just now';
  if (diffInSeconds < 3600) return Math.floor(diffInSeconds / 60) + ' minutes ago';
  if (diffInSeconds < 86400) return Math.floor(diffInSeconds / 3600) + ' hours ago';
  if (diffInSeconds < 2592000) return Math.floor(diffInSeconds / 86400) + ' days ago';

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
    var textarea = document.createElement('textarea');
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

// ============================================
// Toast Notification System
// ============================================

var TOAST_ICONS = {
  success: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M7 10l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5"/></svg>',
  error: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M7.5 7.5l5 5M12.5 7.5l-5 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
  warning: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M10 3L2 17h16L10 3z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M10 8v4M10 14v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
  info: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M10 9v4M10 7v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>'
};

/**
 * Show toast notification with stacking, close button, and auto-dismiss
 */
function showNotification(message, type) {
  type = type || 'info';
  var container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    container.setAttribute('aria-live', 'polite');
    document.body.appendChild(container);
  }

  var toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.setAttribute('role', 'alert');

  var iconHtml = TOAST_ICONS[type] || TOAST_ICONS.info;
  toast.innerHTML =
    '<span class="toast-icon">' + iconHtml + '</span>' +
    '<span class="toast-content">' + escapeHtml(message) + '</span>' +
    '<button type="button" class="toast-close" aria-label="Dismiss">&times;</button>' +
    '<div class="toast-progress"></div>';

  var closeBtn = toast.querySelector('.toast-close');
  closeBtn.addEventListener('click', function() {
    dismissToast(toast);
  });

  container.appendChild(toast);

  var timer = setTimeout(function() {
    dismissToast(toast);
  }, 3000);

  toast._dismissTimer = timer;
}

function dismissToast(toast) {
  if (toast._dismissed) return;
  toast._dismissed = true;
  clearTimeout(toast._dismissTimer);
  toast.classList.add('toast-removing');
  setTimeout(function() {
    if (toast.parentNode) {
      toast.parentNode.removeChild(toast);
    }
  }, 250);
}

function escapeHtml(str) {
  var div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

// ============================================
// Confirmation Modal System
// ============================================

var MODAL_ICONS = {
  danger: '<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><circle cx="11" cy="11" r="9" stroke="currentColor" stroke-width="2"/><path d="M11 7v5M11 14.5v.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  warning: '<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 3L2 19h18L11 3z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M11 9v4M11 15.5v.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  info: '<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><circle cx="11" cy="11" r="9" stroke="currentColor" stroke-width="2"/><path d="M11 10v5M11 7.5v.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'
};

/**
 * Show custom confirmation modal. Returns a Promise that resolves true/false.
 */
function confirmModal(options) {
  var title = options.title || 'Confirm';
  var message = options.message || 'Are you sure?';
  var style = options.style || 'danger';
  var confirmText = options.confirmText || 'Confirm';

  return new Promise(function(resolve) {
    // Create overlay
    var overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'modal-title');

    var iconHtml = MODAL_ICONS[style] || MODAL_ICONS.danger;

    overlay.innerHTML =
      '<div class="modal-card">' +
        '<div class="modal-header">' +
          '<div class="modal-icon modal-icon-' + style + '">' + iconHtml + '</div>' +
          '<div class="modal-text">' +
            '<h3 class="modal-title" id="modal-title">' + escapeHtml(title) + '</h3>' +
            '<p class="modal-message">' + escapeHtml(message) + '</p>' +
          '</div>' +
        '</div>' +
        '<div class="modal-actions">' +
          '<button type="button" class="modal-btn modal-btn-cancel">Cancel</button>' +
          '<button type="button" class="modal-btn modal-btn-confirm modal-btn-' + style + '">' + escapeHtml(confirmText) + '</button>' +
        '</div>' +
      '</div>';

    document.body.appendChild(overlay);

    // Focus trap
    var cancelBtn = overlay.querySelector('.modal-btn-cancel');
    var confirmBtn = overlay.querySelector('.modal-btn-confirm');
    var previousFocus = document.activeElement;

    // Trigger open animation
    requestAnimationFrame(function() {
      overlay.classList.add('modal-open');
      confirmBtn.focus();
    });

    function close(result) {
      overlay.classList.remove('modal-open');
      setTimeout(function() {
        if (overlay.parentNode) {
          overlay.parentNode.removeChild(overlay);
        }
        if (previousFocus) {
          previousFocus.focus();
        }
      }, 250);
      resolve(result);
    }

    cancelBtn.addEventListener('click', function() { close(false); });
    confirmBtn.addEventListener('click', function() { close(true); });

    // Close on overlay click (not card)
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) { close(false); }
    });

    // Close on Escape
    function onKeydown(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        close(false);
        document.removeEventListener('keydown', onKeydown);
      }
      // Focus trap: Tab cycles between cancel and confirm
      if (e.key === 'Tab') {
        var focusable = [cancelBtn, confirmBtn];
        var idx = focusable.indexOf(document.activeElement);
        if (e.shiftKey) {
          e.preventDefault();
          focusable[(idx - 1 + focusable.length) % focusable.length].focus();
        } else {
          e.preventDefault();
          focusable[(idx + 1) % focusable.length].focus();
        }
      }
    }
    document.addEventListener('keydown', onKeydown);
  });
}

/**
 * Confirm action before proceeding (legacy compat)
 */
function confirmAction(message) {
  return confirm(message);
}

/**
 * Toggle details visibility
 */
function toggleDetails(buttonElement) {
  var detailsContent = buttonElement.nextElementSibling;

  if (detailsContent) {
    var isHidden = detailsContent.style.display === 'none' || !detailsContent.style.display;

    detailsContent.style.display = isHidden ? 'block' : 'none';
    buttonElement.textContent = isHidden ? 'Hide Details' : 'Show Details';
  }
}

// ============================================
// Dark Mode / Theme
// ============================================

/**
 * Initialize theme from localStorage or system preference.
 * Called inline in <head> to prevent FOUC.
 */
function initTheme() {
  var saved = localStorage.getItem('authgate-theme');
  if (saved === 'dark' || saved === 'light') {
    document.documentElement.setAttribute('data-theme', saved);
  }
  // If no saved preference, the @media prefers-color-scheme fallback in CSS handles it
}

/**
 * Toggle between light/dark themes.
 */
function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme');
  var next;

  if (current === 'dark') {
    next = 'light';
  } else if (current === 'light') {
    next = 'dark';
  } else {
    // No explicit attribute — detect system preference
    next = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'light' : 'dark';
  }

  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('authgate-theme', next);
  updateThemeToggleIcon(next);
}

function updateThemeToggleIcon(theme) {
  var btn = document.getElementById('theme-toggle-btn');
  if (!btn) return;
  var isDark = theme === 'dark' ||
    (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches);
  btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  // Toggle icon visibility
  var sunIcon = btn.querySelector('.theme-icon-sun');
  var moonIcon = btn.querySelector('.theme-icon-moon');
  if (sunIcon && moonIcon) {
    sunIcon.style.display = isDark ? 'block' : 'none';
    moonIcon.style.display = isDark ? 'none' : 'block';
  }
}

// ============================================
// Debounced Search
// ============================================

/**
 * Initialize debounced search on inputs with [data-debounce-search].
 */
function initDebounceSearch() {
  var inputs = document.querySelectorAll('[data-debounce-search]');
  inputs.forEach(function(input) {
    var timer = null;
    input.addEventListener('input', function() {
      clearTimeout(timer);
      timer = setTimeout(function() {
        var form = input.closest('form');
        if (form) { form.submit(); }
      }, 300);
    });
  });
}

// ============================================
// Collapsible Audit Filters
// ============================================

/**
 * Toggle audit log advanced filters visibility.
 */
function toggleFilters() {
  var filters = document.getElementById('audit-advanced-filters');
  var btn = document.getElementById('toggle-filters-btn');
  if (!filters || !btn) return;

  var isHidden = filters.classList.contains('filters-collapsed');
  filters.classList.toggle('filters-collapsed');
  btn.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
  var btnText = btn.querySelector('.toggle-filters-text');
  if (btnText) {
    btnText.textContent = isHidden ? 'Hide Filters' : 'Show Filters';
  }
  var icon = btn.querySelector('.toggle-filters-icon');
  if (icon) {
    icon.style.transform = isHidden ? 'rotate(180deg)' : '';
  }

  // Save preference
  localStorage.setItem('authgate-audit-filters', isHidden ? 'open' : 'closed');
}

/**
 * Initialize collapsible filter state from localStorage.
 */
function initCollapsibleFilters() {
  var filters = document.getElementById('audit-advanced-filters');
  if (!filters) return;
  var saved = localStorage.getItem('authgate-audit-filters');
  if (saved === 'closed') {
    filters.classList.add('filters-collapsed');
    var btn = document.getElementById('toggle-filters-btn');
    if (btn) {
      btn.setAttribute('aria-expanded', 'false');
      var btnText = btn.querySelector('.toggle-filters-text');
      if (btnText) btnText.textContent = 'Show Filters';
    }
  }
}

export {
  formatRelativeTime,
  copyToClipboard,
  showNotification,
  confirmAction,
  confirmModal,
  toggleDetails,
  initTheme,
  toggleTheme,
  initDebounceSearch,
  toggleFilters,
  initCollapsibleFilters
};

/**
 * Initialization
 */
document.addEventListener('DOMContentLoaded', function() {
  // Theme toggle icon
  var theme = document.documentElement.getAttribute('data-theme');
  updateThemeToggleIcon(theme);

  // Debounced search
  initDebounceSearch();

  // Collapsible filters
  initCollapsibleFilters();

  // Keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    // ESC to close mobile menu
    if (e.key === 'Escape') {
      var navbarMenu = document.getElementById('navbarMenu');
      if (navbarMenu && navbarMenu.classList.contains('active')) {
        navbarMenu.classList.remove('active');
      }
    }
  });

  // Delegated handler for data-confirm-* attributes
  document.addEventListener('submit', function(e) {
    var target = e.target;
    // Check if the form or submitter has data-confirm-title
    var submitter = e.submitter;
    var el = null;

    if (submitter && submitter.hasAttribute('data-confirm-title')) {
      el = submitter;
    } else if (target.hasAttribute && target.hasAttribute('data-confirm-title')) {
      el = target;
    }

    if (!el) return;

    e.preventDefault();
    var confirmTitle = el.getAttribute('data-confirm-title');
    var confirmMessage = el.getAttribute('data-confirm-message') || 'Are you sure?';
    var confirmStyle = el.getAttribute('data-confirm-style') || 'danger';
    var confirmLabel = el.getAttribute('data-confirm-label') || 'Confirm';

    confirmModal({
      title: confirmTitle,
      message: confirmMessage,
      style: confirmStyle,
      confirmText: confirmLabel
    }).then(function(confirmed) {
      if (confirmed) {
        // Remove the data attribute temporarily to avoid re-triggering
        el.removeAttribute('data-confirm-title');
        if (submitter) {
          submitter.click();
        } else {
          target.submit();
        }
      }
    });
  });
});
