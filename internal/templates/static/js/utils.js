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
    return navigator.clipboard.writeText(text).then(function() {
      showNotification('Copied to clipboard!', 'success');
      return true;
    }).catch(function(err) {
      console.error('Failed to copy:', err);
      showNotification('Failed to copy', 'error');
      return false;
    });
  } else {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();

    var success = false;
    try {
      success = document.execCommand('copy');
      if (success) {
        showNotification('Copied to clipboard!', 'success');
      } else {
        showNotification('Failed to copy', 'error');
      }
    } catch (err) {
      console.error('Failed to copy:', err);
      showNotification('Failed to copy', 'error');
    }

    document.body.removeChild(textarea);
    return Promise.resolve(success);
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
  if (!container) return;

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
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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

    var cancelBtn = overlay.querySelector('.modal-btn-cancel');
    var confirmBtn = overlay.querySelector('.modal-btn-confirm');
    var previousFocus = document.activeElement;

    requestAnimationFrame(function() {
      overlay.classList.add('modal-open');
      confirmBtn.focus();
    });

    function onKeydown(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        close(false);
      }
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

    function close(result) {
      document.removeEventListener('keydown', onKeydown);
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

    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) { close(false); }
    });

    document.addEventListener('keydown', onKeydown);
  });
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
 * Toggle between light/dark themes.
 */
function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme');
  var next = (current === 'dark') ? 'light' : 'dark';

  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('authgate-theme', next);
  updateThemeToggleIcon(next);
  reRenderMermaid(next);
}

// Re-initializes Mermaid diagrams with the new theme.
function reRenderMermaid(theme) {
  if (typeof mermaid === 'undefined') return;
  var containers = document.querySelectorAll('.mermaid');
  if (!containers.length) return;

  var isDark = theme === 'dark';
  // startOnLoad: false prevents double-render when combined with mermaid.run()
  mermaid.initialize({ startOnLoad: false, theme: isDark ? 'dark' : 'default' });

  containers.forEach(function(el) {
    var source = el.getAttribute('data-mermaid-source');
    if (!source) return;

    el.removeAttribute('data-processed');
    el.textContent = source;
  });

  var runResult = mermaid.run({ nodes: containers });
  if (runResult && typeof runResult.catch === 'function') {
    runResult.catch(function(err) {
      console.error('Mermaid rendering failed:', err);
    });
  }
}

function updateThemeToggleIcon(theme) {
  var btn = document.getElementById('theme-toggle-btn');
  if (!btn) return;
  var isDark = (theme || document.documentElement.getAttribute('data-theme')) === 'dark';
  btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
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

/**
 * Initialize relative time display for elements with data-timestamp attribute
 */
function initRelativeTime() {
  var elements = document.querySelectorAll('[data-timestamp]');
  elements.forEach(function(el) {
    var ts = el.getAttribute('data-timestamp');
    if (ts) {
      el.textContent = formatRelativeTime(ts);
      el.title = new Date(ts).toLocaleString();
    }
  });
}

/**
 * Initialize copyable value buttons (event delegation)
 */
function initCopyableValues() {
  document.addEventListener('click', function(e) {
    var target = e.target;
    if (!target || typeof target.closest !== 'function') return;

    var btn = target.closest('.copyable-value-btn');
    if (!btn) return;

    var wrapper = btn.closest('.copyable-value');
    var textEl = wrapper && wrapper.querySelector('.copyable-value-text');
    if (!textEl) return;

    var value = textEl.textContent;

    copyToClipboard(value).then(function(success) {
      if (!success) return;

      btn.classList.add('copyable-value-btn--copied');

      if (btn._copyTimer) clearTimeout(btn._copyTimer);

      btn._copyTimer = setTimeout(function() {
        btn.classList.remove('copyable-value-btn--copied');
      }, 1500);
    });
  });
}

/**
 * Initialize search clear buttons
 */
function initSearchClear() {
  document.querySelectorAll('.search-input-wrapper').forEach(function(wrapper) {
    var input = wrapper.querySelector('.search-input');
    if (!input || wrapper.querySelector('.search-clear-btn')) return;

    var clearBtn = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.className = 'search-clear-btn';
    clearBtn.setAttribute('aria-label', 'Clear search');
    clearBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
    clearBtn.style.display = input.value ? 'flex' : 'none';
    wrapper.appendChild(clearBtn);

    input.addEventListener('input', function() {
      clearBtn.style.display = this.value ? 'flex' : 'none';
    });

    clearBtn.addEventListener('click', function() {
      input.value = '';
      clearBtn.style.display = 'none';
      input.focus();
      // Submit form to clear search results
      var form = input.closest('form');
      if (form) form.submit();
    });
  });
}

export {
  formatRelativeTime,
  copyToClipboard,
  showNotification,
  confirmModal,
  toggleDetails,
  toggleTheme,
  initDebounceSearch,
  toggleFilters,
  initCollapsibleFilters,
  initRelativeTime,
  initSearchClear,
  initCopyableValues
};

/**
 * Initialization
 */
document.addEventListener('DOMContentLoaded', function() {
  // Theme toggle icon
  updateThemeToggleIcon();

  // Debounced search
  initDebounceSearch();

  // Collapsible filters
  initCollapsibleFilters();

  // Relative time display
  initRelativeTime();

  // Search clear buttons
  initSearchClear();

  // Copyable value buttons
  initCopyableValues();

  // Keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      var navbarMenu = document.getElementById('navbarMenu');
      if (navbarMenu && navbarMenu.classList.contains('active')) {
        navbarMenu.classList.remove('active');
      }
    }
  });

  // Prevent double-submit: add loading state to submit buttons.
  // Skip forms/buttons with data-confirm-* (handled by the confirm modal below).
  document.addEventListener('submit', function(e) {
    var form = e.target;
    var btn = e.submitter || form.querySelector('button[type="submit"], input[type="submit"]');
    if (!btn || btn.classList.contains('btn-loading')) return;
    var hasConfirm = (btn.hasAttribute('data-confirm-title') || form.hasAttribute('data-confirm-title'));
    if (hasConfirm) return;
    btn.classList.add('btn-loading');
    setTimeout(function() { btn.classList.remove('btn-loading'); }, 5000);
  });

  // Delegated handler for data-confirm-* attributes
  document.addEventListener('submit', function(e) {
    var target = e.target;
    var submitter = e.submitter;
    var el = null;

    if (submitter && submitter.hasAttribute('data-confirm-title')) {
      el = submitter;
    } else if (target.hasAttribute && target.hasAttribute('data-confirm-title')) {
      el = target;
    }

    if (!el) return;

    e.preventDefault();
    var savedTitle = el.getAttribute('data-confirm-title');
    var confirmMessage = el.getAttribute('data-confirm-message') || 'Are you sure?';
    var confirmStyle = el.getAttribute('data-confirm-style') || 'danger';
    var confirmLabel = el.getAttribute('data-confirm-label') || 'Confirm';

    // Temporarily remove to prevent re-trigger on programmatic submit
    el.removeAttribute('data-confirm-title');

    confirmModal({
      title: savedTitle,
      message: confirmMessage,
      style: confirmStyle,
      confirmText: confirmLabel
    }).then(function(confirmed) {
      if (confirmed) {
        if (submitter) {
          submitter.click();
        } else {
          target.submit();
        }
      }
      // Restore the attribute so it works on subsequent attempts
      el.setAttribute('data-confirm-title', savedTitle);
    });
  });
});
