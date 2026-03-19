import { toggleMenu, toggleDropdown } from './navbar.js';
import { copySecret, toggleDescription, confirmDelete, confirmRegenerateSecret } from './admin.js';
import {
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
} from './utils.js';
import './code-formatter.js';

// Expose functions globally so HTML onclick attributes can access them
window.toggleMenu = toggleMenu;
window.toggleDropdown = toggleDropdown;
window.copySecret = copySecret;
window.toggleDescription = toggleDescription;
window.confirmDelete = confirmDelete;
window.confirmRegenerateSecret = confirmRegenerateSecret;
window.formatRelativeTime = formatRelativeTime;
window.copyToClipboard = copyToClipboard;
window.showNotification = showNotification;
window.confirmAction = confirmAction;
window.confirmModal = confirmModal;
window.toggleDetails = toggleDetails;
window.toggleTheme = toggleTheme;
window.toggleFilters = toggleFilters;
