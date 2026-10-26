/**
 * Bank Nusantara - ATM Dispute, Fraud & e-KYC Customer Vault
 * Frontend Application Script
 *
 * Implements Mandatory Modern Web Guidance Patterns:
 * 1. autofill-sign-in-form: Proper forms, show password toggles, unblocked paste.
 * 2. validate-input-after-interaction: UserInvalidFallback WeakMap, syncAria for aria-invalid.
 * 3. responsive-table: Interactive responsive tables with @container cards.
 * 4. light-dismiss-a-dialog: closedby="any" with modal getBoundingClientRect() fallback.
 */

'use strict';

// ============================================================================
// 1. MANDATORY MODERN WEB GUIDANCE: UserInvalidFallback & syncAria
// ============================================================================

const UserInvalidFallback = (() => {
  const dirtyState = new WeakMap();

  const updateState = (input) => {
    if (!input || typeof input.checkValidity !== 'function') return;
    const isValid = input.checkValidity();

    // Update both visual class and ARIA state
    input.classList.toggle('user-invalid-fallback', !isValid);
    input.classList.toggle('user-valid-fallback', isValid);

    if (!isValid) {
      input.setAttribute('aria-invalid', 'true');
    } else {
      input.removeAttribute('aria-invalid');
    }
  };

  const handleEvent = (event) => {
    const input = event.target;
    if (!input) return;

    if (event.type === 'reset') {
      const controls = input.elements || [];
      for (const control of controls) {
        dirtyState.delete(control);
        control.classList.remove('user-invalid-fallback');
        control.classList.remove('user-valid-fallback');
        control.removeAttribute('aria-invalid');
      }
      return;
    }

    if (typeof input.checkValidity !== 'function') return;

    if (event.type === 'input' || event.type === 'change') {
      const state = dirtyState.get(input) || { hasInteracted: false, hasBlurred: false };
      state.hasInteracted = true;
      dirtyState.set(input, state);
      if (state.hasBlurred) {
        updateState(input);
      }
    } else if (event.type === 'blur') {
      const state = dirtyState.get(input) || { hasInteracted: false, hasBlurred: false };
      state.hasBlurred = true;
      dirtyState.set(input, state);
      if (state.hasInteracted) {
        updateState(input);
      }
    }
  };

  const init = (root = document) => {
    // If browser natively supports :user-invalid, fallback class is not strictly needed,
    // but we still initialize event listeners to sync aria-invalid.
    root.addEventListener('blur', handleEvent, true); // Capture phase
    root.addEventListener('input', handleEvent);
    root.addEventListener('change', handleEvent);
    root.addEventListener('reset', handleEvent, true);
  };

  return { init };
})();

// Keep aria-invalid in sync with native :user-invalid state
const syncAria = (el) => {
  if (el && typeof el.matches === 'function') {
    try {
      el.setAttribute('aria-invalid', el.matches(':user-invalid') ? 'true' : 'false');
    } catch (_) {}
  }
};

document.addEventListener('blur', (e) => syncAria(e.target), true);
document.addEventListener('input', (e) => {
  if (e.target && e.target.hasAttribute && e.target.hasAttribute('aria-invalid')) {
    syncAria(e.target);
  }
});

// ============================================================================
// 2. MANDATORY MODERN WEB GUIDANCE: light-dismiss-a-dialog Fallback
// ============================================================================

function setupDialogLightDismiss(dialog) {
  if (!dialog) return;

  // Fallback for browsers without native closedby support
  if (!('closedBy' in HTMLDialogElement.prototype)) {
    dialog.addEventListener('click', (event) => {
      // 1. When clicking the backdrop, the event target is the dialog element itself.
      if (event.target !== dialog) return;

      // 2. Check if the click coordinates fall within the dialog's content box.
      const rect = dialog.getBoundingClientRect();
      const isDialogContent = (
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width
      );

      if (isDialogContent) return;

      // 3. Click was outside content area on backdrop -> close dialog
      dialog.close();
    });
  }
}

// ============================================================================
// 3. APPLICATION STATE & API HELPERS
// ============================================================================

const AppState = {
  currentUser: null,
  activeCipher: 'aes-256-cbc',
  cases: [],
  selectedCaseId: null,
  selectedCaseData: null,
  latestBenchmark: null
};

// Resilient API Fetch Helper (Handles /api/auth/* and /api/* interchangeable paths)
async function apiFetch(url, options = {}) {
  const defaultHeaders = {
    'Accept': 'application/json'
  };
  if (options.body && !(options.body instanceof FormData)) {
    defaultHeaders['Content-Type'] = 'application/json';
  }
  options.headers = { ...defaultHeaders, ...options.headers };

  try {
    let res = await fetch(url, options);

    // If 404 on /api/auth/*, try /api/*
    if (res.status === 404 && url.startsWith('/api/auth/')) {
      const altUrl = url.replace('/api/auth/', '/api/');
      res = await fetch(altUrl, options);
    } else if (res.status === 404 && url.startsWith('/api/') && !url.startsWith('/api/auth/')) {
      const altUrl = url.replace('/api/', '/api/auth/');
      const altRes = await fetch(altUrl, options);
      if (altRes.status !== 404) res = altRes;
    }

    return res;
  } catch (err) {
    console.error('API Fetch Network Error:', err);
    throw err;
  }
}

// Helper to format currency
function formatIDR(amount) {
  if (typeof amount === 'string' && amount.trim().length > 0) {
    const digitsOnly = amount.replace(/[^0-9]/g, '');
    if (digitsOnly.length > 0) {
      return 'IDR ' + Number(digitsOnly).toLocaleString('id-ID');
    }
    return amount;
  }
  const num = Number(amount) || 2500000;
  return 'IDR ' + num.toLocaleString('id-ID');
}

// ============================================================================
// 4. AUTHENTICATION & SESSION MANAGEMENT
// ============================================================================

async function checkSession() {
  try {
    const res = await apiFetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      if (data.authenticated || data.user) {
        AppState.currentUser = data.user || data;
        renderAuthenticatedState();
        return true;
      }
    }
  } catch (err) {
    console.warn('Session check note:', err);
  }
  renderLoggedOutState();
  return false;
}

function renderAuthenticatedState() {
  document.getElementById('authView').classList.add('hidden');
  document.getElementById('authenticatedPortal').classList.remove('hidden');
  document.getElementById('userHeaderProfile').classList.remove('hidden');

  const username = AppState.currentUser ? (AppState.currentUser.username || AppState.currentUser.full_name || 'Customer') : 'Customer';
  document.getElementById('headerUsername').textContent = username;
}

function renderLoggedOutState() {
  document.getElementById('authView').classList.remove('hidden');
  document.getElementById('authenticatedPortal').classList.add('hidden');
  document.getElementById('userHeaderProfile').classList.add('hidden');
}

// Sign In Handler
async function handleSignIn(e) {
  e.preventDefault();
  const form = e.target;
  const alertBox = document.getElementById('signInAlert');
  alertBox.classList.add('hidden');
  alertBox.textContent = '';

  if (!form.checkValidity()) {
    form.querySelectorAll('input').forEach(input => {
      input.dispatchEvent(new Event('blur'));
    });
    return;
  }

  const username = form.username.value.trim();
  const password = form.password.value;

  try {
    const res = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();
    if (res.ok && (data.success || data.user || data.authenticated)) {
      AppState.currentUser = data.user || { username };
      renderAuthenticatedState();
    } else {
      alertBox.textContent = data.message || data.error || 'Authentication failed. Please check your credentials.';
      alertBox.classList.remove('hidden');
    }
  } catch (err) {
    alertBox.textContent = 'Network or server error during sign-in. Please try again.';
    alertBox.classList.remove('hidden');
  }
}

// Registration Handler
async function handleRegister(e) {
  e.preventDefault();
  const form = e.target;
  const alertBox = document.getElementById('registerAlert');
  alertBox.classList.add('hidden');
  alertBox.textContent = '';

  if (!form.checkValidity()) {
    form.querySelectorAll('input').forEach(input => {
      input.dispatchEvent(new Event('blur'));
    });
    return;
  }

  const full_name = form.full_name.value.trim();
  const username = form.username.value.trim();
  const password = form.password.value;

  try {
    const res = await apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ full_name, username, password })
    });

    const data = await res.json();
    if (res.ok && (data.success || data.user)) {
      AppState.currentUser = data.user || { username, full_name };
      renderAuthenticatedState();
    } else {
      alertBox.textContent = data.message || data.error || 'Registration failed.';
      alertBox.classList.remove('hidden');
    }
  } catch (err) {
    alertBox.textContent = 'Server error during vault creation.';
    alertBox.classList.remove('hidden');
  }
}

// Sign Out Handler
async function handleSignOut() {
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' });
  } catch (_) {}
  AppState.currentUser = null;
  AppState.cases = [];
  AppState.selectedCaseId = null;
  AppState.selectedCaseData = null;
  renderLoggedOutState();
}

// 1-Click Quick Demo Login Helper
async function handleQuickDemoLogin() {
  const demoUsername = 'demo_customer';
  const demoPassword = 'BankDemo2026!';
  const demoFullName = 'Budi Santoso';

  // 1. Try login first
  try {
    let res = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: demoUsername, password: demoPassword })
    });

    if (!res.ok) {
      // 2. Register demo customer if not exists
      await apiFetch('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          username: demoUsername,
          password: demoPassword,
          full_name: demoFullName
        })
      });

      // 3. Login again
      res = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: demoUsername, password: demoPassword })
      });
    }

    const data = await res.json();
    AppState.currentUser = data.user || { username: demoUsername, full_name: demoFullName };
    renderAuthenticatedState();
  } catch (err) {
    console.error('Quick Demo Login Error:', err);
    alert('Could not complete Quick Demo Login. Ensure the backend server is running.');
  }
}

// ============================================================================
// 9. TAB NAVIGATION & UI BINDINGS
// ============================================================================

function switchTab(btnId, panelId) {
  // Navigation tabs
  document.querySelectorAll('.portal-tab-btn').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  document.querySelectorAll('.portal-tab-panel').forEach(p => p.classList.add('hidden'));

  const btn = document.getElementById(btnId);
  const panel = document.getElementById(panelId);
  if (btn && panel) {
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    panel.classList.remove('hidden');
  }
}

function setupAuthTabs() {
  const tabSignIn = document.getElementById('tabSignInBtn');
  const tabReg = document.getElementById('tabRegisterBtn');
  const panelSignIn = document.getElementById('signInTabPanel');
  const panelReg = document.getElementById('registerTabPanel');

  if (tabSignIn && tabReg && panelSignIn && panelReg) {
    tabSignIn.addEventListener('click', () => {
      tabSignIn.classList.add('active');
      tabSignIn.setAttribute('aria-selected', 'true');
      tabReg.classList.remove('active');
      tabReg.setAttribute('aria-selected', 'false');
      panelSignIn.classList.remove('hidden');
      panelReg.classList.add('hidden');
    });

    tabReg.addEventListener('click', () => {
      tabReg.classList.add('active');
      tabReg.setAttribute('aria-selected', 'true');
      tabSignIn.classList.remove('active');
      tabSignIn.setAttribute('aria-selected', 'false');
      panelReg.classList.remove('hidden');
      panelSignIn.classList.add('hidden');
    });
  }
}

function setupPasswordToggles() {
  document.querySelectorAll('.btn-toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input) return;

      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🔒';
        btn.setAttribute('aria-label', 'Hide password');
      } else {
        input.type = 'password';
        btn.textContent = '👁️';
        btn.setAttribute('aria-label', 'Show password');
      }
    });
  });
}

// ============================================================================
// 10. INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // 1. Initialize modern-web-guidance input validation fallback & ARIA sync
  UserInvalidFallback.init(document);

  // 2. Setup modal dialog light-dismiss fallbacks
  setupDialogLightDismiss(document.getElementById('vaultInspectorDialog'));
  setupDialogLightDismiss(document.getElementById('tamperResultDialog'));

  // 3. UI interactions
  setupAuthTabs();
  setupPasswordToggles();

  // 4. Portal Tab buttons
  const tabCasesBtn = document.getElementById('tabCasesBtn');
  const tabNewCaseBtn = document.getElementById('tabNewCaseBtn');
  const tabBenchBtn = document.getElementById('tabBenchBtn');

  if (tabCasesBtn) tabCasesBtn.addEventListener('click', () => switchTab('tabCasesBtn', 'tabCasesPanel'));
  if (tabNewCaseBtn) tabNewCaseBtn.addEventListener('click', () => switchTab('tabNewCaseBtn', 'tabNewCasePanel'));
  if (tabBenchBtn) tabBenchBtn.addEventListener('click', () => switchTab('tabBenchBtn', 'tabBenchPanel'));

  // 5. Auth form submissions
  const signInForm = document.getElementById('signInForm');
  const registerForm = document.getElementById('registerForm');
  const btnSignOut = document.getElementById('btnSignOut');
  const btnQuickDemoLogin = document.getElementById('btnQuickDemoLogin');

  if (signInForm) signInForm.addEventListener('submit', handleSignIn);
  if (registerForm) registerForm.addEventListener('submit', handleRegister);
  if (btnSignOut) btnSignOut.addEventListener('click', handleSignOut);
  if (btnQuickDemoLogin) btnQuickDemoLogin.addEventListener('click', handleQuickDemoLogin);

  // 6. Check initial session
  await checkSession();
});
