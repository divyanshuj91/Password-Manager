// Content Script for Vaultme Obsidian Extension

let activeDropdown = null;
let currentFocusedInput = null;

// Helper to set element value and trigger native events
function setElementValue(element, value) {
  if (!element) return;
  element.focus();
  element.value = value;
  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
  element.blur();
}

// Generate secure password
function generateSecurePassword() {
  const length = 16;
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const all = uppercase + lowercase + numbers + symbols;

  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);

  let password = '';
  // Guarantee one of each character type
  password += uppercase[array[0] % uppercase.length];
  password += lowercase[array[1] % lowercase.length];
  password += numbers[array[2] % numbers.length];
  password += symbols[array[3] % symbols.length];

  for (let i = 4; i < length; i++) {
    password += all[array[i] % all.length];
  }

  // Quick shuffle
  return password.split('').sort(() => 0.5 - Math.random()).join('');
}

// Guess if signup page based on multiple password inputs or URL path
function isSignupPage() {
  const path = window.location.pathname.toLowerCase();
  if (path.includes('signup') || path.includes('register') || path.includes('join') || path.includes('create')) {
    return true;
  }
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  // Usually signup forms have 2 password fields (new password + confirm password)
  return passwordInputs.length >= 2;
}

// Find related fields in same form or vicinity
function getFormFields(passInput) {
  const form = passInput.form;
  let userInput = null;
  const allPasswordInputs = [];

  if (form) {
    const inputs = Array.from(form.querySelectorAll('input'));
    inputs.forEach(inp => {
      if (inp.type === 'password') {
        allPasswordInputs.push(inp);
      } else if (!userInput && (inp.type === 'text' || inp.type === 'email' || inp.type === 'tel')) {
        userInput = inp;
      }
    });
  } else {
    // Fallback searching preceding elements
    const allInputs = Array.from(document.querySelectorAll('input'));
    const idx = allInputs.indexOf(passInput);
    
    // Look for passwords
    allInputs.forEach(inp => {
      if (inp.type === 'password') allPasswordInputs.push(inp);
    });

    for (let i = idx - 1; i >= Math.max(0, idx - 3); i--) {
      const inp = allInputs[i];
      if (inp.type === 'text' || inp.type === 'email' || inp.type === 'tel') {
        userInput = inp;
        break;
      }
    }
  }

  return {
    userInput,
    passwordInputs: allPasswordInputs.length > 0 ? allPasswordInputs : [passInput]
  };
}

// Hide active dropdown
function hideDropdown() {
  if (activeDropdown) {
    activeDropdown.remove();
    activeDropdown = null;
  }
  currentFocusedInput = null;
}

// Create Obsidian Style Suggestion Dropdown
function createDropdownContainer(targetInput) {
  hideDropdown();
  currentFocusedInput = targetInput;

  const rect = targetInput.getBoundingClientRect();
  const dropdown = document.createElement('div');
  dropdown.id = 'vaultme-obsidian-dropdown';
  
  // Apply monochromatic obsidian styles directly
  Object.assign(dropdown.style, {
    position: 'absolute',
    left: `${rect.left + window.scrollX}px`,
    top: `${rect.bottom + window.scrollY + 4}px`,
    width: `${rect.width}px`,
    backgroundColor: '#0d0d0d',
    border: '1px solid #444748',
    borderRadius: '4px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
    zIndex: '2147483647',
    overflow: 'hidden',
    fontFamily: "'Inter', system-ui, sans-serif",
    fontSize: '13px',
    color: '#ffffff',
    maxHeight: '200px',
    overflowY: 'auto'
  });

  document.body.appendChild(dropdown);
  activeDropdown = dropdown;
  return dropdown;
}

// Display matching username login suggestions
function showLoginSuggestions(targetInput, matches) {
  const dropdown = createDropdownContainer(targetInput);
  
  // Header label
  const header = document.createElement('div');
  header.textContent = 'VAULTME LOGINS';
  Object.assign(header.style, {
    fontSize: '9px',
    fontWeight: '700',
    letterSpacing: '0.08em',
    color: '#8e9192',
    padding: '8px 12px 4px 12px',
    borderBottom: '1px solid #1c1b1b'
  });
  dropdown.appendChild(header);

  matches.forEach(item => {
    const row = document.createElement('div');
    row.textContent = item.username;
    Object.assign(row.style, {
      padding: '10px 12px',
      cursor: 'pointer',
      transition: 'background-color 0.2s',
      fontFamily: 'monospace',
      borderBottom: '1px solid #131313'
    });

    row.addEventListener('mouseover', () => {
      row.style.backgroundColor = '#1c1b1b';
    });
    row.addEventListener('mouseout', () => {
      row.style.backgroundColor = 'transparent';
    });

    // Use mousedown to prevent focus/blur issue
    row.addEventListener('mousedown', (e) => {
      e.preventDefault(); // Prevents input from losing focus immediately
      chrome.runtime.sendMessage({ action: 'get_autofill_data', id: item.id }, (res) => {
        if (res && res.success) {
          const { userInput, passwordInputs } = getFormFields(targetInput);
          if (userInput) setElementValue(userInput, res.username);
          passwordInputs.forEach(pass => setElementValue(pass, res.password));
        }
        hideDropdown();
      });
    });

    dropdown.appendChild(row);
  });
}

// Display Generator Suggestion on Signup page
function showGeneratorSuggestion(passwordInput) {
  const dropdown = createDropdownContainer(passwordInput);

  const row = document.createElement('div');
  row.innerHTML = '✨ <strong style="color:#ffffff;">Generate secure password</strong> <span style="color:#8e9192; font-size:11px;">(Vaultme)</span>';
  Object.assign(row.style, {
    padding: '12px',
    cursor: 'pointer',
    transition: 'background-color 0.2s'
  });

  row.addEventListener('mouseover', () => {
    row.style.backgroundColor = '#1c1b1b';
  });
  row.addEventListener('mouseout', () => {
    row.style.backgroundColor = 'transparent';
  });

  row.addEventListener('mousedown', (e) => {
    e.preventDefault();
    const newPassword = generateSecurePassword();
    const { userInput, passwordInputs } = getFormFields(passwordInput);
    
    // Autofill all password/confirm password fields
    passwordInputs.forEach(pass => setElementValue(pass, newPassword));
    hideDropdown();

    // Show a small Obsidian confirmation toast to prompt saving
    showSaveNotification(userInput ? userInput.value : '', newPassword);
  });

  dropdown.appendChild(row);
}

// Show a floating Obsidian badge notifying that password can be saved
function showSaveNotification(username, password) {
  const existing = document.getElementById('vaultme-save-notification');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'vaultme-save-notification';
  
  Object.assign(toast.style, {
    position: 'fixed',
    bottom: '20px',
    right: '20px',
    backgroundColor: '#0d0d0d',
    border: '1px solid #8e9192',
    color: '#ffffff',
    padding: '12px 16px',
    borderRadius: '4px',
    boxShadow: '0 4px 16px rgba(0,0,0,0.6)',
    zIndex: '2147483647',
    fontFamily: "'Inter', sans-serif",
    fontSize: '12px',
    display: 'flex',
    alignItems: 'center',
    gap: '12px'
  });

  const label = document.createElement('span');
  label.innerHTML = '🔒 Password generated. <strong>Save to Vaultme?</strong>';
  toast.appendChild(label);

  const saveBtn = document.createElement('button');
  saveBtn.textContent = 'SAVE';
  Object.assign(saveBtn.style, {
    backgroundColor: '#ffffff',
    color: '#000000',
    border: 'none',
    padding: '4px 10px',
    fontSize: '11px',
    fontWeight: '700',
    cursor: 'pointer',
    borderRadius: '2px'
  });

  saveBtn.addEventListener('click', () => {
    // Send to background as pending
    chrome.runtime.sendMessage({
      action: 'set_pending_credential',
      url: window.location.origin,
      username: username || '',
      password: password
    }, (res) => {
      saveBtn.disabled = true;
      saveBtn.textContent = 'SAVED';
      saveBtn.style.backgroundColor = '#444748';
      saveBtn.style.color = '#8e9192';
      label.textContent = 'Open Vaultme extension to complete saving!';
      setTimeout(() => toast.remove(), 4000);
    });
  });

  const closeBtn = document.createElement('button');
  closeBtn.textContent = '✕';
  Object.assign(closeBtn.style, {
    background: 'none',
    border: 'none',
    color: '#8e9192',
    cursor: 'pointer',
    fontSize: '12px'
  });
  closeBtn.addEventListener('click', () => toast.remove());

  toast.appendChild(saveBtn);
  toast.appendChild(closeBtn);
  document.body.appendChild(toast);
}

// ---------------- INPUT EVENT LISTENERS ----------------

function handleFocus(e) {
  const input = e.target;
  if (input.tagName !== 'INPUT') return;

  const type = input.type || 'text';
  const name = input.name || '';
  const id = input.id || '';

  // Detect signup vs login context on focus of password input
  if (type === 'password') {
    if (isSignupPage()) {
      showGeneratorSuggestion(input);
    } else {
      // Query matching logins from background
      const domain = window.location.href;
      chrome.runtime.sendMessage({ action: 'get_matching_usernames', domain }, (response) => {
        if (response && response.success && response.matches.length > 0) {
          showLoginSuggestions(input, response.matches);
        }
      });
    }
  } else if (type === 'text' || type === 'email') {
    // Also suggest when focused on username input if matching logins exist
    const domain = window.location.href;
    chrome.runtime.sendMessage({ action: 'get_matching_usernames', domain }, (response) => {
      if (response && response.success && response.matches.length > 0) {
        showLoginSuggestions(input, response.matches);
      }
    });
  }
}

// Monitor document focus events globally (using capture phase to detect focus on any element)
document.addEventListener('focus', handleFocus, true);

// Close dropdown on click outside
document.addEventListener('mousedown', (e) => {
  if (activeDropdown && !activeDropdown.contains(e.target) && e.target !== currentFocusedInput) {
    hideDropdown();
  }
});

// Re-position dropdown on window resize or scroll
window.addEventListener('resize', hideDropdown);
window.addEventListener('scroll', hideDropdown);

// Listen for autofill messages from extension popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const originalSendResponse = sendResponse;
  sendResponse = (response) => {
    if (typeof originalSendResponse === 'function') {
      try {
        originalSendResponse(response);
      } catch (e) {
        console.warn("sendResponse failed in content script:", e);
      }
    }
  };

  if (request.action === 'fill_inputs') {
    const { username, password } = request;
    
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
    if (passwordInputs.length === 0) {
      sendResponse({ success: false, error: 'No password fields found on this page.' });
      return;
    }

    let filled = false;
    for (const passInput of passwordInputs) {
      const { userInput, passwordInputs: formPassInputs } = getFormFields(passInput);
      
      // Fill the passwords
      formPassInputs.forEach(pass => setElementValue(pass, password));
      
      // Fill the username
      if (userInput) {
        setElementValue(userInput, username);
      }
      filled = true;
    }

    sendResponse({ success: filled });
  }
  return true;
});
