const COOKIE_PREF_KEY = 'tea2tea_cookie_prefs_v1';
const COOKIE_MAX_AGE_DAYS = 365;

function readCookie(name) {
  if (typeof document === 'undefined') return null;
  const cookies = document.cookie ? document.cookie.split('; ') : [];
  for (let i = 0; i < cookies.length; i += 1) {
    const parts = cookies[i].split('=');
    const key = parts.shift();
    if (key === name) {
      return decodeURIComponent(parts.join('='));
    }
  }
  return null;
}

function writeCookie(name, value, days) {
  const maxAgeSeconds = Math.max(days * 24 * 60 * 60, 0);
  const secure = window.location.protocol === 'https:' ? '; Secure' : '';
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAgeSeconds}; SameSite=Lax${secure}`;
}

function buildCookiePrefs(overrides = {}) {
  return {
    necessary: true,
    analytics: false,
    marketing: false,
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

function getCookiePrefs() {
  const raw = readCookie(COOKIE_PREF_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    return {
      necessary: true,
      analytics: Boolean(parsed.analytics),
      marketing: Boolean(parsed.marketing),
      updatedAt: parsed.updatedAt || null,
    };
  } catch (error) {
    return null;
  }
}

function storeCookiePrefs(prefs) {
  const payload = buildCookiePrefs(prefs);
  writeCookie(COOKIE_PREF_KEY, JSON.stringify(payload), COOKIE_MAX_AGE_DAYS);
  document.dispatchEvent(new CustomEvent('cookie-preferences-saved', { detail: payload }));
  return payload;
}

function initCookieConsent() {
  const banner = document.querySelector('[data-cookie-banner]');
  const modal = document.querySelector('[data-cookie-modal]');
  if (!banner || !modal) return;

  const form = modal.querySelector('[data-cookie-form]');
  const analyticsInput = form?.querySelector('input[name="analytics"]');
  const marketingInput = form?.querySelector('input[name="marketing"]');
  if (!form || !analyticsInput || !marketingInput) return;

  const openButtons = document.querySelectorAll('[data-cookie-open]');
  const acceptButtons = document.querySelectorAll('[data-cookie-accept]');
  const declineButtons = document.querySelectorAll('[data-cookie-decline]');
  const closeButtons = modal.querySelectorAll('[data-cookie-close]');
  const saveButton = form.querySelector('[data-cookie-save]');
  const acceptModalButton = modal.querySelector('[data-cookie-accept-modal]');

  const body = document.body;
  const currentPrefs = getCookiePrefs();

  const showBanner = () => {
    banner.removeAttribute('hidden');
  };

  const hideBanner = () => {
    banner.setAttribute('hidden', '');
  };

  const openModal = () => {
    const prefs = getCookiePrefs() || buildCookiePrefs();
    analyticsInput.checked = Boolean(prefs.analytics);
    marketingInput.checked = Boolean(prefs.marketing);
    modal.removeAttribute('hidden');
    if (body) {
      body.classList.add('cookie-modal-open');
    }
  };

  const closeModal = () => {
    modal.setAttribute('hidden', '');
    if (body) {
      body.classList.remove('cookie-modal-open');
    }
  };

  const applyChoice = (prefs, { hide = true } = {}) => {
    storeCookiePrefs(prefs);
    if (hide) {
      hideBanner();
      closeModal();
    }
  };

  const handleSave = (event) => {
    event.preventDefault();
    applyChoice(
      {
        analytics: analyticsInput.checked,
        marketing: marketingInput.checked,
      },
      { hide: true },
    );
  };

  const handleAcceptAll = () => {
    applyChoice({ analytics: true, marketing: true }, { hide: true });
  };

  const handleDecline = () => {
    applyChoice({ analytics: false, marketing: false }, { hide: true });
  };

  const handleKeydown = (event) => {
    if (event.key === 'Escape' && !modal.hasAttribute('hidden')) {
      event.preventDefault();
      closeModal();
    }
  };

  if (!currentPrefs) {
    showBanner();
  }

  openButtons.forEach((button) => {
    button.addEventListener('click', () => {
      hideBanner();
      openModal();
    });
  });

  acceptButtons.forEach((button) => {
    button.addEventListener('click', handleAcceptAll);
  });

  declineButtons.forEach((button) => {
    button.addEventListener('click', handleDecline);
  });

  if (saveButton) {
    form.addEventListener('submit', handleSave);
  }

  if (acceptModalButton) {
    acceptModalButton.addEventListener('click', handleAcceptAll);
  }

  closeButtons.forEach((button) => {
    button.addEventListener('click', () => {
      closeModal();
      if (!getCookiePrefs()) {
        showBanner();
      }
    });
  });

  modal.addEventListener('click', (event) => {
    if (event.target === modal) {
      closeModal();
      if (!getCookiePrefs()) {
        showBanner();
      }
    }
  });

  document.addEventListener('keydown', handleKeydown);
}

function prefersReducedMotion() {
  return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function getHeaderOffset() {
  const header = document.querySelector('.site-header');
  if (!header) return 0;
  return header.getBoundingClientRect().height + 24;
}

function smoothScrollToHash(hash, options = {}) {
  if (!hash || hash === '#') return false;
  const target = document.querySelector(hash);
  if (!target) return false;

  const offset = getHeaderOffset();
  const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - offset;
  const prefersReduced = prefersReducedMotion();
  const behavior = options.immediate || prefersReduced ? 'auto' : 'smooth';

  window.scrollTo({ top: Math.max(targetPosition, 0), behavior });

  const shouldFocus = Boolean(options.focus) && typeof target.focus === 'function';
  if (shouldFocus) {
    const hadTabindex = target.hasAttribute('tabindex');
    if (!hadTabindex) {
      target.setAttribute('tabindex', '-1');
    }
    target.classList.add('is-temp-focus');
    window.requestAnimationFrame(() => {
      target.focus({ preventScroll: true });
      window.requestAnimationFrame(() => {
        target.classList.remove('is-temp-focus');
        if (!hadTabindex) {
          target.removeAttribute('tabindex');
        }
      });
    });
  }

  return true;
}

function initPageTransitions() {
  const body = document.body;
  if (!body) return;
  const reduceMotion = prefersReducedMotion();

  const alignHashWithOffset = (immediate = false) => {
    if (window.location.hash) {
      window.setTimeout(() => {
        smoothScrollToHash(window.location.hash, { immediate: immediate || reduceMotion, focus: false });
      }, immediate ? 0 : 120);
    }
  };

  window.addEventListener('hashchange', () => {
    smoothScrollToHash(window.location.hash, { immediate: true, focus: false });
  });

  alignHashWithOffset(true);

  if (reduceMotion) return;

  body.classList.remove('is-navigating');

  const transitionDelay = 280;
  const anchorSelector = 'a[href]:not([data-no-transition])';
  const isModifierKey = (event) => event.metaKey || event.ctrlKey || event.shiftKey || event.altKey;
  const disallowedProtocol = /^(mailto:|tel:|javascript:)/i;

  document.addEventListener(
    'click',
    (event) => {
      if (event.defaultPrevented) return;
      if (isModifierKey(event)) return;

      const anchor = event.target.closest(anchorSelector);
      if (!anchor) return;
      if (anchor.target && anchor.target !== '_self') return;
      if (anchor.hasAttribute('download')) return;

      const href = anchor.getAttribute('href');
      if (!href || disallowedProtocol.test(href)) return;

      if (href.startsWith('#')) {
        event.preventDefault();
        const shouldFocus = event.detail === 0;
        const didScroll = smoothScrollToHash(href, { focus: shouldFocus });
        if (didScroll && window.location.hash !== href) {
          history.pushState({}, '', href);
        }
        return;
      }

      let url;
      try {
        url = new URL(anchor.href, window.location.href);
      } catch (error) {
        return;
      }

      if (url.origin !== window.location.origin) return;

      const isSamePath = url.pathname === window.location.pathname && url.search === window.location.search;
      if (isSamePath) {
        if (url.hash) {
          event.preventDefault();
          const shouldFocus = event.detail === 0;
          const didScroll = smoothScrollToHash(url.hash, { focus: shouldFocus });
          if (didScroll && window.location.hash !== url.hash) {
            history.pushState({}, '', url.hash);
          }
        }
        return;
      }

      if (body.classList.contains('is-navigating')) return;

      event.preventDefault();
      body.classList.add('is-navigating');

      window.setTimeout(() => {
        window.location.href = anchor.href;
      }, transitionDelay);
    },
    { capture: true },
  );

  document.addEventListener(
    'submit',
    (event) => {
      const form = event.target;
      if (!form || !(form instanceof HTMLFormElement)) return;
      if (form.hasAttribute('data-no-transition')) return;
      if (form.target && form.target !== '_self') return;
      if (body.classList.contains('is-navigating')) return;

      body.classList.add('is-navigating');
    },
    { capture: true },
  );

  window.addEventListener('pageshow', () => {
    body.classList.remove('is-navigating');
  });
}


document.addEventListener('DOMContentLoaded', () => {
  const menuToggle = document.querySelector('.menu-toggle');
  const nav = document.querySelector('[data-nav]');

  if (menuToggle && nav) {
    menuToggle.addEventListener('click', () => {
      const expanded = menuToggle.getAttribute('aria-expanded') === 'true';
      menuToggle.setAttribute('aria-expanded', String(!expanded));
      menuToggle.classList.toggle('is-open');
      nav.classList.toggle('is-open');
    });
  }

  const adminToggle = document.querySelector('[data-admin-nav-toggle]');
  const adminMenu = document.querySelector('[data-admin-nav]');

  if (adminToggle && adminMenu) {
    const closeMenu = () => {
      adminToggle.classList.remove('is-open');
      adminToggle.setAttribute('aria-expanded', 'false');
      adminMenu.classList.remove('is-open');
    };

    adminToggle.addEventListener('click', (event) => {
      event.stopPropagation();
      const expanded = adminToggle.getAttribute('aria-expanded') === 'true';
      adminToggle.setAttribute('aria-expanded', String(!expanded));
      adminToggle.classList.toggle('is-open');
      adminMenu.classList.toggle('is-open');
    });

    document.addEventListener('click', (event) => {
      if (!adminMenu.contains(event.target) && !adminToggle.contains(event.target)) {
        closeMenu();
      }
    });
  }

  initPageTransitions();
  initCookieConsent();
});
