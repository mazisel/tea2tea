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
});
