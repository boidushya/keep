(() => {
  const MASK = '••••••••';
  let revealed = false;

  const setRevealed = (el, on) => {
    el.textContent = on ? el.dataset.value : MASK;
    el.dataset.revealed = on ? '1' : '';
  };

  const flashCopyIcon = (btn) => {
    const i = btn.querySelector('i.ti');
    if (!i) {
      const orig = btn.textContent;
      btn.textContent = 'copied';
      setTimeout(() => (btn.textContent = orig), 1100);
      return;
    }
    const orig = i.className;
    i.className = 'ti ti-copy-check';
    setTimeout(() => { i.className = orig; }, 1100);
  };

  const init = () => {
    document.querySelectorAll('[data-secret]').forEach(el => {
      el.addEventListener('click', () => setRevealed(el, !el.dataset.revealed));
    });

    const toggle = document.querySelector('[data-reveal-all]');
    if (toggle) {
      const icon = toggle.querySelector('i.ti');
      const label = toggle.querySelector('[data-label]');
      toggle.addEventListener('click', () => {
        revealed = !revealed;
        if (icon) icon.className = revealed ? 'ti ti-eye-off' : 'ti ti-eye';
        if (label) label.textContent = revealed ? 'hide all' : 'reveal all';
        document.querySelectorAll('[data-secret]').forEach(el => setRevealed(el, revealed));
      });
    }

    document.querySelectorAll('[data-copy], [data-copy-target]').forEach(btn => {
      btn.addEventListener('click', async () => {
        let text = btn.dataset.copy;
        if (btn.dataset.copyTarget) {
          const el = document.querySelector(btn.dataset.copyTarget);
          text = el ? el.textContent : '';
        }
        try {
          await navigator.clipboard.writeText(text);
          flashCopyIcon(btn);
        } catch (e) {
          const orig = btn.textContent;
          btn.textContent = 'failed';
          setTimeout(() => (btn.textContent = orig), 1100);
        }
      });
    });

    document.addEventListener('click', (e) => {
      document.querySelectorAll('details[open]').forEach(d => {
        if (!d.contains(e.target)) d.open = false;
      });
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        document.querySelectorAll('details[open]').forEach(d => (d.open = false));
      }
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
