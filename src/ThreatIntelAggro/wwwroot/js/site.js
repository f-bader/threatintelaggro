// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Shared bulk selection behavior for the Inbox and IOC review lists.
(() => {
  function initializeBulkSelection(form) {
    form.__bulkSelectionController?.abort();
    const controller = new AbortController();
    form.__bulkSelectionController = controller;
    const listenerOptions = { signal: controller.signal };
    const selectVisible = form.querySelector('[data-select-visible]');
    const count = form.querySelector('[data-selection-count]');
    const items = [...document.querySelectorAll(`[form="${form.id}"][data-selection-item]`)];
    const groupSelects = [...document.querySelectorAll('[data-group-select-visible]')].map(control => ({
      control,
      items: [...(control.closest('.article-group-card')?.querySelectorAll(`[form="${form.id}"][data-selection-item]`) ?? [])]
    }));
    const actions = [...form.querySelectorAll('[data-selection-action]')];
    const role = form.querySelector('[data-selection-role]');

    const refresh = () => {
      const selectedItems = items.filter(item => item.checked);
      if (count) count.textContent = `${selectedItems.length} selected`;
      if (selectVisible) {
        selectVisible.disabled = items.length === 0;
        selectVisible.checked = items.length > 0 && selectedItems.length === items.length;
        selectVisible.indeterminate = selectedItems.length > 0 && selectedItems.length < items.length;
      }
      groupSelects.forEach(({ control, items: groupItems }) => {
        const selectedInGroup = groupItems.filter(item => item.checked).length;
        control.disabled = groupItems.length === 0;
        control.checked = groupItems.length > 0 && selectedInGroup === groupItems.length;
        control.indeterminate = selectedInGroup > 0 && selectedInGroup < groupItems.length;
      });
      actions.forEach(button => {
        const allSelectedEligible = selectedItems.length > 0 && selectedItems.every(item => {
          if (button.dataset.selectionAction === 'classify') return item.dataset.actionable === 'false';
          if (button.dataset.selectionAction === 'approve') return item.dataset.actionable === 'true' && item.dataset.approved === 'false';
          return button.dataset.selectionAction === 'dismiss';
        });
        button.disabled = !allSelectedEligible || (button.dataset.selectionAction === 'classify' && role?.value === '');
      });
      form.dispatchEvent(new CustomEvent('bulk-selection-change', { detail: { selectedItems } }));
    };

    selectVisible?.addEventListener('change', () => {
      items.forEach(item => { item.checked = selectVisible.checked; });
      refresh();
    }, listenerOptions);
    groupSelects.forEach(({ control, items: groupItems }) => control.addEventListener('change', () => {
      groupItems.forEach(item => { item.checked = control.checked; });
      refresh();
    }, listenerOptions));
    items.forEach(item => item.addEventListener('change', refresh, listenerOptions));
    role?.addEventListener('change', refresh, listenerOptions);
    refresh();
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-bulk-selection]').forEach(initializeBulkSelection);
  });
  document.addEventListener('inbox-results-updated', () => {
    document.querySelectorAll('[data-bulk-selection]').forEach(initializeBulkSelection);
  });
})();

const reviewUi = {
  preserveState(panel, next, preserveSelection = false) {
    const active = panel.contains(document.activeElement) ? document.activeElement : null;
    const owners = '[data-article-id], [data-group-key], .detection-card, .ioc-row, tr';
    const key = owner => owner?.dataset.articleId ?? owner?.dataset.groupKey ?? owner?.dataset.reviewKey
      ?? (owner?.id || owner?.querySelector('[data-selection-item]')?.value
          || owner?.querySelector('input[name="id"]')?.value);
    const index = new Map([...next.querySelectorAll(owners)].map(owner => [key(owner), owner]));
    for (const details of panel.querySelectorAll('details')) {
      const owner = details.closest(owners);
      const destination = owner && key(owner) && index.get(key(owner));
      const label = details.className;
      const matching = [...(destination?.querySelectorAll?.('details') ?? [])]
        .find(candidate => candidate.className === label);
      if (matching) matching.open = details.open;
    }
    if (preserveSelection) {
      const selected = new Set([...panel.querySelectorAll('[data-selection-item]:checked')].map(input => input.value));
      for (const input of next.querySelectorAll('[data-selection-item]')) input.checked = selected.has(input.value);
    }
    const owner = active?.closest(owners);
    const destination = owner && key(owner) && index.get(key(owner));
    const handler = active?.form && new URL(active.form.action).searchParams.get('handler');
    const nextForm = [...(destination?.querySelectorAll?.('form') ?? [])].find(form =>
      new URL(form.action).searchParams.get('handler') === handler)
      ?? destination?.querySelector?.('[data-read-action]');
    panel.replaceWith(next);
    if (active) {
      const focus = nextForm?.querySelector(active.matches('select') ? 'select' : 'button')
        ?? next.querySelector('h2, .empty-state h3') ?? next;
      if (!focus.matches('button, select')) focus.tabIndex = -1;
      focus.focus({preventScroll: true});
    }
  }
};

// Native forms still handle navigation when scripting is unavailable.
document.addEventListener('submit', async event => {
  const form = event.target.closest('form[data-review-action]');
  if (!form || event.defaultPrevented) return;
  const panel = form.closest('[data-review-panel]');
  if (!panel) return;
  event.preventDefault();
  if (panel.getAttribute('aria-busy') === 'true') return;

  const name = panel.dataset.reviewPanel;
  const button = event.submitter;
  const payload = new FormData(form);
  if (button?.name) payload.set(button.name, button.value);
  const previousLabel = button?.textContent;
  if (button) {
    button.setAttribute('aria-disabled', 'true');
    button.textContent = 'Working…';
  }
  panel.querySelector('[data-review-error]')?.remove();
  document.dispatchEvent(new Event('review-action-starting'));
  panel.setAttribute('aria-busy', 'true');
  try {
    const response = await fetch(form.action, {
      method: 'POST',
      body: payload,
      headers: { 'X-Review-Fragment': name }
    });
    if (!response.ok) throw new Error('Action failed');
    if (form.matches('[data-inline-status]')) {
      const result = await response.json();
      form.closest('.detection-card').querySelector('[data-detection-status]').textContent = result.status;
      return;
    }
    const copy = new DOMParser().parseFromString(await response.text(), 'text/html');
    const next = copy.querySelector(`[data-review-panel="${name}"]`);
    if (!next) throw new Error('Updated results missing');
    reviewUi.preserveState(panel, next, !form.matches('[data-bulk-selection]'));
    const badge = document.querySelector(`[data-workspace-count="${name}"]`);
    if (badge) badge.textContent = next.dataset.reviewCount;
    if (name === 'feeds') {
      for (const count of copy.querySelectorAll('[data-workspace-count]')) {
        const target = document.querySelector(`[data-workspace-count="${count.dataset.workspaceCount}"]`);
        if (target) target.textContent = count.textContent;
      }
    }
    document.dispatchEvent(new Event('inbox-results-updated'));
    pollPanelJobs(next);
  } catch {
    const status = document.createElement('p');
    status.className = 'notice';
    status.dataset.reviewError = '';
    status.setAttribute('role', 'alert');
    status.textContent = 'Could not confirm the action. Refresh the results before trying again.';
    panel.prepend(status);
  } finally {
    if (button) {
      button.removeAttribute('aria-disabled');
      button.textContent = previousLabel;
    }
    panel.removeAttribute('aria-busy');
    document.dispatchEvent(new Event('review-action-completed'));
  }
});

// Share fragment navigation between result views. Exports keep their native submit behavior.
(() => {
  let controller;
  let debounce;
  let queuedFilter;
  const filter = 'form[data-fragment-filter]';
  const update = async (form, submitter, pending) => {
    clearTimeout(debounce);
    controller?.abort();
    const panel = form.closest('[data-filter-panel]');
    const name = panel.dataset.filterPanel;
    const url = pending ?? new URL(form.action);
    if (!pending) url.search = new URLSearchParams(new FormData(form, submitter ?? undefined));
    if (panel.querySelector('[data-review-panel][aria-busy=true]')) {
      queuedFilter = () => update(panel.querySelector(filter), null, url);
      return;
    }
    queuedFilter = undefined;
    const request = new AbortController();
    controller = request;
    panel.setAttribute('aria-busy', 'true');
    try {
      const response = await fetch(url, { headers: { 'X-Review-Fragment': name }, signal: request.signal });
      if (!response.ok) throw new Error();
      const copy = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = copy.querySelector(`[data-filter-panel="${name}"]`);
      if (request.signal.aborted || !panel.isConnected) return;
      if (!next) throw new Error();
      const active = form.contains(document.activeElement) ? document.activeElement : null;
      const focus = active?.name && [...next.querySelectorAll('[name]')].find(control => control.name === active.name
        && (active.type !== 'checkbox' || control.value === active.value));
      const selection = active?.matches('input[type=search], input[type=text], input:not([type])')
        ? [active.selectionStart, active.selectionEnd] : null;
      panel.replaceWith(next);
      focus?.focus({preventScroll: true});
      if (focus && selection?.[0] !== null && selection) focus.setSelectionRange(...selection);
      history.replaceState(history.state, '', url);
      document.dispatchEvent(new Event('inbox-results-updated'));
      document.dispatchEvent(new Event('review-filter-updated'));
    } catch {
      if (!request.signal.aborted) window.location.assign(url);
    } finally {
      if (controller === request) panel.removeAttribute('aria-busy');
    }
  };
  document.addEventListener('submit', event => {
    if (!event.target.matches(filter) || event.submitter?.hasAttribute('formaction')) return;
    event.preventDefault();
    update(event.target, event.submitter);
  });
  document.addEventListener('change', event => {
    const form = event.target.closest(`${filter}[data-filter-auto]`);
    if (form && event.target.matches('select,input[type=checkbox]')) update(form);
  });
  document.addEventListener('input', event => {
    const form = event.target.closest(`${filter}[data-filter-auto]`);
    if (!form || !event.target.matches('input[name=search]')) return;
    clearTimeout(debounce);
    controller?.abort();
    debounce = setTimeout(() => update(form), 400);
  });
  document.addEventListener('review-action-completed', () => queuedFilter?.());
  document.addEventListener('review-action-starting', () => controller?.abort());
})();

// A manual job can outlive the request. Poll only visible jobs that are still active.
function pollPanelJobs(panel) {
  if (panel.dataset.pollingJobs === 'true') return;
  const jobs = [...panel.querySelectorAll('[data-job-state=queued],[data-job-state=running]')];
  if (!jobs.length) return;
  panel.dataset.pollingJobs = 'true';
  const poll = async () => {
    if (!panel.isConnected) return;
    if (panel.getAttribute('aria-busy') === 'true') { setTimeout(poll, 1000); return; }
    try {
      const results = await Promise.all(jobs.map(async job => {
        const response = await fetch('/internal/manual-jobs/' + encodeURIComponent(job.dataset.manualJob));
        if (response.status === 404) return { state: 'failed', message: 'Job status is unavailable.' };
        if (!response.ok) throw new Error();
        return response.json();
      }));
      if (!panel.isConnected) return;
      if (panel.getAttribute('aria-busy') === 'true') { setTimeout(poll, 1000); return; }
      results.forEach((result, index) => {
        jobs[index].textContent = result.message;
        jobs[index].dataset.jobState = result.state;
      });
      if (results.some(result => result.state === 'queued' || result.state === 'running')) {
        setTimeout(poll, 1000);
        return;
      }
      const name = panel.dataset.reviewPanel;
      const response = await fetch(window.location.href, { headers: { 'X-Review-Fragment': name } });
      if (!response.ok) throw new Error();
      const copy = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = copy.querySelector(`[data-review-panel="${name}"]`);
      if (!next || !panel.isConnected || panel.getAttribute('aria-busy') === 'true') return;
      const inboxCount = copy.querySelector('[data-workspace-count=inbox]');
      if (inboxCount) document.querySelector('[data-workspace-count=inbox]').textContent = inboxCount.textContent;
      reviewUi.preserveState(panel, next, true);
      pollPanelJobs(next);
    } catch {
      if (panel.isConnected) setTimeout(poll, 3000);
    }
  };
  setTimeout(poll, 1000);
}

document.addEventListener('DOMContentLoaded', () => document.querySelectorAll('[data-review-panel]').forEach(pollPanelJobs));
