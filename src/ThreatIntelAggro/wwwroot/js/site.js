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
    document.querySelectorAll('#bulk-articles-form[data-bulk-selection]').forEach(initializeBulkSelection);
  });
})();
