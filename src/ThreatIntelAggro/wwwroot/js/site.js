// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Shared bulk selection behavior for the Inbox and IOC review lists.
(() => {
  function initializeBulkSelection(form) {
    const selectVisible = form.querySelector('[data-select-visible]');
    const count = form.querySelector('[data-selection-count]');
    const items = [...document.querySelectorAll(`[form="${form.id}"][data-selection-item]`)];
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
    });
    items.forEach(item => item.addEventListener('change', refresh));
    role?.addEventListener('change', refresh);
    refresh();
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-bulk-selection]').forEach(initializeBulkSelection);
  });
})();
