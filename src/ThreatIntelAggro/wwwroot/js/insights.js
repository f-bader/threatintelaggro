(() => {

    function initialize() {
      const map = document.querySelector('[data-entity-map]');
      if (!map) return;
      const tiles = [...map.querySelectorAll('[data-entity-key]')];
      const clearButton = document.querySelector('[data-clear-entity-filter]');
      const status = document.querySelector('[data-entity-filter-message]');
      const relatedArticles = document.querySelector('[data-related-articles]');
      let selectedKey = null;

      function layout(items) {
        function split(group, left, top, width, height) {
          if (!group.length) return;
          if (group.length === 1) {
            const tile = group[0];
            tile.style.left = `calc(${left}% + 2px)`;
            tile.style.top = `calc(${top}% + 2px)`;
            tile.style.width = `calc(${width}% - 4px)`;
            tile.style.height = `calc(${height}% - 4px)`;
            return;
          }
          const total = group.reduce((sum, tile) => sum + Number(tile.dataset.articleCount), 0);
          let running = 0, splitAt = 1, closest = Infinity;
          for (let index = 1; index < group.length; index++) {
            running += Number(group[index - 1].dataset.articleCount);
            const distance = Math.abs(total / 2 - running);
            if (distance < closest) { closest = distance; splitAt = index; }
          }
          const first = group.slice(0, splitAt), second = group.slice(splitAt);
          const weight = first.reduce((sum, tile) => sum + Number(tile.dataset.articleCount), 0);
          const share = weight / total;
          if (width >= height) {
            split(first, left, top, width * share, height);
            split(second, left + width * share, top, width * (1 - share), height);
          } else {
            split(first, left, top, width, height * share);
            split(second, left, top + height * share, width, height * (1 - share));
          }
        }
        split(items, 0, 0, 100, 100);
      }

      function refresh() {
        const enabled = new Set([...document.querySelectorAll('[data-entity-toggle]:checked')].map(toggle => toggle.dataset.entityToggle));
        let selected = tiles.find(tile => tile.dataset.entityKey === selectedKey);
        if (selected && !enabled.has(selected.dataset.entityCategory)) {
          selectedKey = null;
          selected = null;
        }
        const related = selected ? new Set(JSON.parse(selected.dataset.entityRelated)) : null;
        const visible = tiles.filter(tile => {
          const categoryVisible = enabled.has(tile.dataset.entityCategory);
          const matchesSelection = !selected || tile === selected ||
            (tile.dataset.entityCategory !== selected.dataset.entityCategory && related.has(tile.dataset.entityKey));
          const show = categoryVisible && matchesSelection;
          tile.hidden = !show;
          tile.classList.toggle('is-selected', tile === selected);
          tile.setAttribute('aria-pressed', String(tile === selected));
          return show;
        });
        layout(visible);
        map.querySelector('[data-entity-map-empty]').hidden = visible.length > 0 || enabled.size > 0;

        const matrixHeaders = [...document.querySelectorAll('[data-matrix-category-head]')];
        matrixHeaders.forEach(head => {
          head.hidden = !enabled.has(head.dataset.matrixCategoryHead) ||
            (!!selected && head.dataset.entityKey !== selectedKey && !related.has(head.dataset.entityKey));
        });
        document.querySelectorAll('tbody tr[data-matrix-row-category]').forEach(row => {
          const rowMatches = enabled.has(row.dataset.matrixRowCategory) &&
            (!selected || row.dataset.entityKey === selectedKey || related.has(row.dataset.entityKey));
          row.hidden = !rowMatches;
          [...row.cells].slice(1).forEach((cell, index) => {
            const head = matrixHeaders[index];
            cell.hidden = !rowMatches || !head || head.hidden;
          });
        });
        clearButton.hidden = !selected;
        relatedArticles.hidden = !selected;
        status.textContent = selected
          ? `${selected.querySelector('.entity-tile-category').textContent}: ${selected.querySelector('.entity-tile-name').textContent} — showing directly co-mentioned entities.`
          : 'Select an entity to focus the map on its co-mentioned entities. Category colors identify the entity type.';
        if (selected) {
          relatedArticles.href = selected.dataset.articlesHref;
          relatedArticles.setAttribute('aria-label', `Show articles mentioning ${selected.querySelector('.entity-tile-name').textContent}`);
        }
      }

      tiles.forEach(tile => tile.addEventListener('click', () => {
        selectedKey = selectedKey === tile.dataset.entityKey ? null : tile.dataset.entityKey;
        refresh();
      }));
      clearButton.addEventListener('click', () => { selectedKey = null; refresh(); });
      document.querySelectorAll('[data-entity-toggle]').forEach(toggle => toggle.addEventListener('change', refresh));
      refresh();
    }

  document.addEventListener('DOMContentLoaded', initialize);
  document.addEventListener('review-filter-updated', initialize);
})();
