(() => {

function initialize() {
  const form = document.getElementById('graph-filter-form');
  const svg = document.querySelector('[data-graph-svg]');
  if (!form || !svg) return;
  const inspectorLabel = document.querySelector('[data-inspector-label]');
  const inspectorType = document.querySelector('[data-inspector-type]');
  const inspectorDetails = document.querySelector('[data-inspector-details]');
  const evidenceList = document.querySelector('[data-inspector-evidence]');
  const nodes = [...svg.querySelectorAll('[data-graph-node]')];
  const edges = [...svg.querySelectorAll('[data-edge-from]')];
  const canvasViewport = document.querySelector('.graph-canvas-viewport');
  const graphBackground = svg.querySelector('[data-graph-background]');
  function selectNode(node) {
    nodes.forEach(item => item.classList.toggle('selected', item === node));
    inspectorLabel.textContent = node.dataset.nodeLabel || '';
    inspectorType.textContent = (node.dataset.nodeType || '').toUpperCase();
    inspectorDetails.textContent = node.dataset.nodeDetails || 'No additional entity description is available.';
    const meta = [node.dataset.nodeCategory, node.dataset.nodeSource, node.dataset.nodeStatus ? 'IOC · ' + node.dataset.nodeStatus : ''].filter(Boolean);
    document.querySelector('[data-inspector-category]').textContent = meta[0] || '';
    document.querySelector('[data-inspector-source]').textContent = meta[1] || '';
    document.querySelector('[data-inspector-status]').textContent = meta[2] || '';
    evidenceList.replaceChildren();
    edges.filter(edge => edge.dataset.edgeFrom === node.dataset.nodeId || edge.dataset.edgeTo === node.dataset.nodeId).slice(0, 12).forEach(edge => {
      const title = edge.querySelector('title')?.textContent || '';
      const row = document.createElement('div'); row.className = 'graph-evidence-item';
      const mark = document.createElement('span'); mark.className = 'graph-evidence-mark';
      const content = document.createElement('div'); const strong = document.createElement('strong'); strong.textContent = title.split(' · evidence:')[0];
      const small = document.createElement('small'); small.textContent = title.includes(' · evidence:') ? 'Evidence: ' + title.split(' · evidence:')[1] : title;
      content.append(strong, small); row.append(mark, content); evidenceList.append(row);
    });
  }
  nodes.forEach(node => {
    node.addEventListener('click', () => selectNode(node));
    node.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectNode(node); } });
  });
  const nodeById = new Map(nodes.map(node => [node.dataset.nodeId, node]));
  const readViewBox = () => {
    const values = (svg.getAttribute('viewBox') || `0 0 ${svg.getAttribute('width')} ${svg.getAttribute('height')}`).trim().split(/[\s,]+/).map(Number);
    return { x: values[0] || 0, y: values[1] || 0, width: values[2] || Number(svg.getAttribute('width')), height: values[3] || Number(svg.getAttribute('height')) };
  };
  const setViewBox = view => {
    svg.setAttribute('viewBox', `${view.x} ${view.y} ${view.width} ${view.height}`);
    graphBackground?.setAttribute('x', String(view.x));
    graphBackground?.setAttribute('y', String(view.y));
    graphBackground?.setAttribute('width', String(view.width));
    graphBackground?.setAttribute('height', String(view.height));
  };
  const pointerToSvg = (clientX, clientY) => {
    const rect = svg.getBoundingClientRect(); const view = readViewBox();
    return { x: view.x + (clientX - rect.left) / Math.max(1, rect.width) * view.width, y: view.y + (clientY - rect.top) / Math.max(1, rect.height) * view.height };
  };
  function setNodePosition(node, x, y) {
    node.dataset.nodeX = String(x); node.dataset.nodeY = String(y);
    node.querySelector('circle')?.setAttribute('cx', String(x));
    node.querySelector('circle')?.setAttribute('cy', String(y));
    node.querySelectorAll('text').forEach(text => {
      text.setAttribute('x', String(x));
      text.setAttribute('y', String(y + (text.classList.contains('graph-node-label') ? 39 : 52)));
    });
    edges.filter(edge => edge.dataset.edgeFrom === node.dataset.nodeId || edge.dataset.edgeTo === node.dataset.nodeId).forEach(edge => {
      const source = nodeById.get(edge.dataset.edgeFrom); const target = nodeById.get(edge.dataset.edgeTo);
      if (!source || !target) return;
      const sx = Number(source.dataset.nodeX); const sy = Number(source.dataset.nodeY);
      const tx = Number(target.dataset.nodeX); const ty = Number(target.dataset.nodeY);
      const dx = tx - sx; const dy = ty - sy; const length = Math.hypot(dx, dy) || 1;
      const line = edge.querySelector('line');
      line?.setAttribute('x1', String(sx + dx / length * 24));
      line?.setAttribute('y1', String(sy + dy / length * 24));
      line?.setAttribute('x2', String(tx - dx / length * 24));
      line?.setAttribute('y2', String(ty - dy / length * 24));
    });
  }
  let drag = null;
  let pan = null;
  nodes.forEach(node => {
    node.addEventListener('pointerdown', event => {
      if (event.button !== 0) return;
      const point = pointerToSvg(event.clientX, event.clientY);
      drag = { node, pointerId: event.pointerId, pointerX: point.x, pointerY: point.y, nodeX: Number(node.dataset.nodeX), nodeY: Number(node.dataset.nodeY) };
      node.classList.add('dragging'); svg.setPointerCapture?.(event.pointerId); event.preventDefault();
    });
  });
  svg.addEventListener('pointerdown', event => {
    if (event.button !== 0 || event.target.closest?.('[data-graph-node]')) return;
    const rect = svg.getBoundingClientRect();
    const view = readViewBox();
    pan = { pointerId: event.pointerId, pointerX: event.clientX, pointerY: event.clientY, rect, view };
    canvasViewport.classList.add('panning');
    svg.setPointerCapture?.(event.pointerId);
    event.preventDefault();
  });
  svg.addEventListener('pointermove', event => {
    if (drag && drag.pointerId === event.pointerId) {
      const point = pointerToSvg(event.clientX, event.clientY);
      setNodePosition(drag.node, drag.nodeX + point.x - drag.pointerX, drag.nodeY + point.y - drag.pointerY);
      return;
    }
    if (!pan || pan.pointerId !== event.pointerId) return;
    const deltaX = event.clientX - pan.pointerX;
    const deltaY = event.clientY - pan.pointerY;
    const viewX = pan.view.x - deltaX / Math.max(1, pan.rect.width) * pan.view.width;
    const viewY = pan.view.y - deltaY / Math.max(1, pan.rect.height) * pan.view.height;
    setViewBox({ x: viewX, y: viewY, width: pan.view.width, height: pan.view.height });
  });
  const finishDrag = event => {
    if (drag && drag.pointerId === event.pointerId) { drag.node.classList.remove('dragging'); drag = null; }
    if (pan && pan.pointerId === event.pointerId) { pan = null; canvasViewport.classList.remove('panning'); }
  };
  svg.addEventListener('pointerup', finishDrag);
  svg.addEventListener('pointercancel', finishDrag);
  const coToggle = form.querySelector('[name="CoMentionsInput"]');
  svg.querySelectorAll('.co-mention-edge').forEach(edge => edge.style.display = coToggle?.checked ? '' : 'none');
  let baseCanvasWidth = Number(svg.getAttribute('width'));
  let baseCanvasHeight = Number(svg.getAttribute('height'));
  let zoomLevel = 1;
  let fitBounds = null;
  function applyCanvasZoom() {
    svg.style.width = `${Math.max(1, baseCanvasWidth * zoomLevel)}px`;
    svg.style.height = `${Math.max(1, baseCanvasHeight * zoomLevel)}px`;
  }
  form.querySelector('[data-graph-zoom="in"]')?.addEventListener('click', () => { zoomLevel = Math.min(5, zoomLevel * 1.25); applyCanvasZoom(); });
  form.querySelector('[data-graph-zoom="out"]')?.addEventListener('click', () => { zoomLevel = Math.max(.2, zoomLevel / 1.25); applyCanvasZoom(); });
  form.querySelector('[data-graph-fit]')?.addEventListener('click', () => {
    if (!canvasViewport || nodes.length === 0) return;
    const padding = 42;
    const bounds = nodes.map(node => {
      const x = Number(node.dataset.nodeX); const y = Number(node.dataset.nodeY);
      const labelWidth = Math.max(46, (node.querySelector('.graph-node-label')?.textContent.length || 0) * 5.5);
      return { left: x - labelWidth / 2, right: x + labelWidth / 2, top: y - 24, bottom: y + 57 };
    });
    const left = Math.min(...bounds.map(box => box.left)) - padding;
    const top = Math.min(...bounds.map(box => box.top)) - padding;
    const right = Math.max(...bounds.map(box => box.right)) + padding;
    const bottom = Math.max(...bounds.map(box => box.bottom)) + padding;
    setViewBox({ x: left, y: top, width: right - left, height: bottom - top });
    fitBounds = { x: left, y: top, width: right - left, height: bottom - top };
    baseCanvasWidth = Math.max(1, canvasViewport.clientWidth);
    baseCanvasHeight = Math.max(1, canvasViewport.clientHeight);
    zoomLevel = 1; applyCanvasZoom();
    canvasViewport.scrollLeft = 0; canvasViewport.scrollTop = 0;
  });
  const resize = new AbortController();
  document.addEventListener('review-filter-updated', () => resize.abort(), { once: true });
  window.addEventListener('resize', () => {
    if (!fitBounds || !canvasViewport) return;
    baseCanvasWidth = Math.max(1, canvasViewport.clientWidth);
    baseCanvasHeight = Math.max(1, canvasViewport.clientHeight);
    applyCanvasZoom();
  }, { signal: resize.signal });
  form.querySelector('.graph-export-image')?.addEventListener('click', () => {
    const clone = svg.cloneNode(true); clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    const style = document.createElementNS('http://www.w3.org/2000/svg', 'style');
    const exportedNodeColors = nodes.map(node => { const colors = getComputedStyle(node); return `.graph-node.type-${node.dataset.nodeTypeKey} circle{fill:${colors.getPropertyValue('--graph-node-fill').trim()};stroke:${colors.getPropertyValue('--graph-node-stroke').trim()}}`; }).join('');
    style.textContent = '.graph-edges line{stroke:#4b6672;stroke-width:1.2}.graph-edge.co-mention-edge line{stroke:#71808e;stroke-dasharray:4 4}.graph-edge text{fill:#aab6c0;font:9px monospace}.graph-node circle{fill:#13232a;stroke:#57c5d9;stroke-width:1.5}.graph-node text{fill:#d9e0e8;font:10px monospace;text-anchor:middle}.graph-node .graph-node-kind{fill:#81909e;font-size:8px}' + exportedNodeColors + '.graph-node.selected circle{stroke:#dff7fa;stroke-width:2.4}';
    clone.prepend(style); const blob = new Blob([new XMLSerializer().serializeToString(clone)], { type: 'image/svg+xml' });
    const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'threat-intel-graph.svg'; link.click(); URL.revokeObjectURL(link.href);
  });
}

  document.addEventListener('DOMContentLoaded', initialize);
  document.addEventListener('review-filter-updated', initialize);
})();
