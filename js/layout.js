// Panel sizing. Each adjustable dimension is a CSS custom property that can be
// driven two ways: by dragging the gutter that sits on the panel's edge, or by
// the mirrored sliders in the left column. Both write the same value, so they
// always agree. Sizes are remembered per browser.

const KEY = 'btcdeb.layout';

/* sign: which way the pointer has to move to make the panel bigger.
   keep: how much room the flexible middle (or the layout above) must keep. */
const DIMS = {
  left:    { prop: '--col-left',  def: 290, min: 190, max: 640, axis: 'x', sign:  1 },
  right:   { prop: '--col-right', def: 340, min: 220, max: 720, axis: 'x', sign: -1 },
  console: { prop: '--console-h', def: 190, min: 68,  max: 720, axis: 'y', sign: -1 },
};
const MID_MIN = 320;   // the script listing stops being useful below this
const TOP_MIN = 220;   // never let the console eat the whole layout
const STEP = 16;       // arrow-key nudge

const size = { ...Object.fromEntries(Object.entries(DIMS).map(([k, d]) => [k, d.def])) };
const sliders = {};
const gutters = {};

/** Bounds depend on the viewport and on the *other* column's current width. */
function limits(name) {
  const d = DIMS[name];
  if (d.axis === 'y') {
    return [d.min, Math.max(d.min, Math.min(d.max, window.innerHeight - TOP_MIN))];
  }
  const other = name === 'left' ? size.right : size.left;
  const room = window.innerWidth - other - MID_MIN;
  return [d.min, Math.max(d.min, Math.min(d.max, room))];
}

const clamp = (name, v) => {
  const [lo, hi] = limits(name);
  return Math.round(Math.min(hi, Math.max(lo, Number(v) || 0)));
};

/** Push a value into the CSS var and back into both controls. */
function paint(name) {
  const d = DIMS[name];
  const [lo, hi] = limits(name);
  document.documentElement.style.setProperty(d.prop, `${size[name]}px`);

  const slider = sliders[name];
  if (slider) {
    slider.min = lo;
    slider.max = hi;
    slider.value = size[name];
    const out = slider.parentElement.querySelector('output');
    if (out) out.textContent = `${size[name]}px`;
  }

  const gutter = gutters[name];
  if (gutter) {
    gutter.setAttribute('aria-valuemin', lo);
    gutter.setAttribute('aria-valuemax', hi);
    gutter.setAttribute('aria-valuenow', size[name]);
  }
}

function set(name, value, persist = true) {
  size[name] = clamp(name, value);
  paint(name);
  // A wider left column shrinks what the right one may claim, and vice versa.
  paint(name === 'left' ? 'right' : name === 'right' ? 'left' : name);
  if (persist) save();
}

// ── persistence ───────────────────────────────────────────────────────────

function save() {
  try {
    localStorage.setItem(KEY, JSON.stringify(size));
  } catch {
    /* private browsing, quota — sizing just becomes session-only */
  }
}

function load() {
  let saved;
  try {
    saved = JSON.parse(localStorage.getItem(KEY) || '{}');
  } catch {
    return;
  }
  if (!saved || typeof saved !== 'object') return;
  for (const name of Object.keys(DIMS)) {
    if (Number.isFinite(saved[name])) size[name] = clamp(name, saved[name]);
  }
}

// ── dragging ──────────────────────────────────────────────────────────────

function startDrag(e, name) {
  if (e.button !== 0 && e.pointerType === 'mouse') return;
  const gutter = gutters[name];
  const d = DIMS[name];
  const axis = d.axis === 'x' ? 'clientX' : 'clientY';
  const origin = e[axis];
  const base = size[name];

  e.preventDefault();
  gutter.classList.add('active');
  document.body.classList.add('resizing');

  // Tracked on the window rather than through pointer capture: the pointer
  // leaves a 6px gutter almost immediately, and capture is the part most
  // likely to be missing (synthetic events, odd input devices).
  const move = (ev) => set(name, base + (ev[axis] - origin) * d.sign, false);
  const end = () => {
    window.removeEventListener('pointermove', move);
    window.removeEventListener('pointerup', end);
    window.removeEventListener('pointercancel', end);
    gutter.classList.remove('active');
    document.body.classList.remove('resizing');
    save();
  };

  window.addEventListener('pointermove', move);
  window.addEventListener('pointerup', end);
  window.addEventListener('pointercancel', end);
}

function nudge(e, name) {
  const d = DIMS[name];
  const keys = d.axis === 'x'
    ? { ArrowLeft: -1, ArrowRight: 1 }
    : { ArrowUp: -1, ArrowDown: 1 };

  if (e.key in keys) {
    e.preventDefault();
    set(name, size[name] + keys[e.key] * STEP * d.sign);
  } else if (e.key === 'Home' || e.key === 'Enter') {
    e.preventDefault();
    set(name, d.def);
  }
}

// ── wiring ────────────────────────────────────────────────────────────────

export function initLayout() {
  for (const gutter of document.querySelectorAll('[data-resize]')) {
    const name = gutter.dataset.resize;
    if (!DIMS[name]) continue;
    gutters[name] = gutter;
    gutter.addEventListener('pointerdown', (e) => startDrag(e, name));
    gutter.addEventListener('keydown', (e) => nudge(e, name));
    // Double-click a gutter to put that panel back where it started.
    gutter.addEventListener('dblclick', () => set(name, DIMS[name].def));
  }

  for (const slider of document.querySelectorAll('[data-size]')) {
    const name = slider.dataset.size;
    if (!DIMS[name]) continue;
    sliders[name] = slider;
    slider.addEventListener('input', () => set(name, slider.value, false));
    slider.addEventListener('change', save);
  }

  const reset = document.getElementById('size-reset');
  if (reset) {
    reset.addEventListener('click', () => {
      for (const [name, d] of Object.entries(DIMS)) set(name, d.def, false);
      save();
    });
  }

  // The viewport shrinking can invalidate a stored width.
  window.addEventListener('resize', () => {
    for (const name of Object.keys(DIMS)) {
      size[name] = clamp(name, size[name]);
      paint(name);
    }
  });

  load();
  for (const name of Object.keys(DIMS)) paint(name);
}
