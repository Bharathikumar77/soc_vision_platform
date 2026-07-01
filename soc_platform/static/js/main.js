/**
 * SOC Platform — Main JavaScript
 * UI interactions, clock, sidebar, toast notifications
 */

// ── Live Clock ──
function updateClock() {
  const el = document.getElementById('topbarTime');
  if (el) {
    const now = new Date();
    el.textContent = now.toUTCString().replace('GMT', 'UTC');
  }
}
updateClock();
setInterval(updateClock, 1000);

// ── Sidebar Toggle (mobile) ──
const sidebarToggle = document.getElementById('sidebarToggle');
const sidebar = document.getElementById('sidebar');
if (sidebarToggle && sidebar) {
  sidebarToggle.addEventListener('click', () => {
    sidebar.classList.toggle('open');
  });
  document.addEventListener('click', (e) => {
    if (!sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  });
}

// ── Toast Notification ──
function showToast(message, type = 'info') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = 'opacity 0.3s';
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ── Animate KPI bars on dashboard load ──
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.cat-bar-fill').forEach(bar => {
    const w = bar.style.width;
    bar.style.width = '0';
    setTimeout(() => { bar.style.width = w; }, 100);
  });

  // Animate KPI numbers
  document.querySelectorAll('.kpi-value').forEach(el => {
    const target = parseInt(el.textContent, 10);
    if (isNaN(target) || target === 0) return;
    let current = 0;
    const step = Math.ceil(target / 30);
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = current;
      if (current >= target) clearInterval(timer);
    }, 30);
  });
});
