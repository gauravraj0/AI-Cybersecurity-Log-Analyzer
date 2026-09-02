const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];

const toast = $('#toast');
const toastMessage = $('#toastMessage');
let toastTimer;

function showToast(message) {
  toastMessage.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove('show'), 3600);
}

$('#toastClose').addEventListener('click', () => toast.classList.remove('show'));

// Sidebar and workspace controls
$('#sidebarToggle').addEventListener('click', () => {
  $('#sidebar').classList.toggle('collapsed');
});

$('#mobileMenu').addEventListener('click', () => {
  $('#sidebar').classList.toggle('mobile-open');
});

const workspaceMenu = $('#workspaceMenu');
$('#workspaceSwitcher').addEventListener('click', (event) => {
  event.stopPropagation();
  workspaceMenu.classList.toggle('open');
});

$$('.workspace-option').forEach((option) => {
  option.addEventListener('click', () => {
    $$('.workspace-option').forEach((item) => item.classList.remove('active'));
    option.classList.add('active');
    const name = $('b', option)?.textContent || 'Northstar';
    const subtitle = $('small', option)?.textContent || 'Production workspace';
    $('.workspace-meta b').textContent = name;
    $('.workspace-meta small').textContent = `${subtitle} workspace`;
    workspaceMenu.classList.remove('open');
    showToast(`Switched to ${name} workspace`);
  });
});

$('.add-workspace').addEventListener('click', () => {
  workspaceMenu.classList.remove('open');
  showToast('Workspace creation is available on the Pro plan');
});

// Navigation remains in the single-page command center while giving immediate feedback.
$$('.nav-item').forEach((item) => {
  item.addEventListener('click', (event) => {
    event.preventDefault();
    $$('.nav-item').forEach((nav) => nav.classList.remove('active'));
    item.classList.add('active');
    const sectionName = item.dataset.section || 'Overview';
    $('#breadcrumbCurrent').textContent = sectionName;
    $('#sidebar').classList.remove('mobile-open');
    if (sectionName === 'Overview') {
      $('#overview').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else {
      showToast(`${sectionName} module selected — command center data remains in view`);
    }
  });
});

// Topbar notifications
const notificationPanel = $('#notificationPanel');
$('#notificationButton').addEventListener('click', (event) => {
  event.stopPropagation();
  notificationPanel.classList.toggle('open');
  workspaceMenu.classList.remove('open');
});
$('#markRead').addEventListener('click', () => {
  $('.notification-dot').style.display = 'none';
  notificationPanel.classList.remove('open');
  showToast('All notifications marked as read');
});
$('#helpButton').addEventListener('click', () => showToast('Tip: press ⌘ K anytime to search your event history'));
$('#profileButton').addEventListener('click', () => showToast('Profile settings are available from the Settings module'));

// File ingestion / drop zone
const fileInput = $('#fileInput');
const analyzeButtons = [$('#analyzeButton'), $('#intakeButton')];
analyzeButtons.forEach((button) => button.addEventListener('click', () => fileInput.click()));

function formatFileSize(bytes) {
  if (!bytes) return '0 KB';
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function addActivityForFile(file) {
  const activityList = $('#activityList');
  const item = document.createElement('div');
  item.className = 'activity-item';
  item.innerHTML = `<span class="activity-icon analyzed"><svg viewBox="0 0 24 24" fill="none"><path d="M4.5 12h3l2-5 4.2 10 2.1-5h3.7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></span><div class="activity-copy"><b>New log file queued for analysis</b><span><strong>${file.name}</strong> · ${formatFileSize(file.size)}</span></div><time>now</time>`;
  activityList.prepend(item);
  const items = $$('.activity-item', activityList);
  if (items.length > 5) items[items.length - 1].remove();
}

function handleFiles(fileList) {
  const files = [...fileList];
  if (!files.length) return;
  const file = files[0];
  const valid = /\.(log|txt|csv|json|ndjson)$/i.test(file.name);
  if (!valid) {
    showToast('Please choose a LOG, CSV, JSON, or NDJSON file');
    return;
  }
  addActivityForFile(file);
  showToast(`${file.name} queued — Aegis AI is analyzing it now`);
  $('#analyzeButton').innerHTML = '<svg viewBox="0 0 24 24" fill="none"><path d="M4.5 12h3l2-5 4.2 10 2.1-5h3.7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>Analyzing...';
  window.setTimeout(() => {
    $('#analyzeButton').innerHTML = '<svg viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>Analyze logs';
  }, 2400);
}

fileInput.addEventListener('change', (event) => {
  handleFiles(event.target.files);
  event.target.value = '';
});

const dropZone = $('#dropZone');
['dragenter', 'dragover'].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropZone.classList.add('dragging');
}));
['dragleave', 'drop'].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropZone.classList.remove('dragging');
}));
dropZone.addEventListener('drop', (event) => handleFiles(event.dataTransfer.files));
dropZone.addEventListener('click', () => fileInput.click());
$('#connectButton').addEventListener('click', () => showToast('Source connector panel is ready in Log sources'));
$('#upgradeButton').addEventListener('click', () => showToast('Aegis AI Pro includes adaptive detections and 365-day retention'));

// Download a useful report instead of a dead-end button.
$('#exportButton').addEventListener('click', () => {
  const rows = $$('#detectionRows tr').filter((row) => row.style.display !== 'none');
  const csv = [
    ['Detection', 'Source', 'Detected', 'Risk', 'Status'],
    ...rows.map((row) => $$('.detection-table td', row).slice(0, 5).map((cell) => cell.innerText.replace(/\s+/g, ' ').trim())),
  ].map((line) => line.map((value) => `"${value.replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'aegis-threat-report.csv';
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
  showToast('Threat report exported successfully');
});

// Threat activity chart ranges
const chartData = {
  '24h': {
    total: '188',
    labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', 'Now'],
    red: [25, 42, 31, 84, 58, 106, 93],
    blue: [12, 20, 29, 47, 34, 63, 52],
    change: '8.4%',
  },
  '7d': {
    total: '1,284',
    labels: ['Aug 27', 'Aug 28', 'Aug 29', 'Aug 30', 'Aug 31', 'Sep 01', 'Today'],
    red: [69, 88, 55, 110, 81, 154, 139],
    blue: [38, 62, 53, 76, 69, 99, 83],
    change: '18.6%',
  },
  '30d': {
    total: '4,891',
    labels: ['Aug 04', 'Aug 09', 'Aug 14', 'Aug 19', 'Aug 24', 'Aug 29', 'Today'],
    red: [46, 63, 57, 89, 75, 123, 151],
    blue: [38, 46, 68, 55, 73, 84, 113],
    change: '24.2%',
  },
};

function smoothPath(values, width = 740, height = 190, max = 180) {
  const points = values.map((value, index) => ({
    x: (width / (values.length - 1)) * index,
    y: height - (value / max) * (height - 12) - 3,
  }));
  if (points.length < 2) return '';
  let path = `M${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  for (let index = 1; index < points.length; index += 1) {
    const previous = points[index - 1];
    const current = points[index];
    const midpoint = (previous.x + current.x) / 2;
    path += ` C${midpoint.toFixed(1)} ${previous.y.toFixed(1)} ${midpoint.toFixed(1)} ${current.y.toFixed(1)} ${current.x.toFixed(1)} ${current.y.toFixed(1)}`;
  }
  return path;
}

function areaPath(linePath, height = 220) {
  const match = linePath.match(/^M([\d.]+) ([\d.]+)/);
  if (!match) return '';
  return `${linePath}V${height}H${match[1]}Z`;
}

function updateChart(range) {
  const data = chartData[range];
  const red = smoothPath(data.red);
  const blue = smoothPath(data.blue);
  $('#redLine').setAttribute('d', red);
  $('#blueLine').setAttribute('d', blue);
  $('#redArea').setAttribute('d', areaPath(red));
  $('#blueArea').setAttribute('d', areaPath(blue));
  $('#chartTotal').textContent = data.total;
  $('.chart-change').innerHTML = `<i></i> ${data.change} <small>vs. last period</small>`;
  $('#xLabels').innerHTML = data.labels.map((label) => `<span>${label}</span>`).join('');
  const lastRed = data.red[data.red.length - 1];
  const lastBlue = data.blue[data.blue.length - 1];
  const x = 740;
  const yRed = 190 - (lastRed / 180) * 178 - 3;
  const yBlue = 190 - (lastBlue / 180) * 178 - 3;
  $('#chartPoints').innerHTML = `<circle cx="${x}" cy="${yRed.toFixed(1)}" r="4" fill="#ff6b62" stroke="#0f131c" stroke-width="3"/><circle cx="${x}" cy="${yBlue.toFixed(1)}" r="3.5" fill="#6db7ff" stroke="#0f131c" stroke-width="3"/>`;
}

$$('.range-tab').forEach((tab) => tab.addEventListener('click', () => {
  $$('.range-tab').forEach((button) => button.classList.remove('active'));
  tab.classList.add('active');
  updateChart(tab.dataset.range);
}));

// Search and severity filters
const detectionRows = $$('#detectionRows tr');
let activeSeverity = 'all';
function filterDetections() {
  const query = $('#logSearch').value.trim().toLowerCase();
  let visible = 0;
  detectionRows.forEach((row) => {
    const matchesSearch = !query || row.dataset.search.includes(query);
    const matchesSeverity = activeSeverity === 'all' || row.dataset.severity === activeSeverity;
    row.style.display = matchesSearch && matchesSeverity ? '' : 'none';
    if (matchesSearch && matchesSeverity) visible += 1;
  });
  $('#emptyState').classList.toggle('visible', visible === 0);
}
$('#logSearch').addEventListener('input', filterDetections);
$('#filterButton').addEventListener('click', () => $('#filterMenu').classList.toggle('open'));
$$('.filter-chip').forEach((chip) => chip.addEventListener('click', () => {
  $$('.filter-chip').forEach((button) => button.classList.remove('selected'));
  chip.classList.add('selected');
  activeSeverity = chip.dataset.filter;
  filterDetections();
  $('#filterMenu').classList.remove('open');
}));
$('#viewQueue').addEventListener('click', () => {
  $('#filterMenu').classList.remove('open');
  showToast('Showing all 7 detections in the investigation queue');
});

// Detection detail modal
const modalBackdrop = $('#modalBackdrop');
const modalDetails = {
  'Privilege escalation attempt': {
    description: 'Aegis identified an unusual privilege escalation sequence originating from an external session. The behavior deviates from this identity’s normal access pattern.',
    reasoning: 'The actor requested an unusual IAM policy change after a successful login from an unrecognized ASN. Similar activity has preceded account takeover in 3 prior incidents.',
    confidence: '98.2%',
  },
  'Distributed brute-force attack': {
    description: 'A coordinated sequence of failed SSH authentications was detected across the public web tier and automatically contained at the edge.',
    reasoning: '43 login attempts targeted 8 accounts within 90 seconds. IP reputation, velocity, and username distribution align with an automated credential attack.',
    confidence: '99.1%',
  },
  'Malware beacon signature': {
    description: 'The endpoint generated a recurring outbound connection pattern associated with command-and-control traffic.',
    reasoning: 'The destination is newly observed for this workspace and the request cadence matches a known C2 heartbeat. Endpoint isolation is recommended.',
    confidence: '94.7%',
  },
  'Impossible travel detected': {
    description: 'A single identity authenticated from two geographically distant locations in a time window that is not physically plausible.',
    reasoning: 'The second session used a new browser fingerprint and an unfamiliar ASN. Confirm the user’s activity and rotate credentials if unrecognized.',
    confidence: '88.6%',
  },
};

function openDetectionModal(row) {
  const title = $('td:first-child b', row)?.textContent || 'Detection';
  const risk = $('.risk-tag', row)?.textContent || 'High';
  const source = $('.source-chip', row)?.innerText.replace(/\s+/g, ' ').trim() || 'Unknown source';
  const eventId = $('.mono', row)?.textContent || 'EVT-00000';
  const observed = $('.time-cell', row)?.textContent || 'Just now';
  const detail = modalDetails[title] || modalDetails['Privilege escalation attempt'];
  $('#modalTitle').textContent = title;
  $('#modalSeverity').textContent = risk.toUpperCase();
  $('#modalSeverity').className = `modal-severity ${risk.toLowerCase()}-modal`;
  $('#modalDescription').textContent = detail.description;
  $('#modalReasoning').textContent = detail.reasoning;
  $('#modalSource').textContent = source;
  $('#modalEvent').textContent = eventId;
  $('#modalObserved').textContent = observed;
  $('#modalConfidence').textContent = detail.confidence;
  modalBackdrop.classList.add('open');
  document.body.style.overflow = 'hidden';
}

detectionRows.forEach((row) => {
  row.addEventListener('click', (event) => {
    if (event.target.closest('button')) return;
    openDetectionModal(row);
  });
  $('.row-more', row).addEventListener('click', () => openDetectionModal(row));
});
function closeModal() {
  modalBackdrop.classList.remove('open');
  document.body.style.overflow = '';
}
$('#modalClose').addEventListener('click', closeModal);
$('#modalDismiss').addEventListener('click', closeModal);
$('#modalInvestigate').addEventListener('click', () => {
  closeModal();
  showToast('Investigation workspace opened for this detection');
});
modalBackdrop.addEventListener('click', (event) => {
  if (event.target === modalBackdrop) closeModal();
});
$('#postureButton').addEventListener('click', () => showToast('Risk assessment refreshed from 26 connected sources'));

// Live stream pause control
$('#streamControl').addEventListener('click', () => {
  const control = $('#streamControl');
  const paused = control.classList.toggle('paused');
  $('.activity-panel')?.classList.toggle('stream-paused', paused);
  $('#streamControlText').textContent = paused ? 'Resume' : 'Pause';
  showToast(paused ? 'Live activity stream paused' : 'Live activity stream resumed');
});
$('#activityFooter').addEventListener('click', () => showToast('Live stream expanded to the event explorer'));

// Global affordances
window.addEventListener('click', (event) => {
  if (!event.target.closest('.notification-wrap')) notificationPanel.classList.remove('open');
  if (!event.target.closest('#workspaceSwitcher') && !event.target.closest('#workspaceMenu')) workspaceMenu.classList.remove('open');
});
window.addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault();
    $('#logSearch').focus();
  }
  if (event.key === 'Escape') {
    closeModal();
    notificationPanel.classList.remove('open');
    workspaceMenu.classList.remove('open');
  }
});

updateChart('7d');
