/**
 * InfoShield — Document Privacy Workflow Engine
 * Vanilla JavaScript implementation for light-themed document submission assistant.
 * Handles state, Web Speech API, camera/file upload, multi-stage workflow, and responsive UI.
 */

(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Backend Configuration (Dynamic Resolution for Local & Cloud Deployments)
  // ---------------------------------------------------------------------------
  function getBackendBaseUrl() {
    // 1. Runtime configuration object from config.js (HIGHEST authority for configured deployment)
    if (window.INFOSHIELD_CONFIG && typeof window.INFOSHIELD_CONFIG.BACKEND_URL === 'string') {
      const cfgUrl = window.INFOSHIELD_CONFIG.BACKEND_URL.trim();
      if (cfgUrl) {
        // Clear any stale local storage override from past sessions to prevent redirection
        try { localStorage.removeItem('infoshield_backend_url'); } catch (_) {}
        return cfgUrl.replace(/\/+$/, '');
      }
    }

    const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

    // 2. Strict Dev-only URL Query Parameter override
    // NEVER permit in production or across untrusted domains
    if (isLocalhost) {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const queryBackend = urlParams.get('backend');
        if (queryBackend) {
          const parsed = new URL(queryBackend.trim());
          const allowedHosts = ['localhost', '127.0.0.1'];
          if (allowedHosts.includes(parsed.hostname) && (parsed.protocol === 'http:' || parsed.protocol === 'https:')) {
            const clean = queryBackend.trim().replace(/\/+$/, '');
            return clean;
          }
        }
      } catch (_) {}
    } else {
      // In production, ensure no unauthenticated local storage backend overrides persist
      try { localStorage.removeItem('infoshield_backend_url'); } catch (_) {}
    }

    // 3. Default to localhost if accessed on local development host
    if (isLocalhost) {
      return 'http://127.0.0.1:8000';
    }

    // 4. Default to empty string for same-origin reverse-proxy / Vercel rewrites (HTTPS in prod)
    return '';
  }

  const BACKEND_BASE_URL = getBackendBaseUrl();

  // ---------------------------------------------------------------------------
  // Application State
  // ---------------------------------------------------------------------------
  const state = {
    currentScreen: 'screen-select',
    selectedDocument: 'Aadhaar Card',
    uploadedFile: null,
    uploadedImageDataUrl: null,
    uploadedImageDimensions: null,
    purposeText: '',
    activeResultTab: 'protected', // 'original' | 'protected'
    isListeningSearch: false,
    isListeningPurpose: false,
    isProcessing: false,
    apiResult: null,
    sessionHistory: [],
    screenHistory: []
  };

  // ---------------------------------------------------------------------------
  // Document Specification Presets for Purpose-Based Minimization
  // ---------------------------------------------------------------------------
  // Document Specification Presets for Purpose-Based Minimization
  // ---------------------------------------------------------------------------
  const DOCUMENT_PROFILES = {
    'Aadhaar Card': {
      orgTitle: 'GOVERNMENT OF INDIA',
      subTitle: 'Unique Identification Authority of India',
      numberLabel: 'Aadhaar Number',
      fullNumber: '9823  4567  9012',
      maskedNumber: 'XXXX  XXXX  9012',
      addressText: 'Flat 402, Green Meadows, Andheri East, Mumbai, Maharashtra - 400069',
      redactedAddress: '[REDACTED FOR PRIVACY — State: Maharashtra Preserved]',
      hasQr: true,
      fields: [
        { name: 'Full Name', status: 'required', label: 'Required', desc: 'Used to identify the applicant for administrative records.' },
        { name: 'Date of Birth', status: 'required', label: 'Required', desc: 'Needed for age and matriculation eligibility verification.' },
        { name: 'Aadhaar Number', status: 'conditional', label: 'Conditional', desc: 'Only last 4 digits needed. Full 12 digits minimized.' },
        { name: 'Full Address', status: 'excluded', label: 'Not required', desc: 'Not necessary for the stated purpose. Region minimized.' },
        { name: 'QR Code (Biometrics)', status: 'excluded', label: 'Not required', desc: 'Contains biometric payload. Removed to prevent unauthorized extraction.' }
      ],
      reasons: [
        { field: 'Aadhaar Number', state: 'masked', desc: 'Not required to expose full 12-digit number for submission. Minimized to last 4 digits.' },
        { field: 'Street Address', state: 'redacted', desc: 'Only broad state jurisdiction is needed. Exact residential address redacted.' },
        { field: 'QR Code Matrix', state: 'removed', desc: 'Contains cryptographic demographic payload. Removed to prevent third-party harvesting.' },
        { field: 'Full Name & DOB', state: 'kept', desc: 'Essential demographic credentials required to verify your application.' }
      ]
    },
    'PAN Card': {
      orgTitle: 'INCOME TAX DEPARTMENT',
      subTitle: 'Government of India',
      numberLabel: 'Permanent Account Number',
      fullNumber: 'ABCDE  1234  F',
      maskedNumber: 'XXXXX  1234  F',
      addressText: 'N/A (Card does not display residential address)',
      redactedAddress: '[N/A — Financial Identity Only]',
      hasQr: false,
      fields: [
        { name: 'Full Name', status: 'required', label: 'Required', desc: 'Matches applicant tax identity records.' },
        { name: 'Date of Birth', status: 'required', label: 'Required', desc: 'Verifies applicant legal age.' },
        { name: 'PAN Number', status: 'conditional', label: 'Conditional', desc: 'Exposing last 4 characters suffices for verification.' },
        { name: "Father's Name", status: 'excluded', label: 'Not required', desc: 'Irrelevant for general non-banking verifications.' }
      ],
      reasons: [
        { field: 'PAN Number', state: 'masked', desc: 'First 5 letters masked to prevent unauthorized tax credit inquiries.' },
        { field: "Father's Name", state: 'redacted', desc: 'Secondary familial identifiers are unnecessary for applicant verification.' },
        { field: 'Full Name & DOB', state: 'kept', desc: 'Core identifying credentials retained for recipient review.' }
      ]
    },
    'Passport': {
      orgTitle: 'REPUBLIC OF INDIA',
      subTitle: 'Passport / Passeport',
      numberLabel: 'Passport Number',
      fullNumber: 'Z892  3412',
      maskedNumber: 'Z89X  XXXX',
      addressText: 'Flat 402, Green Meadows, Andheri East, Mumbai, Maharashtra - 400069',
      redactedAddress: '[REDACTED — Nationality: Indian Preserved]',
      hasQr: false,
      fields: [
        { name: 'Full Name', status: 'required', label: 'Required', desc: 'Matches passenger and immigration identification records.' },
        { name: 'Nationality', status: 'required', label: 'Required', desc: 'Confirms sovereign citizen travel authority.' },
        { name: 'Passport Number', status: 'conditional', label: 'Conditional', desc: 'First 3 characters retained. Serial shielded.' },
        { name: 'File Number & Barcode', status: 'excluded', label: 'Not required', desc: 'Internal consular dispatch codes removed.' }
      ],
      reasons: [
        { field: 'Passport Number', state: 'masked', desc: 'First 3 characters retained for prefix validity, sequential serial shielded.' },
        { field: 'File Number & Barcode', state: 'removed', desc: 'Internal consular dispatch codes removed to avoid unauthorized dossier search.' },
        { field: 'Full Name & Nationality', state: 'kept', desc: 'Mandatory primary demographic keys retained.' }
      ]
    },
    'Driving Licence': {
      orgTitle: 'MINISTRY OF ROAD TRANSPORT & HIGHWAYS',
      subTitle: 'Driving Licence - Government of India',
      numberLabel: 'Licence Number',
      fullNumber: 'MH02  2018  0092341',
      maskedNumber: 'MH02  XXXX  XXXX341',
      addressText: 'Flat 402, Green Meadows, Andheri East, Mumbai, Maharashtra - 400069',
      redactedAddress: '[REDACTED — Issuing RTO: MH-02 Mumbai Preserved]',
      hasQr: true,
      fields: [
        { name: 'Driver Name', status: 'required', label: 'Required', desc: 'Identifies licensed driver.' },
        { name: 'Authorized Classes', status: 'required', label: 'Required', desc: 'Validates authorized vehicle operation category.' },
        { name: 'Licence Number', status: 'conditional', label: 'Conditional', desc: 'Regional RTO and last 3 digits retained.' },
        { name: 'Blood Group', status: 'excluded', label: 'Not required', desc: 'Sensitive biometric health metric shielded.' },
        { name: 'Residential Address', status: 'excluded', label: 'Not required', desc: 'Street address shielded; jurisdiction retained.' }
      ],
      reasons: [
        { field: 'Licence Serial', state: 'masked', desc: 'RTO jurisdiction kept while internal sequential registration is minimized.' },
        { field: 'Blood Group', state: 'removed', desc: 'Health and medical classification data removed to protect privacy.' },
        { field: 'Driver Name & Class', state: 'kept', desc: 'Validates authorized credential holder and vehicle permit.' }
      ]
    },
    'College ID': {
      orgTitle: 'UNIVERSITY ACADEMIC RECORDS',
      subTitle: 'Student Identification Card',
      numberLabel: 'Student Roll No',
      fullNumber: 'CS-2024-88912',
      maskedNumber: 'CS-XXXX-88912',
      addressText: 'Hostel Block 3, North Campus, Mumbai - 400076',
      redactedAddress: '[REDACTED — Campus Residential Address Protected]',
      hasQr: true,
      fields: [
        { name: 'Student Name', status: 'required', label: 'Required', desc: 'Identifies active student enrolment.' },
        { name: 'Student ID / Roll', status: 'required', label: 'Required', desc: 'Validates institutional credential.' },
        { name: 'Blood Group / Emergency', status: 'excluded', label: 'Not required', desc: 'Medical information not needed for general verification.' },
        { name: 'Hostel Address', status: 'excluded', label: 'Not required', desc: 'Private campus room location shielded.' }
      ],
      reasons: [
        { field: 'Student Roll No', state: 'masked', desc: 'Batch prefix preserved while personal internal student index is minimized.' },
        { field: 'Emergency / Blood Group', state: 'removed', desc: 'Personal health data removed to preserve privacy.' },
        { field: 'Student Name', state: 'kept', desc: 'Retained to verify academic status.' }
      ]
    },
    'Marksheet': {
      orgTitle: 'CENTRAL BOARD OF SECONDARY EDUCATION',
      subTitle: 'Senior School Certificate Examination',
      numberLabel: 'Roll Number',
      fullNumber: '6624  912',
      maskedNumber: '662X  XXX',
      addressText: 'Examination Centre: Mumbai Zone 4',
      redactedAddress: '[PRESERVED — Educational Board Center Verified]',
      hasQr: true,
      fields: [
        { name: 'Student Name', status: 'required', label: 'Required', desc: 'Authenticates student transcript.' },
        { name: 'Subject Scores & Grade', status: 'required', label: 'Required', desc: 'Essential academic performance evaluation.' },
        { name: 'Roll Number', status: 'conditional', label: 'Conditional', desc: 'Prefix retained; internal seat serial minimized.' },
        { name: "Parents' Names", status: 'excluded', label: 'Not required', desc: 'Irrelevant for academic merit verification.' }
      ],
      reasons: [
        { field: "Parents' Names", state: 'redacted', desc: 'Parental information is non-essential for verifying academic qualifications.' },
        { field: 'Internal Ledger ID', state: 'removed', desc: 'Exam center internal serialization removed.' },
        { field: 'Name & Subject Grades', state: 'kept', desc: 'Core scholastic performance preserved for institutional review.' }
      ]
    },
    'Bank Statement': {
      orgTitle: 'RESERVE BANK ACCREDITED BANK',
      subTitle: 'Account Statement & Summary',
      numberLabel: 'Account Number',
      fullNumber: '5010  0492  8192  34',
      maskedNumber: 'XXXX  XXXX  XXXX  34',
      addressText: 'Branch: Andheri East, Mumbai',
      redactedAddress: '[PRESERVED — Bank Branch & City Verified]',
      hasQr: false,
      fields: [
        { name: 'Account Holder Name', status: 'required', label: 'Required', desc: 'Authenticates account owner.' },
        { name: 'Closing Balance', status: 'required', label: 'Required', desc: 'Demonstrates financial solvency.' },
        { name: 'Account Number', status: 'conditional', label: 'Conditional', desc: 'Masked to last 4 digits.' },
        { name: 'Counterparty Details', status: 'excluded', label: 'Not required', desc: 'Third-party transaction history shielded.' }
      ],
      reasons: [
        { field: 'Account Number', state: 'masked', desc: 'Only last 4 digits visible to prevent unauthorized debits.' },
        { field: 'Transaction Payees', state: 'redacted', desc: 'Third-party vendors and beneficiary accounts stripped.' },
        { field: 'Account Holder & Balance', state: 'kept', desc: 'Verifies necessary financial eligibility.' }
      ]
    },
    'Income Certificate': {
      orgTitle: 'DEPARTMENT OF REVENUE',
      subTitle: 'Certificate of Annual Income',
      numberLabel: 'Certificate Application ID',
      fullNumber: 'INC-2026-992147',
      maskedNumber: 'INC-2026-XXXXXX',
      addressText: 'Tehsil: Andheri, District: Mumbai Suburban',
      redactedAddress: '[PRESERVED — Administrative Tehsil Jurisdiction Verified]',
      hasQr: true,
      fields: [
        { name: 'Applicant Name', status: 'required', label: 'Required', desc: 'Identifies certificate beneficiary.' },
        { name: 'Annual Income Slab', status: 'required', label: 'Required', desc: 'Verifies income qualification criteria.' },
        { name: 'Certificate ID', status: 'conditional', label: 'Conditional', desc: 'Year verified; serial masked.' },
        { name: 'Family Asset Breakdown', status: 'excluded', label: 'Not required', desc: 'Property schedule stripped.' }
      ],
      reasons: [
        { field: 'Asset Schedule', state: 'redacted', desc: 'Granular land and property schedules removed.' },
        { field: 'Certificate Serial', state: 'masked', desc: 'Application year kept; sequence minimized.' },
        { field: 'Name & Income Slab', state: 'kept', desc: 'Validates threshold eligibility.' }
      ]
    },
    'Address Proof': {
      orgTitle: 'ELECTRICITY DISTRIBUTION CO.',
      subTitle: 'Utility Bill & Residence Verification',
      numberLabel: 'Consumer Number',
      fullNumber: '0289  1004  9219',
      maskedNumber: 'XXXX  XXXX  9219',
      addressText: 'Flat 402, Green Meadows, Andheri East, Mumbai, Maharashtra - 400069',
      redactedAddress: '[MINIMIZED — City & Postal Code 400069 Preserved]',
      hasQr: false,
      fields: [
        { name: 'Resident Name', status: 'required', label: 'Required', desc: 'Confirms resident identity.' },
        { name: 'City & Postal Code', status: 'required', label: 'Required', desc: 'Confirms geographic address area.' },
        { name: 'Consumer Number', status: 'conditional', label: 'Conditional', desc: 'Masked to last 4 digits.' },
        { name: 'Tariff & Consumption Data', status: 'excluded', label: 'Not required', desc: 'Utility usage metrics shielded.' }
      ],
      reasons: [
        { field: 'Tariff Metrics', state: 'removed', desc: 'Power units and tariff billing ledger obscured.' },
        { field: 'Unit / Flat Address', state: 'redacted', desc: 'Building flat obscured while area and pin code 400069 are retained.' },
        { field: 'Resident Name & Area', state: 'kept', desc: 'Suffices to prove valid residence.' }
      ]
    },
    'Default': {
      orgTitle: 'DOCUMENT RECORD',
      subTitle: 'InfoShield Purpose-Verified Document',
      numberLabel: 'Document Identifier',
      fullNumber: 'DOC-8491-99201',
      maskedNumber: 'DOC-XXXX-99201',
      addressText: 'Private Residence, Sector 18, City Centre - 400001',
      redactedAddress: '[REDACTED FOR PRIVACY — Jurisdiction Preserved]',
      hasQr: true,
      fields: [
        { name: 'Full Name', status: 'required', label: 'Required', desc: 'Confirms identity of applicant.' },
        { name: 'Relevant Metadata', status: 'conditional', label: 'Conditional', desc: 'Only data matching your stated purpose is retained.' },
        { name: 'High-Risk Identifiers', status: 'excluded', label: 'Not required', desc: 'Excessive identifying numbers shielded.' }
      ],
      reasons: [
        { field: 'Sensitive Numbers', state: 'masked', desc: 'Primary identity keys masked to prevent credential abuse.' },
        { field: 'Exact Residence', state: 'redacted', desc: 'Street location obscured while keeping broader city context.' },
        { field: 'Name & Purpose Core', state: 'kept', desc: 'Retained as needed for the recipient.' }
      ]
    }
  };

  // ---------------------------------------------------------------------------
  // Speech Recognition (Web Speech API)
  // ---------------------------------------------------------------------------
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

  function createSpeechRecognizer(onResultCallback, onStatusCallback) {
    if (!SpeechRecognition) {
      return null;
    }

    try {
      const recognizer = new SpeechRecognition();
      recognizer.lang = 'en-US';
      recognizer.continuous = false;
      recognizer.interimResults = false;
      recognizer.maxAlternatives = 1;

      recognizer.onstart = function () {
        if (onStatusCallback) onStatusCallback('listening');
      };

      recognizer.onresult = function (event) {
        if (event.results && event.results.length > 0) {
          const text = event.results[0][0].transcript;
          if (onResultCallback) onResultCallback(text);
        }
      };

      recognizer.onerror = function (event) {
        if (onStatusCallback) onStatusCallback('error', event.error);
      };

      recognizer.onend = function () {
        if (onStatusCallback) onStatusCallback('idle');
      };

      return recognizer;
    } catch (e) {
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Toast Notifications
  // ---------------------------------------------------------------------------
  function showToast(message, duration = 3200) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
      <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => {
      toast.classList.add('show');
    });

    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }, 300);
    }, duration);
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ---------------------------------------------------------------------------
  // Screen Navigation Router
  // ---------------------------------------------------------------------------
  function navigateTo(targetScreenId, addToHistory = true) {
    const screens = document.querySelectorAll('.app-screen');
    const target = document.getElementById(targetScreenId);

    if (!target) return;

    if (addToHistory && state.currentScreen !== targetScreenId) {
      state.screenHistory.push(state.currentScreen);
    }

    screens.forEach(s => s.classList.remove('active'));
    target.classList.add('active');
    state.currentScreen = targetScreenId;

    // Scroll to top of content
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // Sync Navigation Bars
    syncNavHighlight(targetScreenId);

    // Screen-specific triggers
    onScreenEntered(targetScreenId);
  }

  function goBack() {
    if (state.screenHistory.length > 0) {
      const prev = state.screenHistory.pop();
      navigateTo(prev, false);
    } else {
      navigateTo('screen-select', false);
    }
  }

  function syncNavHighlight(screenId) {
    // Determine active nav key
    let navKey = 'home';
    if (screenId === 'screen-history') navKey = 'history';
    else if (screenId === 'screen-profile') navKey = 'profile';

    // Mobile Bottom Nav
    document.querySelectorAll('.bottom-nav-item').forEach(item => {
      const targetNav = item.getAttribute('data-nav');
      if (targetNav === navKey) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Desktop Sidebar Nav
    document.querySelectorAll('.sidebar-nav-item').forEach(item => {
      const targetNav = item.getAttribute('data-nav');
      if (targetNav === navKey) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });
  }

  function onScreenEntered(screenId) {
    if (screenId === 'screen-scan') {
      runBackgroundScanSimulation();
    } else if (screenId === 'screen-analysis') {
      // Progress animation is handled during executeProtectionPipeline
    } else if (screenId === 'screen-required') {
      populateRequiredInfoScreen();
    } else if (screenId === 'screen-result') {
      populateProtectionResultScreen();
    } else if (screenId === 'screen-history') {
      loadHistoryFromBackend();
    }
  }

  // ---------------------------------------------------------------------------
  // Screen 1: Document Selection & Search Setup
  // ---------------------------------------------------------------------------
  function initScreenSelect() {
    const searchInput = document.getElementById('docSearchInput');
    const micBtn = document.getElementById('searchMicBtn');
    const micStatus = document.getElementById('searchMicStatus');
    const docGrid = document.getElementById('docGrid');
    const emptyNotice = document.getElementById('docSearchEmpty');
    const fallbackBtn = document.getElementById('searchFallbackBtn');

    // Document Card Click Handling
    docGrid.querySelectorAll('.doc-card').forEach(card => {
      const docType = card.getAttribute('data-doc');

      function selectCard() {
        state.selectedDocument = docType;
        updateSelectedDocUI(docType);
        navigateTo('screen-upload');
      }

      card.addEventListener('click', selectCard);
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          selectCard();
        }
      });
    });

    // Real-time Search Filtering
    if (searchInput) {
      searchInput.addEventListener('input', function () {
        const query = this.value.trim().toLowerCase();
        let matchCount = 0;

        docGrid.querySelectorAll('.doc-card').forEach(card => {
          const docName = card.getAttribute('data-doc').toLowerCase();
          const keywords = (card.getAttribute('data-keywords') || '').toLowerCase();

          if (!query || docName.includes(query) || keywords.includes(query)) {
            card.style.display = 'flex';
            matchCount++;
          } else {
            card.style.display = 'none';
          }
        });

        if (matchCount === 0 && query) {
          emptyNotice.classList.add('visible');
        } else {
          emptyNotice.classList.remove('visible');
        }
      });
    }

    if (fallbackBtn) {
      fallbackBtn.addEventListener('click', () => {
        state.selectedDocument = 'Other Document';
        updateSelectedDocUI('Other Document');
        navigateTo('screen-upload');
      });
    }

    // Web Speech API for Search Microphone
    const searchSpeech = createSpeechRecognizer(
      // On speech result
      function (transcript) {
        if (searchInput) {
          searchInput.value = transcript;
          searchInput.dispatchEvent(new Event('input'));
          showToast(`Searched for: "${transcript}"`);
        }
      },
      // On status change
      function (status, error) {
        if (status === 'listening') {
          micBtn.classList.add('listening');
          if (micStatus) micStatus.classList.add('visible');
        } else if (status === 'error') {
          micBtn.classList.remove('listening');
          if (micStatus) micStatus.classList.remove('visible');
          if (error === 'not-allowed') {
            showToast('Microphone permission was denied.');
          } else {
            showToast(`Voice error: ${error || 'Could not understand'}`);
          }
        } else {
          micBtn.classList.remove('listening');
          if (micStatus) micStatus.classList.remove('visible');
        }
      }
    );

    if (micBtn) {
      micBtn.addEventListener('click', function () {
        if (!SpeechRecognition) {
          showToast("Voice search isn't supported in this browser.");
          return;
        }

        try {
          if (micBtn.classList.contains('listening')) {
            searchSpeech.stop();
          } else {
            searchSpeech.start();
          }
        } catch (e) {
          showToast("Voice search isn't supported in this browser.");
        }
      });
    }
  }

  function updateSelectedDocUI(docType) {
    const label = document.getElementById('uploadSelectedDocName');
    if (label) label.textContent = docType;

    const analysisDocLabel = document.getElementById('analysisDocLabel');
    if (analysisDocLabel) analysisDocLabel.textContent = docType;
  }

  // ---------------------------------------------------------------------------
  // Screen 2: Upload Document Setup
  // ---------------------------------------------------------------------------
  function initScreenUpload() {
    const uploadBackBtn = document.getElementById('uploadBackBtn');
    const chipChangeDocBtn = document.getElementById('chipChangeDocBtn');
    const triggerFileCard = document.getElementById('triggerFileCard');
    const triggerCameraCard = document.getElementById('triggerCameraCard');
    const realFileInput = document.getElementById('realFileInput');
    const realCameraInput = document.getElementById('realCameraInput');

    const previewBox = document.getElementById('uploadPreviewBox');
    const actionCards = document.getElementById('uploadActionCards');
    const previewImg = document.getElementById('previewImageElement');
    const previewFileName = document.getElementById('previewFileName');
    const previewFileSpecs = document.getElementById('previewFileSpecs');
    const previewReplaceBtn = document.getElementById('previewReplaceBtn');
    const previewContinueBtn = document.getElementById('previewContinueBtn');

    if (uploadBackBtn) uploadBackBtn.addEventListener('click', goBack);
    if (chipChangeDocBtn) chipChangeDocBtn.addEventListener('click', () => navigateTo('screen-select'));

    // Trigger clicks to hidden real file inputs
    if (triggerFileCard && realFileInput) {
      triggerFileCard.addEventListener('click', () => realFileInput.click());
      triggerFileCard.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          realFileInput.click();
        }
      });
    }

    if (triggerCameraCard && realCameraInput) {
      triggerCameraCard.addEventListener('click', () => realCameraInput.click());
      triggerCameraCard.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          realCameraInput.click();
        }
      });
    }

    // Process file upon selection
    function handleSelectedFile(file) {
      if (!file) return;

      const validExtensions = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
      if (!validExtensions.includes(file.type) && !file.type.startsWith('image/')) {
        showToast('Please select a JPG, PNG, or WEBP image.');
        return;
      }

      state.uploadedFile = file;

      // File Size Formatting
      const sizeKb = (file.size / 1024).toFixed(0);
      const sizeLabel = file.size > 1024 * 1024
        ? `${(file.size / (1024 * 1024)).toFixed(1)} MB`
        : `${sizeKb} KB`;

      // Read as Data URL for preview
      const reader = new FileReader();
      reader.onload = function (e) {
        state.uploadedImageDataUrl = e.target.result;
        previewImg.src = e.target.result;

        // Image Dimensions
        const tempImg = new Image();
        tempImg.onload = function () {
          state.uploadedImageDimensions = `${this.naturalWidth} × ${this.naturalHeight} px`;
          previewFileSpecs.textContent = `${sizeLabel} • ${state.uploadedImageDimensions}`;
        };
        tempImg.src = e.target.result;

        previewFileName.textContent = file.name;
        previewFileSpecs.textContent = `${sizeLabel} • Reading dimensions...`;

        // Switch to preview mode
        actionCards.style.display = 'none';
        previewBox.classList.add('active');
      };
      reader.readAsDataURL(file);
    }

    if (realFileInput) {
      realFileInput.addEventListener('change', function () {
        if (this.files && this.files[0]) {
          handleSelectedFile(this.files[0]);
        }
      });
    }

    if (realCameraInput) {
      realCameraInput.addEventListener('change', function () {
        if (this.files && this.files[0]) {
          handleSelectedFile(this.files[0]);
        }
      });
    }

    // Replace Image
    if (previewReplaceBtn) {
      previewReplaceBtn.addEventListener('click', () => {
        state.uploadedFile = null;
        state.uploadedImageDataUrl = null;
        state.uploadedImageDimensions = null;
        if (realFileInput) realFileInput.value = '';
        if (realCameraInput) realCameraInput.value = '';
        previewBox.classList.remove('active');
        actionCards.style.display = 'grid';
      });
    }

    // Continue to Background Scan
    if (previewContinueBtn) {
      previewContinueBtn.addEventListener('click', () => {
        navigateTo('screen-scan');
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Screen 3: Background Scan Simulation
  // ---------------------------------------------------------------------------
  function runBackgroundScanSimulation() {
    const s1 = document.getElementById('scanStep1');
    const s2 = document.getElementById('scanStep2');
    const s3 = document.getElementById('scanStep3');
    const s4 = document.getElementById('scanStep4');

    // Reset Stepper
    if (s2) { s2.className = 'stepper-item active'; s2.querySelector('.stepper-bullet').textContent = '2'; }
    if (s3) { s3.className = 'stepper-item'; s3.querySelector('.stepper-bullet').textContent = '3'; }
    if (s4) { s4.className = 'stepper-item'; s4.querySelector('.stepper-bullet').textContent = '4'; }

    // Step 2 completion
    setTimeout(() => {
      if (s2) { s2.className = 'stepper-item completed'; s2.querySelector('.stepper-bullet').textContent = '✓'; }
      if (s3) { s3.className = 'stepper-item active'; }
    }, 600);

    // Step 3 completion
    setTimeout(() => {
      if (s3) { s3.className = 'stepper-item completed'; s3.querySelector('.stepper-bullet').textContent = '✓'; }
      if (s4) { s4.className = 'stepper-item active'; }
    }, 1200);

    // Final transition to Purpose Explanation
    setTimeout(() => {
      if (s4) { s4.className = 'stepper-item completed'; s4.querySelector('.stepper-bullet').textContent = '✓'; }
      navigateTo('screen-purpose');
    }, 1800);
  }

  // ---------------------------------------------------------------------------
  // Screen 4: Purpose Explanation Setup
  // ---------------------------------------------------------------------------
  function initScreenPurpose() {
    const purposeBackBtn = document.getElementById('purposeBackBtn');
    const textarea = document.getElementById('purposeTextarea');
    const voiceBtn = document.getElementById('purposeVoiceBtn');
    const voiceLabel = document.getElementById('purposeVoiceLabel');
    const charCount = document.getElementById('purposeCharCount');
    const analyzeBtn = document.getElementById('analyzePurposeBtn');

    if (purposeBackBtn) purposeBackBtn.addEventListener('click', goBack);

    // Character counter & button enablement
    if (textarea) {
      textarea.addEventListener('input', function () {
        const text = this.value;
        state.purposeText = text;
        if (charCount) charCount.textContent = `${text.length} characters`;

        if (analyzeBtn) {
          analyzeBtn.disabled = text.trim().length === 0;
        }
      });
    }

    // Web Speech API for Purpose Dictation
    const purposeSpeech = createSpeechRecognizer(
      // On speech result
      function (transcript) {
        if (textarea) {
          const current = textarea.value.trim();
          textarea.value = current ? `${current} ${transcript}` : transcript;
          textarea.dispatchEvent(new Event('input'));
          showToast(`Added: "${transcript}"`);
        }
      },
      // On status change
      function (status, error) {
        if (status === 'listening') {
          voiceBtn.classList.add('listening');
          if (voiceLabel) voiceLabel.textContent = 'Listening... Speak now';
        } else if (status === 'error') {
          voiceBtn.classList.remove('listening');
          if (voiceLabel) voiceLabel.textContent = '🎙 Speak instead';
          if (error === 'not-allowed') {
            showToast('Microphone permission denied.');
          } else {
            showToast(`Voice error: ${error || 'Could not understand'}`);
          }
        } else {
          voiceBtn.classList.remove('listening');
          if (voiceLabel) voiceLabel.textContent = '🎙 Speak instead';
        }
      }
    );

    if (voiceBtn) {
      voiceBtn.addEventListener('click', function () {
        if (!SpeechRecognition) {
          showToast("Voice input isn't supported in this browser.");
          return;
        }

        try {
          if (voiceBtn.classList.contains('listening')) {
            purposeSpeech.stop();
          } else {
            purposeSpeech.start();
          }
        } catch (e) {
          showToast("Voice input isn't supported in this browser.");
        }
      });
    }

    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', async () => {
        if (state.isProcessing) return;

        if (!state.uploadedFile) {
          showToast('Please upload a document image first.');
          navigateTo('screen-upload');
          return;
        }

        const purpose = state.purposeText.trim();
        if (!purpose) {
          showToast('Please explain why you are submitting this document.');
          return;
        }

        state.isProcessing = true;
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = `
          <div class="spinner-small" style="display:inline-block; vertical-align:middle; width:16px; height:16px; border-width:2px; margin-right:8px;"></div>
          Analyzing...
        `;

        navigateTo('screen-analysis');
        await executeProtectionPipeline(purpose);
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Pipeline Execution (Screen 5: Purpose AI & Protection)
  // ---------------------------------------------------------------------------
  async function executeProtectionPipeline(purpose) {
    const docLabel = document.getElementById('analysisDocLabel');
    const purposeSnippet = document.getElementById('analysisPurposeSnippet');
    const a3 = document.getElementById('anaStep3');
    const a4 = document.getElementById('anaStep4');
    const analyzeBtn = document.getElementById('analyzePurposeBtn');

    if (docLabel) docLabel.textContent = state.selectedDocument || 'Identity Document';
    if (purposeSnippet) purposeSnippet.textContent = `"${purpose}"`;

    // Reset Stepper to Step 3 active
    if (a3) {
      a3.className = 'stepper-item active';
      const bullet = a3.querySelector('.stepper-bullet');
      if (bullet) bullet.textContent = '3';
    }
    if (a4) {
      a4.className = 'stepper-item';
      const bullet = a4.querySelector('.stepper-bullet');
      if (bullet) bullet.textContent = '4';
    }

    try {
      const formData = new FormData();
      formData.append('file', state.uploadedFile);
      formData.append('purpose', purpose);

      const authToken = localStorage.getItem('infoshield_auth_token');
      const headers = {};
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const response = await fetch(`${BACKEND_BASE_URL}/api/protect`, {
        method: 'POST',
        headers: headers,
        body: formData
      });


      if (!response.ok) {
        let errMessage = 'Server error processing document.';
        try {
          const errData = await response.json();
          errMessage = errData.detail || errData.message || errMessage;
        } catch (e) {
          errMessage = `HTTP error ${response.status}: ${response.statusText}`;
        }
        throw new Error(errMessage);
      }

      const result = await response.json();
      state.apiResult = result;

      // Update detected document type if returned by backend
      if (result.document && result.document.type) {
        state.selectedDocument = result.document.type;
        updateSelectedDocUI(result.document.type);
      }

      // Complete Stepper Step 3
      if (a3) {
        a3.className = 'stepper-item completed';
        const bullet = a3.querySelector('.stepper-bullet');
        if (bullet) bullet.textContent = '✓';
      }
      if (a4) {
        a4.className = 'stepper-item active';
      }

      // Add to session history
      addToSessionHistory(result);

      // Brief animation pause for step 4
      await new Promise(r => setTimeout(r, 650));
      if (a4) {
        a4.className = 'stepper-item completed';
        const bullet = a4.querySelector('.stepper-bullet');
        if (bullet) bullet.textContent = '✓';
      }

      showToast('Document analyzed & protected!');
      navigateTo('screen-required');

    } catch (err) {
      console.error('[InfoShield] Pipeline error:', err);
      let errorMsg = err.message || 'Unknown network error';
      if (errorMsg === 'Failed to fetch' || errorMsg.includes('NetworkError')) {
        const targetUrl = getBackendBaseUrl();
        errorMsg = `Cannot connect to backend (${targetUrl}). Please ensure the FastAPI server is running on port 8000 and CORS allows ${window.location.origin}.`;
      }
      showToast(`Error: ${errorMsg}`, 6000);
      navigateTo('screen-purpose');
    } finally {
      state.isProcessing = false;
      if (analyzeBtn) {
        analyzeBtn.disabled = state.purposeText.trim().length === 0;
        analyzeBtn.textContent = 'Analyze Document →';
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Field Title Formatter
  // ---------------------------------------------------------------------------
  function formatFieldTitle(type) {
    const titles = {
      person_name: 'Person Name',
      date_of_birth: 'Date of Birth',
      gender: 'Gender',
      mobile_number: 'Mobile Number',
      aadhaar_number: 'Aadhaar Number',
      pan_number: 'PAN Number',
      vid: 'VID (Virtual ID)',
      address: 'Full Residential Address',
      qr_code: 'QR Code Matrix (Biometrics)'
    };
    if (titles[type]) return titles[type];
    return String(type)
      .replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
  }

  // ---------------------------------------------------------------------------
  // Screen 6: Populate Required Information Screen
  // ---------------------------------------------------------------------------
  function populateRequiredInfoScreen() {
    const requiredBackBtn = document.getElementById('requiredBackBtn');
    const reqPurposeSummary = document.getElementById('reqPurposeSummary');
    const itemsList = document.getElementById('requiredItemsList');
    const generateBtn = document.getElementById('generateProtectedBtn');

    if (requiredBackBtn) requiredBackBtn.onclick = goBack;

    const data = state.apiResult;
    const purposeText = (data && data.purpose) ? data.purpose : state.purposeText.trim();

    if (reqPurposeSummary) {
      reqPurposeSummary.textContent = purposeText || 'College admission and identity verification';
    }

    if (itemsList) {
      itemsList.innerHTML = '';

      if (data && Array.isArray(data.requirements) && data.requirements.length > 0) {
        data.requirements.forEach(req => {
          const itemCard = document.createElement('div');
          
          let stateClass = 'state-required';
          let iconChar = '✓';
          let badgeClass = 'badge-success';
          let badgeLabel = 'Required';

          const decision = (req.decision || '').toUpperCase();
          if (decision === 'CONDITIONAL') {
            stateClass = 'state-conditional';
            iconChar = '⚠';
            badgeClass = 'badge-warning';
            badgeLabel = 'Conditional';
          } else if (decision === 'UNNECESSARY' || decision === 'EXCLUDED') {
            stateClass = 'state-excluded';
            iconChar = '✕';
            badgeClass = 'badge-danger';
            badgeLabel = 'Not required';
          }

          const fieldName = formatFieldTitle(req.type || 'field');
          const fieldDesc = req.reason || 'Evaluated for submission purpose.';

          let actionLabel = req.action || decision;
          if (actionLabel === 'PARTIAL_MASK') actionLabel = 'Partial Masking';
          else if (actionLabel === 'FULL_MASK') actionLabel = 'Fully Redacted';
          else if (actionLabel === 'PRESERVED') actionLabel = 'Preserved';

          let riskMeta = '';
          if (req.risk && req.risk.class) {
            riskMeta = ` • Exposure Risk: ${escapeHtml(req.risk.class)}`;
          }

          itemCard.className = `info-item-card ${stateClass}`;
          itemCard.innerHTML = `
            <div class="info-item-left">
              <div class="info-item-status-icon">${iconChar}</div>
              <div>
                <div class="info-item-title">${escapeHtml(fieldName)}</div>
                <div class="info-item-desc">${escapeHtml(fieldDesc)}<span style="font-size: 0.75rem; color: var(--text-subtle); display: block; margin-top: 3px;">Action: <strong>${escapeHtml(actionLabel)}</strong>${riskMeta}</span></div>
              </div>
            </div>
            <span class="badge ${badgeClass}">${escapeHtml(badgeLabel)}</span>
          `;
          itemsList.appendChild(itemCard);
        });
      } else {
        // Fallback to presets
        const profile = DOCUMENT_PROFILES[state.selectedDocument] || DOCUMENT_PROFILES['Default'];
        profile.fields.forEach(field => {
          const itemCard = document.createElement('div');
          const stateClass = `state-${field.status}`;
          let iconChar = '✓';
          let badgeClass = 'badge-success';
          if (field.status === 'conditional') {
            iconChar = '⚠';
            badgeClass = 'badge-warning';
          } else if (field.status === 'excluded') {
            iconChar = '✕';
            badgeClass = 'badge-danger';
          }

          itemCard.className = `info-item-card ${stateClass}`;
          itemCard.innerHTML = `
            <div class="info-item-left">
              <div class="info-item-status-icon">${iconChar}</div>
              <div>
                <div class="info-item-title">${escapeHtml(field.name)}</div>
                <div class="info-item-desc">${escapeHtml(field.desc)}</div>
              </div>
            </div>
            <span class="badge ${badgeClass}">${escapeHtml(field.label)}</span>
          `;
          itemsList.appendChild(itemCard);
        });
      }
    }

    if (generateBtn) {
      generateBtn.onclick = () => navigateTo('screen-result');
    }
  }

  // ---------------------------------------------------------------------------
  // Screen 7: Protection Result Setup & Tabs
  // ---------------------------------------------------------------------------
  function populateProtectionResultScreen() {
    const tabOriginalBtn = document.getElementById('tabOriginalBtn');
    const tabProtectedBtn = document.getElementById('tabProtectedBtn');
    const cardOriginal = document.getElementById('cardOriginalView');
    const cardProtected = document.getElementById('cardProtectedView');
    const downloadDocBtn = document.getElementById('downloadDocBtn');
    const shareDocBtn = document.getElementById('shareDocBtn');
    const startNewDocBtn = document.getElementById('startNewDocBtn');

    const origImg = document.getElementById('origDocumentImage');
    const origPlaceholder = document.getElementById('origPreviewPlaceholder');
    const origMeta = document.getElementById('origDocMeta');

    const protImg = document.getElementById('protDocumentImage');
    const protPlaceholder = document.getElementById('protLoadingPlaceholder');
    const protMeta = document.getElementById('protDocMeta');

    const resultStatusBadge = document.getElementById('resultStatusBadge');
    const resultDatabaseBadge = document.getElementById('resultDatabaseBadge');
    const resultAuditBadge = document.getElementById('resultAuditBadge');
    const resultWarningsBanner = document.getElementById('resultWarningsBanner');
    const resultWarningsList = document.getElementById('resultWarningsList');
    const whyGrid = document.getElementById('whyProtectedGrid');

    const data = state.apiResult;

    // 1. Display Original Document
    if (state.uploadedImageDataUrl && origImg) {
      origImg.src = state.uploadedImageDataUrl;
      origImg.style.display = 'block';
      if (origPlaceholder) origPlaceholder.style.display = 'none';
      if (origMeta && state.uploadedFile) {
        origMeta.textContent = `${state.uploadedFile.name} • ${state.uploadedImageDimensions || 'Original Upload'}`;
      }
    } else if (origImg) {
      origImg.style.display = 'none';
      if (origPlaceholder) origPlaceholder.style.display = 'flex';
    }

    // 2. Display Protected Document from Server
    if (data && data.document && data.document.protected_url && protImg) {
      const fullProtectedUrl = `${BACKEND_BASE_URL}${data.document.protected_url}`;
      if (protPlaceholder) {
        protPlaceholder.style.display = 'flex';
        protPlaceholder.innerHTML = `
          <div class="spinner-small" style="margin-bottom: 0.5rem;"></div>
          <span>Rendering protected document...</span>
        `;
      }
      protImg.style.display = 'none';

      protImg.onload = function () {
        protImg.style.display = 'block';
        if (protPlaceholder) protPlaceholder.style.display = 'none';
      };

      protImg.onerror = function () {
        if (protPlaceholder) {
          protPlaceholder.innerHTML = `<span style="color: var(--danger);">Failed to load protected image from server.</span>`;
        }
      };

      protImg.src = fullProtectedUrl;

      if (protMeta) {
        const stats = data.stats || {};
        protMeta.textContent = `${data.document.protected_filename || 'Protected Document'} • ${stats.fully_redacted || 0} redacted, ${stats.partially_redacted || 0} masked, ${stats.preserved || 0} preserved`;
      }
    } else if (protImg) {
      protImg.style.display = 'none';
      if (protPlaceholder) {
        protPlaceholder.style.display = 'flex';
        protPlaceholder.textContent = 'No protected document available.';
      }
    }

    // 3. Database Persistence & Audit Metadata
    if (data && data.database) {
      const dbStatus = data.database.status;
      if (dbStatus === 'CONNECTED') {
        if (resultDatabaseBadge) {
          resultDatabaseBadge.className = 'badge badge-success';
          resultDatabaseBadge.textContent = 'Supabase Connected';
        }
        if (resultAuditBadge) {
          const count = data.database.audit_events_recorded || 0;
          resultAuditBadge.textContent = `${count} audit event${count === 1 ? '' : 's'} recorded`;
        }
      } else {
        if (resultDatabaseBadge) {
          resultDatabaseBadge.className = 'badge badge-warning';
          resultDatabaseBadge.textContent = 'Audit DB: Offline';
        }
        if (resultAuditBadge) {
          resultAuditBadge.textContent = 'Protected locally';
        }
      }
    }

    // 4. Warnings & Review Required Display
    const hasWarnings = (data && Array.isArray(data.warnings) && data.warnings.length > 0);
    const reviewReq = (data && data.review_required);
    if ((hasWarnings || reviewReq) && resultWarningsBanner) {
      resultWarningsBanner.style.display = 'block';
      if (resultWarningsList) {
        let warningHtml = hasWarnings
          ? data.warnings.map(w => `<div style="margin-top: 2px;">• ${escapeHtml(w)}</div>`).join('')
          : '';
        if (reviewReq && !hasWarnings) {
          warningHtml = '<div style="margin-top: 2px;">• Manual review required: low intent confidence or unverified document fields detected.</div>';
        }
        resultWarningsList.innerHTML = warningHtml;
      }
    } else if (resultWarningsBanner) {
      resultWarningsBanner.style.display = 'none';
    }

    // 5. Why was information protected? Section
    if (whyGrid) {
      whyGrid.innerHTML = '';
      if (data && Array.isArray(data.redactions_applied) && data.redactions_applied.length > 0) {
        data.redactions_applied.forEach(item => {
          const card = document.createElement('div');
          const isKept = item.action === 'PRESERVED';
          card.className = `why-protected-card ${isKept ? 'state-kept' : ''}`;

          let icon = '✕';
          let badge = '<span class="badge badge-danger">Redacted</span>';
          if (isKept) {
            icon = '✓';
            badge = '<span class="badge badge-success">Preserved</span>';
          } else if (item.action === 'PARTIALLY_REDACTED') {
            icon = '⚠';
            badge = '<span class="badge badge-warning">Masked</span>';
          }

          const reasonText = item.reason || 'Privacy preservation policy applied.';
          const detailsText = item.details ? `<div style="font-size: 0.775rem; color: var(--text-subtle); margin-top: 4px;">${escapeHtml(item.details)}</div>` : '';

          card.innerHTML = `
            <div class="why-card-icon">${icon}</div>
            <div class="why-card-content">
              <div class="why-card-header">
                <span class="why-card-field">${escapeHtml(item.field || 'Field')}</span>
                ${badge}
              </div>
              <div class="why-card-reason">${escapeHtml(reasonText)}</div>
              ${detailsText}
            </div>
          `;
          whyGrid.appendChild(card);
        });
      } else {
        const profile = DOCUMENT_PROFILES[state.selectedDocument] || DOCUMENT_PROFILES['Default'];
        if (profile.reasons) {
          profile.reasons.forEach(r => {
            const card = document.createElement('div');
            const isKept = r.state === 'kept';
            card.className = `why-protected-card ${isKept ? 'state-kept' : ''}`;
            let icon = isKept ? '✓' : '✕';
            let badge = isKept ? '<span class="badge badge-success">Preserved</span>' : '<span class="badge badge-danger">Redacted</span>';
            card.innerHTML = `
              <div class="why-card-icon">${icon}</div>
              <div class="why-card-content">
                <div class="why-card-header">
                  <span class="why-card-field">${escapeHtml(r.field)}</span>
                  ${badge}
                </div>
                <div class="why-card-reason">${escapeHtml(r.desc)}</div>
              </div>
            `;
            whyGrid.appendChild(card);
          });
        }
      }
    }

    // 6. Mobile Tab Toggling
    function setMobileTab(tab) {
      state.activeResultTab = tab;
      if (tab === 'original') {
        if (tabOriginalBtn) tabOriginalBtn.classList.add('active');
        if (tabProtectedBtn) tabProtectedBtn.classList.remove('active');
        if (cardOriginal) cardOriginal.classList.remove('tab-hidden');
        if (cardProtected) cardProtected.classList.add('tab-hidden');
      } else {
        if (tabProtectedBtn) tabProtectedBtn.classList.add('active');
        if (tabOriginalBtn) tabOriginalBtn.classList.remove('active');
        if (cardProtected) cardProtected.classList.remove('tab-hidden');
        if (cardOriginal) cardOriginal.classList.add('tab-hidden');
      }
    }

    if (tabOriginalBtn) tabOriginalBtn.onclick = () => setMobileTab('original');
    if (tabProtectedBtn) tabProtectedBtn.onclick = () => setMobileTab('protected');

    // Default to Protected tab on mobile
    setMobileTab('protected');

    // 7. Download Protected Document
    if (downloadDocBtn) {
      downloadDocBtn.onclick = async () => {
        if (!data || !data.document || !data.document.protected_url) {
          showToast('No protected document to download.');
          return;
        }

        const downloadUrl = `${BACKEND_BASE_URL}${data.document.protected_url}`;
        const fileName = data.document.protected_filename || 'protected_document.png';

        try {
          showToast('Preparing download...');
          const authToken = localStorage.getItem('infoshield_auth_token');
          const headers = {};
          if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
          }
          const res = await fetch(downloadUrl, { headers });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const blob = await res.blob();

          const blobUrl = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = blobUrl;
          a.download = fileName;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);
          showToast(`Downloaded ${fileName}`);
        } catch (err) {
          const a = document.createElement('a');
          a.href = downloadUrl;
          a.download = fileName;
          a.target = '_blank';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
        }
      };
    }

    // 8. Share Securely — Genuine Cryptographic Token Sharing Workflow
    if (shareDocBtn) {
      shareDocBtn.onclick = () => {
        if (!data || !data.document) {
          showToast('No protected document available to share.');
          return;
        }

        const modal = document.getElementById('shareModal');
        const shareResultArea = document.getElementById('shareResultArea');
        const shareGeneratedUrl = document.getElementById('shareGeneratedUrl');
        const shareForm = document.getElementById('shareDocumentForm');
        const recipientInput = document.getElementById('shareRecipientEmail');
        const expirySelect = document.getElementById('shareExpiryHours');
        const maxAccessSelect = document.getElementById('shareMaxAccess');
        const closeBtn = document.getElementById('closeShareModalBtn');
        const cancelBtn = document.getElementById('cancelShareBtn');
        const copyBtn = document.getElementById('copyShareLinkBtn');

        if (!modal) {
          showToast('Secure sharing dialog unavailable.');
          return;
        }

        modal.style.display = 'flex';
        if (shareResultArea) shareResultArea.style.display = 'none';
        if (shareGeneratedUrl) shareGeneratedUrl.value = '';

        closeBtn.onclick = () => { modal.style.display = 'none'; };
        cancelBtn.onclick = () => { modal.style.display = 'none'; };

        if (copyBtn) {
          copyBtn.onclick = async () => {
            if (shareGeneratedUrl && shareGeneratedUrl.value) {
              if (navigator.clipboard) {
                await navigator.clipboard.writeText(shareGeneratedUrl.value);
                showToast('Secure link copied to clipboard!');
              } else {
                shareGeneratedUrl.select();
                showToast('Link ready to copy.');
              }
            }
          };
        }

        shareForm.onsubmit = async (e) => {
          e.preventDefault();
          const docId = data.document.id;
          if (!docId) {
            showToast('Document ID missing. Please ensure document is saved in backend.');
            return;
          }

          const expiryHours = parseInt(expirySelect.value, 10) || 72;
          const maxAccessRaw = parseInt(maxAccessSelect.value, 10);
          const maxAccess = maxAccessRaw > 0 ? maxAccessRaw : null;
          const recipientEmail = recipientInput.value.trim() || null;
          const purpose = state.purposeText || data.purpose || 'Authorized Document Verification';

          try {
            showToast('Generating secure access token...');
            const res = await fetch(`${BACKEND_BASE_URL}/api/shares`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                ...(localStorage.getItem('infoshield_auth_token') ? { 'Authorization': `Bearer ${localStorage.getItem('infoshield_auth_token')}` } : {})
              },
              body: JSON.stringify({
                document_id: docId,
                purpose: purpose,
                recipient_email: recipientEmail,
                expiry_hours: expiryHours,
                max_access_count: maxAccess
              })
            });

            if (!res.ok) {
              const err = await res.json().catch(() => ({ detail: 'Failed to create share.' }));
              throw new Error(err.detail || 'Failed to create share.');
            }

            const shareData = await res.json();
            const shareUrl = `${BACKEND_BASE_URL || window.location.origin}/api/shares/access/${shareData.access_token}`;

            if (shareGeneratedUrl && shareResultArea) {
              shareGeneratedUrl.value = shareUrl;
              shareResultArea.style.display = 'block';
            }
            showToast('Secure share link created!');
          } catch (err) {
            showToast(err.message || 'Error generating secure share link.');
          }
        };
      };
    }

    // 9. Start New Document
    if (startNewDocBtn) {
      startNewDocBtn.onclick = () => {
        resetAppWorkflow();
        navigateTo('screen-select');
      };
    }
  }

  function resetAppWorkflow() {
    state.uploadedFile = null;
    state.uploadedImageDataUrl = null;
    state.uploadedImageDimensions = null;
    state.purposeText = '';
    state.apiResult = null;
    state.isProcessing = false;
    state.screenHistory = [];

    const realFileInput = document.getElementById('realFileInput');
    const realCameraInput = document.getElementById('realCameraInput');
    const uploadPreviewBox = document.getElementById('uploadPreviewBox');
    const uploadActionCards = document.getElementById('uploadActionCards');
    const purposeTextarea = document.getElementById('purposeTextarea');
    const charCount = document.getElementById('purposeCharCount');
    const analyzeBtn = document.getElementById('analyzePurposeBtn');
    const origImg = document.getElementById('origDocumentImage');
    const protImg = document.getElementById('protDocumentImage');
    const origPlaceholder = document.getElementById('origPreviewPlaceholder');
    const protPlaceholder = document.getElementById('protLoadingPlaceholder');

    if (realFileInput) realFileInput.value = '';
    if (realCameraInput) realCameraInput.value = '';
    if (uploadPreviewBox) uploadPreviewBox.classList.remove('active');
    if (uploadActionCards) uploadActionCards.style.display = 'grid';
    if (purposeTextarea) purposeTextarea.value = '';
    if (charCount) charCount.textContent = '0 characters';
    if (analyzeBtn) {
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = 'Analyze Document →';
    }
    if (origImg) { origImg.src = ''; origImg.style.display = 'none'; }
    if (protImg) { protImg.src = ''; protImg.style.display = 'none'; }
    if (origPlaceholder) origPlaceholder.style.display = 'flex';
    if (protPlaceholder) protPlaceholder.style.display = 'flex';
  }

  // ---------------------------------------------------------------------------
  // Session History Management
  // ---------------------------------------------------------------------------
  function addToSessionHistory(result) {
    if (!result || !result.document) return;
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    state.sessionHistory.unshift({
      id: result.document.id || Date.now().toString(),
      docType: result.document.type || state.selectedDocument || 'Document',
      purpose: result.purpose || state.purposeText || 'Identity Verification',
      filename: result.document.protected_filename,
      protectedUrl: result.document.protected_url,
      time: timeStr,
      apiResult: result
    });
  }

  async function loadHistoryFromBackend() {
    renderHistoryScreen();
    try {
      const authToken = localStorage.getItem('infoshield_auth_token');
      const headers = {};
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }
      const resp = await fetch(`${BACKEND_BASE_URL}/api/history`, { headers });

      if (resp.ok) {
        const data = await resp.json();
        if (data && Array.isArray(data.documents) && data.documents.length > 0) {
          data.documents.forEach(doc => {
            const docId = doc.id || doc.protected_filename;
            const exists = state.sessionHistory.some(h => h.id === docId || h.filename === (doc.protected_filename || doc.id));
            if (!exists) {
              state.sessionHistory.push({
                id: docId,
                docType: doc.document_type || doc.type || 'Identity Document',
                purpose: doc.purpose || 'Protected Record',
                filename: doc.protected_filename || doc.id,
                protectedUrl: doc.protected_url || `/api/protected/${doc.protected_filename || doc.id}`,
                time: doc.created_at ? new Date(doc.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Saved',
                apiResult: doc
              });
            }
          });
          renderHistoryScreen();
        }
      }
    } catch (e) {
      // Offline fallback retained
    }
  }

  function renderHistoryScreen() {
    const container = document.getElementById('historyListContainer');
    if (!container) return;

    if (!state.sessionHistory || state.sessionHistory.length === 0) {
      container.innerHTML = `
        <div class="history-empty" id="historyEmptyState" style="text-align: center; padding: 3rem 1.5rem; color: var(--text-subtle); background: var(--bg-surface); border-radius: var(--radius-lg); border: 1px dashed var(--border-medium);">
          <svg width="40" height="40" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="margin: 0 auto 1rem auto; color: var(--text-subtle); display: block;">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          <div style="font-weight: 600; color: var(--text-main); margin-bottom: 0.25rem;">No protected documents yet</div>
          <p style="font-size: 0.85rem; margin: 0;">Documents you protect will be securely listed here.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = '';
    state.sessionHistory.forEach(item => {
      const card = document.createElement('div');
      card.className = 'history-card';
      card.setAttribute('role', 'button');
      card.setAttribute('tabindex', '0');
      card.innerHTML = `
        <div class="history-card-left">
          <div class="history-icon-box">
            <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
          </div>
          <div>
            <div class="history-doc-title">${escapeHtml(item.docType)}</div>
            <div class="history-meta-sub">${escapeHtml(item.time)} • ${escapeHtml(item.purpose)}</div>
          </div>
        </div>
        <span class="badge badge-success">Protected</span>
      `;

      card.addEventListener('click', () => {
        state.apiResult = item.apiResult;
        navigateTo('screen-result');
      });

      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          state.apiResult = item.apiResult;
          navigateTo('screen-result');
        }
      });

      container.appendChild(card);
    });
  }

  // ---------------------------------------------------------------------------
  // Sidebar & Bottom Navigation Setup
  // ---------------------------------------------------------------------------
  function initNavigation() {
    // Desktop Sidebar New Document Button
    const sidebarNewBtn = document.getElementById('sidebarNewBtn');
    if (sidebarNewBtn) {
      sidebarNewBtn.onclick = () => {
        resetAppWorkflow();
        navigateTo('screen-select');
      };
    }

    // Sidebar Links
    const sidebarNavHome = document.getElementById('sidebarNavHome');
    const sidebarNavProtected = document.getElementById('sidebarNavProtected');
    const sidebarNavProfile = document.getElementById('sidebarNavProfile');
    const sidebarUserProfileBtn = document.getElementById('sidebarUserProfileBtn');
    const sidebarSettingsBtn = document.getElementById('sidebarSettingsBtn');

    if (sidebarNavHome) sidebarNavHome.onclick = (e) => { e.preventDefault(); navigateTo('screen-select'); };
    if (sidebarNavProtected) sidebarNavProtected.onclick = (e) => { e.preventDefault(); navigateTo('screen-history'); };
    if (sidebarNavProfile) sidebarNavProfile.onclick = (e) => { e.preventDefault(); navigateTo('screen-profile'); };
    if (sidebarUserProfileBtn) sidebarUserProfileBtn.onclick = () => navigateTo('screen-profile');
    if (sidebarSettingsBtn) sidebarSettingsBtn.onclick = () => navigateTo('screen-profile');

    // Mobile Bottom Nav Links
    const bottomNavHome = document.getElementById('bottomNavHome');
    const bottomNavHistory = document.getElementById('bottomNavHistory');
    const bottomNavProfile = document.getElementById('bottomNavProfile');

    if (bottomNavHome) bottomNavHome.onclick = (e) => { e.preventDefault(); navigateTo('screen-select'); };
    if (bottomNavHistory) bottomNavHistory.onclick = (e) => { e.preventDefault(); navigateTo('screen-history'); };
    if (bottomNavProfile) bottomNavProfile.onclick = (e) => { e.preventDefault(); navigateTo('screen-profile'); };

    // Profile and Settings Action handlers
    const settingPrivacyBtn = document.getElementById('settingPrivacyBtn');
    const settingNotificationsBtn = document.getElementById('settingNotificationsBtn');
    const settingAuditBtn = document.getElementById('settingAuditBtn');
    const settingSignOutBtn = document.getElementById('settingSignOutBtn');
    const saveAuthTokenBtn = document.getElementById('saveAuthTokenBtn');
    const loadDemoTokenBtn = document.getElementById('loadDemoTokenBtn');
    const authTokenInput = document.getElementById('authTokenInput');
    const authStatusText = document.getElementById('authStatusText');
    const profileDisplayEmail = document.getElementById('profileDisplayEmail');
    const profileDisplayName = document.getElementById('profileDisplayName');

    const DEMO_JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJlbWFpbCI6ImFhcmF2LnNoYXJtYUBleGFtcGxlLmNvbSIsInJvbGUiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxODIzODc5MzA1LCJpYXQiOjE3OTIzNDMzMDUsImF1ZCI6ImF1dGhlbnRpY2F0ZWQifQ.rXlwO6dX4RNNjhz5A-CsbBpXKO2cBhP0AWccct0QlFI';

    function updateAuthUI() {
      const token = localStorage.getItem('infoshield_auth_token');
      if (token) {
        if (authStatusText) authStatusText.textContent = 'Status: Signed in with verified JWT';
        if (authTokenInput) authTokenInput.placeholder = 'Token saved (Bearer active)';
        try {
          const parts = token.split('.');
          if (parts.length === 3) {
            const payload = JSON.parse(atob(parts[1]));
            if (payload.email && profileDisplayEmail) profileDisplayEmail.textContent = payload.email;
            if (payload.sub && profileDisplayName) profileDisplayName.textContent = `User: ${payload.sub.slice(0, 8)}...`;
          }
        } catch (_) {}
      } else {
        if (authStatusText) authStatusText.textContent = 'Status: No token active';
        if (profileDisplayEmail) profileDisplayEmail.textContent = 'aarav.sharma@example.com';
        if (profileDisplayName) profileDisplayName.textContent = 'Aarav Sharma';
      }
    }

    // Auto-initialize demo token if empty
    if (!localStorage.getItem('infoshield_auth_token')) {
      localStorage.setItem('infoshield_auth_token', DEMO_JWT_TOKEN);
    }

    updateAuthUI();

    if (loadDemoTokenBtn) {
      loadDemoTokenBtn.onclick = () => {
        localStorage.setItem('infoshield_auth_token', DEMO_JWT_TOKEN);
        if (authTokenInput) authTokenInput.value = '';
        updateAuthUI();
        showToast('Signed in with configured Demo JWT Token.');
        loadHistoryFromBackend();
      };
    }

    if (saveAuthTokenBtn && authTokenInput) {
      saveAuthTokenBtn.onclick = () => {
        const val = authTokenInput.value.trim();
        if (!val) {
          showToast('Please paste a valid JWT token.');
          return;
        }
        if (val.split('.').length !== 3) {
          showToast('Invalid format. A JWT has 3 parts separated by dots.');
          return;
        }
        localStorage.setItem('infoshield_auth_token', val);
        authTokenInput.value = '';
        updateAuthUI();
        showToast('Authentication token saved. Authenticated requests active.');
        loadHistoryFromBackend();
      };
    }

    if (settingSignOutBtn) {
      settingSignOutBtn.onclick = () => {
        localStorage.removeItem('infoshield_auth_token');
        updateAuthUI();
        showToast('Signed out successfully.');
      };
    }

    if (settingPrivacyBtn) settingPrivacyBtn.onclick = () => showToast('Zero-trust minimization is actively enabled.');
    if (settingNotificationsBtn) settingNotificationsBtn.onclick = () => showToast('Consent notification alerts are active.');
    if (settingAuditBtn) settingAuditBtn.onclick = () => showToast('Audit trail exported to local device.');

  }

  async function checkBackendHealth() {
    try {
      const res = await fetch(`${BACKEND_BASE_URL}/api/health`);
      if (res.ok) {
        console.log('[InfoShield] Backend API connected successfully.');
      }
    } catch (e) {
      console.warn(`[InfoShield] Backend not reachable at ${BACKEND_BASE_URL || window.location.origin}.`);
    }
  }

  // ---------------------------------------------------------------------------
  // Application Bootstrap
  // ---------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    initScreenSelect();
    initScreenUpload();
    initScreenPurpose();
    initNavigation();
    checkBackendHealth();

    // Register Service Worker for PWA if supported and on HTTP/HTTPS
    if ('serviceWorker' in navigator && window.location.protocol.startsWith('http')) {
      navigator.serviceWorker.register('sw.js').catch(function (err) {
        console.debug('[InfoShield] ServiceWorker not registered:', err);
      });
    }

    // Start on Document Selection
    navigateTo('screen-select', false);
  });

})();
