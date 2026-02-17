document.addEventListener('DOMContentLoaded', () => {
    // ========================
    // DOM Elements
    // ========================

    // Steps
    const stepCalendar = document.getElementById('step-calendar');
    const stepSlots = document.getElementById('step-slots');
    const stepForm = document.getElementById('step-form');
    const stepDot1 = document.getElementById('stepDot1');
    const stepDot2 = document.getElementById('stepDot2');
    const stepDot3 = document.getElementById('stepDot3');
    const stepLine1 = document.getElementById('stepLine1');
    const stepLine2 = document.getElementById('stepLine2');
    const stepLabel2 = document.getElementById('stepLabel2');
    const stepLabel3 = document.getElementById('stepLabel3');

    // Calendar
    const calendarGrid = document.getElementById('calendarGrid');
    const currentMonthYear = document.getElementById('currentMonthYear');
    const prevMonthBtn = document.getElementById('prevMonth');
    const nextMonthBtn = document.getElementById('nextMonth');

    // Slots
    const slotsGrid = document.getElementById('slotsGrid');
    const selectedDateDisplay = document.getElementById('selectedDateDisplay');
    const noSlotsMessage = document.getElementById('noSlotsMessage');
    const backToCalendar = document.getElementById('backToCalendar');

    // Form
    const bookingForm = document.getElementById('bookingForm');
    const formDate = document.getElementById('formDate');
    const formTime = document.getElementById('formTime');
    const formSummaryDate = document.getElementById('formSummaryDate');
    const formSummaryTime = document.getElementById('formSummaryTime');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const backToSlots = document.getElementById('backToSlots');
    const gdprConsent = document.getElementById('gdprConsent');

    // Type selector
    const typeSelector = document.getElementById('typeSelector');
    const typeInput = document.getElementById('type');
    const diagnosisSection = document.getElementById('diagnosisSection');
    const hasDiagnosis = document.getElementById('hasDiagnosis');
    const fileUploadContainer = document.getElementById('fileUploadContainer');
    const diagnosticFileInput = document.getElementById('diagnosticFile');
    const dropZone = document.getElementById('dropZone');
    const filePreview = document.getElementById('filePreview');
    const fileNameDisplay = document.getElementById('fileName');
    const removeFileBtn = document.getElementById('removeFile');

    // File Viewer
    const fileViewerModal = document.getElementById('fileViewerModal');
    const closeFileViewer = document.getElementById('closeFileViewer');
    const fileViewerContent = document.getElementById('fileViewerContent');
    const fileDownloadLink = document.getElementById('fileDownloadLink');

    // Toast
    const toast = document.getElementById('toast');
    const toastTitle = document.getElementById('toastTitle');
    const toastMessage = document.getElementById('toastMessage');

    // State
    let currentDate = new Date();
    let selectedDate = null;
    let selectedTime = null;

    // ========================
    // Step Wizard
    // ========================

    function goToStep(step) {
        // Hide all steps
        stepCalendar.classList.add('hidden');
        stepSlots.classList.add('hidden');
        stepForm.classList.add('hidden');

        // Reset dots
        [stepDot1, stepDot2, stepDot3].forEach(dot => {
            dot.classList.remove('active', 'completed');
        });
        [stepLine1, stepLine2].forEach(line => {
            line.classList.remove('active');
        });
        if (stepLabel2) stepLabel2.classList.remove('text-medical-600');
        if (stepLabel2) stepLabel2.classList.add('text-gray-400');
        if (stepLabel3) stepLabel3.classList.remove('text-medical-600');
        if (stepLabel3) stepLabel3.classList.add('text-gray-400');

        if (step === 1) {
            stepCalendar.classList.remove('hidden');
            stepDot1.classList.add('active');
        } else if (step === 2) {
            stepSlots.classList.remove('hidden');
            stepDot1.classList.add('completed');
            stepDot2.classList.add('active');
            stepLine1.classList.add('active');
            if (stepLabel2) {
                stepLabel2.classList.remove('text-gray-400');
                stepLabel2.classList.add('text-medical-600');
            }
        } else if (step === 3) {
            stepForm.classList.remove('hidden');
            stepDot1.classList.add('completed');
            stepDot2.classList.add('completed');
            stepDot3.classList.add('active');
            stepLine1.classList.add('active');
            stepLine2.classList.add('active');
            if (stepLabel2) {
                stepLabel2.classList.remove('text-gray-400');
                stepLabel2.classList.add('text-medical-600');
            }
            if (stepLabel3) {
                stepLabel3.classList.remove('text-gray-400');
                stepLabel3.classList.add('text-medical-600');
            }
        }

        // Scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    // Navigation
    backToCalendar.onclick = () => {
        selectedDate = null;
        goToStep(1);
    };

    backToSlots.onclick = () => {
        selectedTime = null;
        goToStep(2);
    };

    // ========================
    // Toast
    // ========================

    function showToast(title, message, type = 'success') {
        toastTitle.textContent = title;
        toastMessage.textContent = message;
        toast.className = `fixed bottom-5 right-5 bg-brand-800 shadow-xl rounded-xl p-5 transform transition-all duration-300 max-w-sm z-50 border-l-4 border border-brand-600/30 ${type === 'success' ? 'border-l-brand-400' : 'border-l-red-400'}`;
        toastTitle.className = `font-bold ${type === 'success' ? 'text-brand-100' : 'text-red-300'}`;
        toastMessage.className = `text-sm mt-1 ${type === 'success' ? 'text-brand-300' : 'text-red-200'}`;
        setTimeout(() => {
            toast.classList.remove('translate-y-20', 'opacity-0');
        }, 10);
        setTimeout(() => {
            toast.classList.add('translate-y-20', 'opacity-0');
        }, 12000);
    }

    // ========================
    // File Processing
    // ========================

    async function processFile(file) {
        if (!file) return null;
        if (file.type === 'application/pdf') {
            return { base64: await fileToBase64(file), type: file.type };
        }
        if (file.type.startsWith('image/')) {
            const compressedBase64 = await compressImage(file);
            return { base64: compressedBase64, type: 'image/jpeg' };
        }
        return null;
    }

    function fileToBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    }

    async function compressImage(file) {
        const MAX_WIDTH = 1200;
        const MAX_HEIGHT = 1200;
        const QUALITY = 0.6;
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    let width = img.width;
                    let height = img.height;
                    const ratio = Math.min(MAX_WIDTH / width, MAX_HEIGHT / height, 1);
                    width *= ratio;
                    height *= ratio;
                    const canvas = document.createElement('canvas');
                    canvas.width = width;
                    canvas.height = height;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(img, 0, 0, width, height);
                    resolve(canvas.toDataURL('image/jpeg', QUALITY));
                };
                img.src = e.target.result;
            };
            reader.readAsDataURL(file);
        });
    }

    // ========================
    // Calendar
    // ========================

    function renderCalendar(date) {
        calendarGrid.innerHTML = '';
        const year = date.getFullYear();
        const month = date.getMonth();

        const monthName = new Intl.DateTimeFormat('ro-RO', { month: 'long', year: 'numeric' }).format(date);
        currentMonthYear.textContent = monthName.charAt(0).toUpperCase() + monthName.slice(1);

        const firstDayIndex = new Date(year, month, 1).getDay();
        const lastDay = new Date(year, month + 1, 0).getDate();

        // Filler for days before 1st
        for (let i = 0; i < firstDayIndex; i++) {
            const div = document.createElement('div');
            div.className = 'calendar-day empty';
            calendarGrid.appendChild(div);
        }

        for (let i = 1; i <= lastDay; i++) {
            const dayDiv = document.createElement('div');
            dayDiv.textContent = i;

            const currentDayDate = new Date(year, month, i);
            const y = currentDayDate.getFullYear();
            const m = String(currentDayDate.getMonth() + 1).padStart(2, '0');
            const d = String(currentDayDate.getDate()).padStart(2, '0');
            const formattedDate = `${y}-${m}-${d}`;

            const isWednesday = currentDayDate.getDay() === 3;
            const isValidMonth = year === 2026 && month >= 1 && month <= 3;
            const isExcludedDate = formattedDate === '2026-04-08';

            const today = new Date();
            today.setHours(0, 0, 0, 0);
            const isPast = currentDayDate < today;

            dayDiv.className = 'calendar-day';

            if (isWednesday && !isPast && isValidMonth && !isExcludedDate) {
                dayDiv.classList.add('active-wednesday');

                const dot = document.createElement('div');
                dot.className = 'availability-dot';
                dayDiv.appendChild(dot);

                if (selectedDate === formattedDate) {
                    dayDiv.classList.add('selected');
                }

                dayDiv.onclick = () => selectDate(formattedDate, dayDiv);
            } else {
                dayDiv.classList.add('disabled-day');
            }

            calendarGrid.appendChild(dayDiv);
        }
    }

    function selectDate(date, element) {
        selectedDate = date;
        const dateObj = new Date(date);
        const dateStr = new Intl.DateTimeFormat('ro-RO', { day: 'numeric', month: 'long', year: 'numeric' }).format(dateObj);
        selectedDateDisplay.textContent = dateStr;

        // Highlight
        document.querySelectorAll('.calendar-day').forEach(d => d.classList.remove('selected'));
        element.classList.add('selected');

        // Go to step 2
        fetchSlots(date);
        goToStep(2);
    }

    prevMonthBtn.onclick = () => {
        const testDate = new Date(currentDate);
        testDate.setMonth(testDate.getMonth() - 1);
        if (testDate.getFullYear() === 2026 && testDate.getMonth() >= 1) {
            currentDate.setMonth(currentDate.getMonth() - 1);
            renderCalendar(currentDate);
        }
    };

    nextMonthBtn.onclick = () => {
        const testDate = new Date(currentDate);
        testDate.setMonth(testDate.getMonth() + 1);
        if (testDate.getFullYear() === 2026 && testDate.getMonth() <= 3) {
            currentDate.setMonth(currentDate.getMonth() + 1);
            renderCalendar(currentDate);
        }
    };

    renderCalendar(currentDate);

    // ========================
    // Slots
    // ========================

    async function fetchSlots(date) {
        slotsGrid.innerHTML = '<div class="col-span-full text-center py-8 text-gray-400 font-medium">Se încarcă intervalele...</div>';
        noSlotsMessage.classList.add('hidden');

        try {
            const res = await fetch(`/api/slots?date=${date}`);
            const slots = await res.json();

            if (res.status !== 200) {
                slotsGrid.innerHTML = `<div class="col-span-full text-center text-red-500">${slots.error}</div>`;
                return;
            }
            renderSlots(slots, date);
        } catch (err) {
            console.error(err);
            slotsGrid.innerHTML = '<div class="col-span-full text-center text-red-500">Eroare de conexiune.</div>';
        }
    }

    function renderSlots(slots, date) {
        slotsGrid.innerHTML = '';
        const availableSlots = slots.filter(s => s.available);

        if (availableSlots.length === 0) {
            noSlotsMessage.classList.remove('hidden');
            return;
        }

        slots.forEach((slot, index) => {
            const btn = document.createElement('button');
            btn.className = 'slot-btn';
            btn.style.animationDelay = `${index * 40}ms`;
            btn.textContent = slot.time;
            btn.disabled = !slot.available;

            if (slot.available) {
                btn.onclick = () => {
                    selectedTime = slot.time;
                    formDate.value = date;
                    formTime.value = slot.time;

                    const dateObj = new Date(date);
                    formSummaryDate.textContent = new Intl.DateTimeFormat('ro-RO', { day: 'numeric', month: 'long', year: 'numeric' }).format(dateObj);
                    formSummaryTime.textContent = slot.time;

                    goToStep(3);
                };
            }

            slotsGrid.appendChild(btn);
        });
    }

    // ========================
    // Type Selector
    // ========================

    typeSelector.addEventListener('click', (e) => {
        const btn = e.target.closest('.type-btn');
        if (!btn) return;

        typeSelector.querySelectorAll('.type-btn').forEach(b => b.classList.remove('selected'));
        btn.classList.add('selected');
        typeInput.value = btn.dataset.value;

        if (btn.dataset.value === 'Prima Consultație') {
            diagnosisSection.classList.remove('hidden');
        } else {
            diagnosisSection.classList.add('hidden');
            hasDiagnosis.checked = false;
            fileUploadContainer.classList.add('hidden');
            if (diagnosticFileInput) diagnosticFileInput.value = '';
            filePreview.classList.add('hidden');
        }
    });

    hasDiagnosis.addEventListener('change', () => {
        if (hasDiagnosis.checked) {
            fileUploadContainer.classList.remove('hidden');
        } else {
            fileUploadContainer.classList.add('hidden');
            if (diagnosticFileInput) diagnosticFileInput.value = '';
            filePreview.classList.add('hidden');
        }
    });

    // ========================
    // Drag-and-Drop Upload
    // ========================

    function handleFileSelection(file) {
        if (!file) return;
        const maxSize = 5 * 1024 * 1024; // 5MB
        if (file.size > maxSize) {
            showToast('Eroare', 'Fișierul este prea mare (max 5MB).', 'error');
            return;
        }
        // Update file input
        const dt = new DataTransfer();
        dt.items.add(file);
        diagnosticFileInput.files = dt.files;

        // Show preview
        fileNameDisplay.textContent = file.name;
        filePreview.classList.remove('hidden');
        dropZone.classList.add('hidden');
    }

    dropZone.addEventListener('click', () => diagnosticFileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            handleFileSelection(e.dataTransfer.files[0]);
        }
    });

    diagnosticFileInput.addEventListener('change', () => {
        if (diagnosticFileInput.files[0]) {
            handleFileSelection(diagnosticFileInput.files[0]);
        }
    });

    removeFileBtn.addEventListener('click', () => {
        diagnosticFileInput.value = '';
        filePreview.classList.add('hidden');
        dropZone.classList.remove('hidden');
    });

    // ========================
    // File Viewer
    // ========================

    closeFileViewer.onclick = () => {
        fileViewerModal.classList.add('hidden');
        fileViewerContent.innerHTML = '';
        fileDownloadLink.innerHTML = '';
    };

    function openFileViewer(base64, type) {
        fileViewerContent.innerHTML = '';
        fileDownloadLink.innerHTML = '';

        if (type === 'application/pdf') {
            fileViewerContent.innerHTML = `
                <div class="text-center p-10">
                    <svg class="w-16 h-16 text-red-500 mx-auto mb-4" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M9 2a2 2 0 00-2 2v8a2 2 0 002 2h6a2 2 0 002-2V6l-4-4H9z"></path>
                    </svg>
                    <p class="text-lg font-medium text-gray-900">Document PDF</p>
                </div>
            `;
            fileDownloadLink.innerHTML = `
                <a href="${base64}" download="diagnostic.pdf"
                   class="inline-block bg-medical-600 text-white px-6 py-3 rounded-xl font-bold hover:bg-medical-700 transition-colors">
                   Descarcă PDF
                </a>
            `;
        } else {
            fileViewerContent.innerHTML = `<img src="${base64}" class="max-w-full h-auto rounded-xl shadow-lg">`;
        }

        fileViewerModal.classList.remove('hidden');
    }

    // ========================
    // Booking Form Submission
    // ========================

    bookingForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        // GDPR check
        if (!gdprConsent.checked) {
            showToast('Atenție', 'Trebuie să acceptați prelucrarea datelor personale (GDPR).', 'error');
            return;
        }

        const firstName = document.getElementById('firstName').value;
        const lastName = document.getElementById('lastName').value;
        const name = `${lastName} ${firstName}`;
        const phone = document.getElementById('phone').value;
        const cnp = document.getElementById('cnp').value;
        const email = document.getElementById('email').value;
        const type = typeInput.value;
        const date = formDate.value;
        const time = formTime.value;

        // Diagnostic files are disabled server-side until secure object storage is configured.
        if (hasDiagnosis.checked && diagnosticFileInput.files[0]) {
            showToast('Info', 'Încărcarea documentelor este temporar indisponibilă online. Vă rugăm aduceți documentele la consultație.', 'error');
            return;
        }

        if (phone.length < 10) {
            showToast('Eroare', 'Numărul de telefon pare invalid.', 'error');
            return;
        }

        if (!/^\d{13}$/.test(cnp)) {
            showToast('Eroare', 'CNP-ul trebuie să aibă exact 13 cifre.', 'error');
            return;
        }

        const submitBtn = document.getElementById('submitBtn');
        submitBtn.disabled = true;
        loadingSpinner.classList.remove('hidden');

        try {
            const res = await AUTH.apiFetch('/api/book', {
                method: 'POST',
                body: JSON.stringify({
                    name, phone, email, cnp, type, date, time,
                    hasDiagnosis: hasDiagnosis.checked
                })
            });

            const data = await res.json();

            if (res.ok) {
                showToast('Succes!', 'Confirmarea și invitația pentru calendar au fost trimise pe adresa dumneavoastră de e-mail.');
                bookingForm.reset();
                // Reset type selector
                typeSelector.querySelectorAll('.type-btn').forEach(b => b.classList.remove('selected'));
                typeSelector.querySelector('[data-value="Control"]').classList.add('selected');
                typeInput.value = 'Control';
                diagnosisSection.classList.add('hidden');
                fileUploadContainer.classList.add('hidden');
                filePreview.classList.add('hidden');
                dropZone.classList.remove('hidden');
                // Go back to step 1
                selectedDate = null;
                selectedTime = null;
                goToStep(1);
                renderCalendar(currentDate);
            } else {
                showToast('Eroare', data.error || 'A apărut o eroare.', 'error');
            }
        } catch (err) {
            showToast('Eroare', 'Eroare de conexiune server.', 'error');
        } finally {
            submitBtn.disabled = false;
            loadingSpinner.classList.add('hidden');
        }
    });

    // ========================
    // Admin Logic (Role-Based)
    // ========================

    const adminLoginBtn = document.getElementById('adminLoginBtn');
    const adminDashboard = document.getElementById('adminDashboard');
    const closeDashboard = document.getElementById('closeDashboard');
    const exportExcelBtn = document.getElementById('exportExcelBtn');
    const timelineGrid = document.getElementById('timelineGrid');
    const currentAdminDateDisplay = document.getElementById('currentAdminDateDisplay');
    const prevAdminDate = document.getElementById('prevAdminDate');
    const nextAdminDate = document.getElementById('nextAdminDate');
    const timelineHeaderCount = document.getElementById('timelineHeaderCount');
    const manageUsersBtn = document.getElementById('manageUsersBtn');
    const userManagerContainer = document.getElementById('userManagerContainer');
    const timelineContainer = document.getElementById('timelineContainer');
    const backToTimeline = document.getElementById('backToTimeline');
    const userTableBody = document.getElementById('userTableBody');

    let adminActiveDate = new Date();
    adminActiveDate.setHours(0, 0, 0, 0);
    while (adminActiveDate.getDay() !== 3) {
        adminActiveDate.setDate(adminActiveDate.getDate() + 1);
    }

    adminLoginBtn.addEventListener('click', () => {
        const user = AUTH.getUser();
        const isAdmin = user && (user.role === 'admin' || user.role === 'superadmin');

        if (isAdmin) {
            openDashboard();
        } else {
            showToast('Acces interzis', 'Nu aveți drepturi de administrator.', 'error');
        }
    });

    function openDashboard() {
        adminDashboard.classList.remove('hidden');
        updateAdminDateDisplay();
        setupAdminSearch();
        fetchAdminAppointments();
        fetchAdminStats();

        // Show Manage Users button only for superadmin
        const user = AUTH.getUser();
        const isSuper = user && user.role === 'superadmin';
        if (isSuper) {
            manageUsersBtn.classList.remove('hidden');
        }
    }

    function setupAdminSearch() {
        // Find or create search input
        let searchInput = document.getElementById('adminSearchInput');
        if (!searchInput) {
            const headerActions = document.querySelector('#adminDashboard div.flex.flex-wrap.gap-2');
            searchInput = document.createElement('input');
            searchInput.id = 'adminSearchInput';
            searchInput.type = 'text';
            searchInput.placeholder = 'Caută nume, telefon sau email...';
            searchInput.className = 'px-4 py-2 rounded-xl bg-brand-800 border border-brand-600/30 text-brand-100 placeholder-brand-400/50 text-sm focus:outline-none focus:border-brand-400 transition-all w-full md:w-64 order-first md:order-none';
            headerActions.prepend(searchInput);

            searchInput.addEventListener('input', () => {
                fetchAdminAppointments(searchInput.value.toLowerCase());
            });
        }
    }

    function updateAdminDateDisplay() {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const isToday = adminActiveDate.getTime() === today.getTime();
        const dateStr = new Intl.DateTimeFormat('ro-RO', { day: 'numeric', month: 'long' }).format(adminActiveDate);
        currentAdminDateDisplay.textContent = (isToday ? 'Azi, ' : '') + dateStr;
    }

    function getAdminActiveDateISO() {
        const y = adminActiveDate.getFullYear();
        const m = String(adminActiveDate.getMonth() + 1).padStart(2, '0');
        const d = String(adminActiveDate.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
    }

    prevAdminDate.onclick = () => {
        adminActiveDate.setDate(adminActiveDate.getDate() - 7);
        updateAdminDateDisplay();
        fetchAdminAppointments();
    };

    nextAdminDate.onclick = () => {
        adminActiveDate.setDate(adminActiveDate.getDate() + 7);
        updateAdminDateDisplay();
        fetchAdminAppointments();
    };

    async function fetchAdminStats() {
        const storageIndicator = document.getElementById('storage-indicator');
        const storageBar = document.getElementById('storage-bar');
        const storageText = document.getElementById('storage-text');

        try {
            const res = await AUTH.apiFetch('/api/admin/stats');
            const data = await res.json();

            if (res.ok) {
                storageIndicator.classList.remove('hidden');
                storageBar.style.width = `${Math.min(data.percentUsed, 100)}%`;
                storageText.textContent = `${data.usedSizeMB} MB / ${data.totalSizeMB} MB (${data.percentUsed}%)`;

                if (data.percentUsed > 80) {
                    storageBar.classList.replace('bg-medical-500', 'bg-red-500');
                }
            }
        } catch (err) {
            console.error('Error fetching stats:', err);
        }
    }

    async function fetchAdminAppointments(filterTerm = '') {
        timelineGrid.innerHTML = '<div class="p-10 text-center text-gray-400 font-medium font-inter">Se încarcă programările...</div>';

        try {
            const res = await AUTH.apiFetch('/api/admin/appointments');

            const appointments = await res.json().catch(() => null);

            if (!res.ok) {
                throw new Error(appointments?.error || `Server error: ${res.status}`);
            }

            const y = adminActiveDate.getFullYear();
            const m = String(adminActiveDate.getMonth() + 1).padStart(2, '0');
            const d = String(adminActiveDate.getDate()).padStart(2, '0');
            const formattedActiveDate = `${y}-${m}-${d}`;

            const filtered = appointments.filter(app => {
                const isDateMatch = app.date === formattedActiveDate;
                if (!isDateMatch) return false;
                if (!filterTerm) return true;

                return app.name.toLowerCase().includes(filterTerm) ||
                    app.phone.includes(filterTerm) ||
                    (app.email && app.email.toLowerCase().includes(filterTerm));
            });
            renderTimeline(filtered);
            timelineHeaderCount.textContent = `(${filtered.length}) Programări`;
        } catch (err) {
            console.error('Admin Fetch Error:', err);
            timelineGrid.innerHTML = `<div class="p-10 text-center text-red-500 font-medium">
                Eroare la încărcare.<br>
                <span class="text-xs text-brand-400/50">${err.message}</span>
            </div>`;
        }
    }

    function renderTimeline(appointments) {
        timelineGrid.innerHTML = '';

        const clinicHours = [];
        for (let hour = 9; hour < 14; hour++) {
            for (let min = 0; min < 60; min += 20) {
                if (hour === 13 && min > 40) break;
                const hh = String(hour).padStart(2, '0');
                const mm = String(min).padStart(2, '0');
                clinicHours.push(`${hh}:${mm}`);
            }
        }

        clinicHours.forEach(time => {
            const row = document.createElement('div');
            row.className = 'timeline-row';

            const hourLabel = document.createElement('div');
            hourLabel.className = 'timeline-hour';
            hourLabel.textContent = time;

            const slotsArea = document.createElement('div');
            slotsArea.className = 'timeline-slots';

            const appsInSlot = appointments.filter(a => a.time === time);

            appsInSlot.forEach((app) => {
                const card = document.createElement('div');
                card.className = `appointment-card ${app.type === 'Control' ? 'app-type-control' : 'app-type-prima'}`;

                card.innerHTML = `
                    <div class="flex items-center gap-3 flex-wrap">
                        <span class="font-bold text-brand-100">${app.name}</span>
                        ${app.type === 'Prima Consultație' ? '<span class="app-new-badge">NOU</span>' : ''}
                        <span class="text-brand-600/30">|</span>
                        <span class="text-brand-300"><strong class="font-inter text-[11px] uppercase text-brand-400/50">Email:</strong> ${app.email || '—'}</span>
                        <span class="text-brand-600/30">|</span>
                        <span class="text-brand-300"><strong class="font-inter text-[11px] uppercase text-brand-400/50">Tel:</strong> ${app.phone}</span>
                        <span class="text-brand-600/30">|</span>
                        <span class="text-brand-300"><strong class="font-inter text-[11px] uppercase text-brand-400/50">Tip:</strong> ${app.type}</span>
                        <span class="text-brand-600/30">|</span>
                        <div class="flex items-center gap-1.5 px-2 py-0.5 rounded-lg ${app.emailSent ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}" title="${app.emailSent ? 'Invitație expediată' : 'Eroare trimitere sau în procesare'}">
                            <span class="text-[10px] font-bold uppercase">${app.emailSent ? 'Trimis' : 'Netrimis'}</span>
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                ${app.emailSent ?
                        '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7" />' :
                        '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M6 18L18 6M6 6l12 12" />'}
                            </svg>
                        </div>
                        <button class="resend-email-btn bg-brand-400/10 hover:bg-brand-400/20 text-brand-400 px-2 py-1 rounded-lg text-[10px] font-bold uppercase transition-all flex items-center gap-1" data-id="${app._id}">
                            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                            Trimite Manual
                        </button>
                        <button class="cancel-appointment-btn bg-red-500/10 hover:bg-red-500/20 text-red-300 px-2 py-1 rounded-lg text-[10px] font-bold uppercase transition-all flex items-center gap-1" data-id="${app._id}">
                            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
                            Anuleaza
                        </button>
                        ${app.diagnosticFileMeta ? `
                            <span class="ml-auto bg-brand-600/20 px-3 py-1 rounded-lg text-xs font-bold text-brand-300">DOC: ${app.diagnosticFileMeta.mime || 'metadata'}</span>
                        ` : ''}
                    </div>
                `;

                card.querySelector('.resend-email-btn').onclick = async (e) => {
                    e.stopPropagation();
                    const btn = e.currentTarget;
                    const originalText = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<span class="animate-pulse">Se trimite...</span>';

                    try {
                        const res = await AUTH.apiFetch(`/api/admin/resend-email/${app._id}`, {
                            method: 'POST'
                        });
                        const data = await res.json();
                        if (res.ok) {
                            showToast('Succes', data.message);
                            // Refresh timeline to show updated status
                            if (typeof fetchAdminAppointments === 'function') {
                                setTimeout(() => fetchAdminAppointments(''), 2000);
                            }
                        } else {
                            const errorMsg = data.details ? `${data.error}: ${data.details}` : (data.error || 'Eroare server');
                            showToast('Eroare', errorMsg, 'error');
                        }
                    } catch (err) {
                        showToast('Eroare', 'Eroare de conexiune.', 'error');
                    } finally {
                        btn.disabled = false;
                        btn.innerHTML = originalText;
                    }
                };

                card.querySelector('.cancel-appointment-btn').onclick = async (e) => {
                    e.stopPropagation();
                    const confirm1 = confirm(`Esti sigur ca vrei sa anulezi programarea pacientului ${app.name}?`);
                    if (!confirm1) return;
                    const confirm2 = confirm('CONFIRMARE FINALA: Programarea va fi stearsa definitiv. Continuam?');
                    if (!confirm2) return;

                    try {
                        const res = await AUTH.apiFetch(`/api/admin/appointment/${app._id}`, {
                            method: 'DELETE'
                        });
                        const data = await res.json();
                        if (res.ok) {
                            showToast('Succes', data.message || 'Programarea a fost anulata.');
                            fetchAdminAppointments();
                            fetchAdminStats();
                        } else {
                            showToast('Eroare', data.error || 'Nu s-a putut anula programarea.', 'error');
                        }
                    } catch (err) {
                        showToast('Eroare', 'Eroare de conexiune.', 'error');
                    }
                };

                slotsArea.appendChild(card);
            });

            row.appendChild(hourLabel);
            row.appendChild(slotsArea);
            timelineGrid.appendChild(row);
        });
    }

    // User Management (SuperAdmin)
    manageUsersBtn.addEventListener('click', () => {
        timelineContainer.classList.add('hidden');
        userManagerContainer.classList.remove('hidden');
        fetchUsers();
    });

    backToTimeline.addEventListener('click', () => {
        userManagerContainer.classList.add('hidden');
        timelineContainer.classList.remove('hidden');
    });

    async function fetchUsers() {
        userTableBody.innerHTML = '<tr><td colspan="4" class="p-10 text-center text-brand-400">Se încarcă lista de utilizatori...</td></tr>';
        try {
            const res = await AUTH.apiFetch('/api/admin/users');
            const users = await res.json();
            if (res.ok) {
                renderUsers(users);
            } else {
                showToast('Eroare', users.error || 'Eroare la preluare utilizatori.', 'error');
            }
        } catch (err) {
            showToast('Eroare', 'Eroare de conexiune server.', 'error');
        }
    }

    function renderUsers(users) {
        userTableBody.innerHTML = '';
        users.forEach(user => {
            const row = document.createElement('tr');
            row.className = 'border-b border-brand-600/10 hover:bg-brand-600/5 transition-colors';

            const isSelf = user.email === AUTH.getUser().email;
            const isSuperAdmin = user.role === 'superadmin';

            row.innerHTML = `
                <td class="py-4 font-medium">${user.displayName}</td>
                <td class="py-4 text-brand-400">${user.email}</td>
                <td class="py-4 text-brand-400">${user.phone}</td>
                <td class="py-4 text-center">
                    <button class="role-toggle-btn w-12 h-6 rounded-full relative transition-all duration-300 ${user.role === 'admin' ? 'bg-brand-400' : (isSuperAdmin ? 'bg-medical-500' : 'bg-brand-700')}" 
                            ${(isSelf || isSuperAdmin) ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>
                        <div class="w-4 h-4 bg-brand-900 rounded-full absolute top-1 transition-all duration-300 ${user.role === 'admin' ? 'left-7' : 'left-1'}"></div>
                    </button>
                    ${isSuperAdmin ? '<span class="block text-[10px] uppercase font-bold text-medical-500 mt-1">Super Admin</span>' : ''}
                </td>
            `;

            if (!isSelf && !isSuperAdmin) {
                row.querySelector('.role-toggle-btn').onclick = () => {
                    const newRole = user.role === 'admin' ? 'user' : 'admin';
                    toggleUserRole(user._id, newRole);
                };
            }

            userTableBody.appendChild(row);
        });
    }

    async function toggleUserRole(userId, role) {
        try {
            const res = await AUTH.apiFetch('/api/admin/users/role', {
                method: 'POST',
                body: JSON.stringify({ userId, role })
            });
            const data = await res.json();
            if (res.ok) {
                showToast('Succes', data.message);
                fetchUsers();
            } else {
                showToast('Eroare', data.error, 'error');
            }
        } catch (err) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    }

    const resetDatabaseBtn = document.getElementById('resetDatabaseBtn');
    const cancelDayAppointmentsBtn = document.getElementById('cancelDayAppointmentsBtn');
    resetDatabaseBtn.addEventListener('click', async () => {
        const confirm1 = confirm("Ești sigur că vrei să ștergi TOATE programările?");
        if (!confirm1) return;
        const confirm2 = confirm("CONFIRMARE FINALĂ: Toate datele vor fi șterse definitiv. Continuăm?");
        if (!confirm2) return;

        try {
            const res = await AUTH.apiFetch('/api/admin/reset', {
                method: 'POST'
            });
            const data = await res.json();
            if (res.ok) {
                showToast('Succes', 'Baza de date a fost resetată.');
                fetchAdminAppointments();
                fetchAdminStats();
            } else {
                showToast('Eroare', data.error || 'Nu s-a putut reseta.', 'error');
            }
        } catch (err) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    });

    cancelDayAppointmentsBtn.addEventListener('click', async () => {
        const selectedDate = getAdminActiveDateISO();
        const confirm1 = confirm(`Esti sigur ca vrei sa anulezi TOATE programarile din ${selectedDate}?`);
        if (!confirm1) return;
        const confirm2 = confirm('CONFIRMARE FINALA: Toate programarile din ziua selectata vor fi sterse definitiv. Continuam?');
        if (!confirm2) return;

        try {
            const res = await AUTH.apiFetch('/api/admin/appointments/by-date', {
                method: 'DELETE',
                body: JSON.stringify({ date: selectedDate })
            });
            const data = await res.json();
            if (res.ok) {
                showToast('Succes', data.message || 'Programarile din ziua selectata au fost anulate.');
                fetchAdminAppointments();
                fetchAdminStats();
            } else {
                showToast('Eroare', data.error || 'Nu s-au putut anula programarile zilei.', 'error');
            }
        } catch (err) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    });

    exportExcelBtn.addEventListener('click', async () => {
        try {
            const res = await AUTH.apiFetch('/api/admin/export');

            if (!res.ok) {
                const errText = await res.text();
                showToast('Eroare', errText || 'Nu s-a putut genera exportul Excel.', 'error');
                return;
            }

            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'programari.xlsx';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        } catch (err) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    });

    closeDashboard.addEventListener('click', () => {
        adminDashboard.classList.add('hidden');
    });
});
