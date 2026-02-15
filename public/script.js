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
        toast.className = `fixed bottom-5 right-5 bg-white shadow-xl rounded-xl p-5 transform transition-all duration-300 max-w-sm z-50 border-l-4 ${type === 'success' ? 'border-green-500' : 'border-red-500'}`;
        setTimeout(() => {
            toast.classList.remove('translate-y-20', 'opacity-0');
        }, 10);
        setTimeout(() => {
            toast.classList.add('translate-y-20', 'opacity-0');
        }, 4000);
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
        const type = typeInput.value;
        const date = formDate.value;
        const time = formTime.value;

        // Diagnostic File
        let fileData = null;
        if (hasDiagnosis.checked && diagnosticFileInput.files[0]) {
            fileData = await processFile(diagnosticFileInput.files[0]);
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
            const res = await fetch('/api/book', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name, phone, cnp, type, date, time,
                    hasDiagnosis: hasDiagnosis.checked,
                    diagnosticFile: fileData ? fileData.base64 : null,
                    fileType: fileData ? fileData.type : null
                })
            });

            const data = await res.json();

            if (res.ok) {
                showToast('Succes!', 'Programarea a fost confirmată cu succes!');
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
    // Admin Logic
    // ========================

    const adminLoginBtn = document.getElementById('adminLoginBtn');
    const adminLoginModal = document.getElementById('adminLoginModal');
    const closeAdminLogin = document.getElementById('closeAdminLogin');
    const adminLoginForm = document.getElementById('adminLoginForm');
    const adminDashboard = document.getElementById('adminDashboard');
    const closeDashboard = document.getElementById('closeDashboard');
    const adminLogout = document.getElementById('adminLogout');
    const exportExcelBtn = document.getElementById('exportExcelBtn');
    const timelineGrid = document.getElementById('timelineGrid');
    const currentAdminDateDisplay = document.getElementById('currentAdminDateDisplay');
    const prevAdminDate = document.getElementById('prevAdminDate');
    const nextAdminDate = document.getElementById('nextAdminDate');
    const timelineHeaderCount = document.getElementById('timelineHeaderCount');

    let adminActiveDate = new Date();
    adminActiveDate.setHours(0, 0, 0, 0);
    while (adminActiveDate.getDay() !== 3) {
        adminActiveDate.setDate(adminActiveDate.getDate() + 1);
    }

    adminLoginBtn.addEventListener('click', () => {
        adminLoginModal.classList.remove('hidden');
    });

    closeAdminLogin.addEventListener('click', () => {
        adminLoginModal.classList.add('hidden');
    });

    adminLoginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('adminPassword').value;

        try {
            const res = await fetch('/api/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            const data = await res.json();

            if (data.success) {
                localStorage.setItem('adminToken', data.token);
                adminLoginModal.classList.add('hidden');
                document.getElementById('adminPassword').value = '';
                showToast('Autentificare reușită', 'Bine ai venit!');
                openDashboard();
            } else {
                showToast('Eroare', 'Parolă incorectă', 'error');
            }
        } catch (err) {
            showToast('Eroare', 'Eroare de conexiune', 'error');
        }
    });

    function openDashboard() {
        const token = localStorage.getItem('adminToken');
        if (!token) {
            showToast('Acces interzis', 'Te rugăm să te autentifici.', 'error');
            return;
        }
        adminDashboard.classList.remove('hidden');
        updateAdminDateDisplay();
        fetchAdminAppointments();
        fetchAdminStats();
    }

    function updateAdminDateDisplay() {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const isToday = adminActiveDate.getTime() === today.getTime();
        const dateStr = new Intl.DateTimeFormat('ro-RO', { day: 'numeric', month: 'long' }).format(adminActiveDate);
        currentAdminDateDisplay.textContent = (isToday ? 'Azi, ' : '') + dateStr;
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
        const token = localStorage.getItem('adminToken');
        const storageIndicator = document.getElementById('storage-indicator');
        const storageBar = document.getElementById('storage-bar');
        const storageText = document.getElementById('storage-text');

        try {
            const res = await fetch('/api/admin/stats', {
                headers: { 'x-admin-token': token }
            });
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

    async function fetchAdminAppointments() {
        const token = localStorage.getItem('adminToken');
        timelineGrid.innerHTML = '<div class="p-10 text-center text-gray-400 font-medium">Se încarcă programările...</div>';

        try {
            const res = await fetch('/api/admin/appointments', {
                headers: { 'x-admin-token': token }
            });

            const appointments = await res.json().catch(() => null);

            if (!res.ok) {
                throw new Error(appointments?.error || `Server error: ${res.status}`);
            }

            if (!Array.isArray(appointments)) {
                throw new Error('Data format error');
            }

            const y = adminActiveDate.getFullYear();
            const m = String(adminActiveDate.getMonth() + 1).padStart(2, '0');
            const d = String(adminActiveDate.getDate()).padStart(2, '0');
            const formattedActiveDate = `${y}-${m}-${d}`;

            const filtered = appointments.filter(app => app.date === formattedActiveDate);
            renderTimeline(filtered);
            timelineHeaderCount.textContent = `(${filtered.length}) Programări`;
        } catch (err) {
            console.error('Admin Fetch Error:', err);
            timelineGrid.innerHTML = `<div class="p-10 text-center text-red-500 font-medium">
                Eroare la încărcare.<br>
                <span class="text-xs text-gray-400">${err.message}</span>
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
                        <span class="font-bold text-gray-900">${app.name}</span>
                        ${app.type === 'Prima Consultație' ? '<span class="app-new-badge">NOU</span>' : ''}
                        <span class="text-gray-300">|</span>
                        <span class="text-gray-600"><strong class="text-[11px] uppercase text-gray-400">Tel:</strong> ${app.phone}</span>
                        <span class="text-gray-300">|</span>
                        <span class="text-gray-600"><strong class="text-[11px] uppercase text-gray-400">CNP:</strong> ${app.cnp}</span>
                        <span class="text-gray-300">|</span>
                        <span class="text-gray-600"><strong class="text-[11px] uppercase text-gray-400">Tip:</strong> ${app.type}</span>
                        ${app.diagnosticFile ? `
                            <button class="ml-auto view-file-link">VEZI DOC</button>
                        ` : ''}
                    </div>
                `;

                if (app.diagnosticFile) {
                    card.querySelector('.view-file-link').onclick = (e) => {
                        e.stopPropagation();
                        openFileViewer(app.diagnosticFile, app.fileType);
                    };
                }

                slotsArea.appendChild(card);
            });

            row.appendChild(hourLabel);
            row.appendChild(slotsArea);
            timelineGrid.appendChild(row);
        });
    }

    // Logout
    function logout() {
        localStorage.removeItem('adminToken');
        adminDashboard.classList.add('hidden');
        showToast('Deconectare', 'Te-ai deconectat cu succes.');
    }

    adminLogout.addEventListener('click', logout);

    const resetDatabaseBtn = document.getElementById('resetDatabaseBtn');
    resetDatabaseBtn.addEventListener('click', async () => {
        const confirm1 = confirm("Ești sigur că vrei să ștergi TOATE programările?");
        if (!confirm1) return;

        const confirm2 = confirm("CONFIRMARE FINALĂ: Toate datele vor fi șterse definitiv. Continuăm?");
        if (!confirm2) return;

        const token = localStorage.getItem('adminToken');
        try {
            const res = await fetch('/api/admin/reset', {
                method: 'POST',
                headers: { 'x-admin-token': token }
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

    exportExcelBtn.addEventListener('click', () => {
        window.location.href = '/api/admin/export';
    });

    closeDashboard.addEventListener('click', () => {
        adminDashboard.classList.add('hidden');
    });
});
