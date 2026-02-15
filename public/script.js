document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const slotsSection = document.getElementById('slots-section');
    const slotsGrid = document.getElementById('slotsGrid');
    const selectedDateDisplay = document.getElementById('selectedDateDisplay');
    const noSlotsMessage = document.getElementById('noSlotsMessage');

    // Calendar Elements
    const calendarGrid = document.getElementById('calendarGrid');
    const currentMonthYear = document.getElementById('currentMonthYear');
    const prevMonthBtn = document.getElementById('prevMonth');
    const nextMonthBtn = document.getElementById('nextMonth');
    const dateError = document.getElementById('dateError');
    const resetBookingBtn = document.getElementById('resetBooking');

    // Modal & Form
    const bookingModal = document.getElementById('bookingModal');
    const closeModalBtn = document.getElementById('closeModal');
    const bookingForm = document.getElementById('bookingForm');
    const modalDate = document.getElementById('modalDate');
    const modalTime = document.getElementById('modalTime');
    const formDate = document.getElementById('formDate');
    const formTime = document.getElementById('formTime');
    const loadingSpinner = document.getElementById('loadingSpinner');

    // Diagnosis & File Elements
    const consultationType = document.getElementById('type');
    const diagnosisSection = document.getElementById('diagnosisSection');
    const hasDiagnosis = document.getElementById('hasDiagnosis');
    const fileUploadContainer = document.getElementById('fileUploadContainer');
    const diagnosticFileInput = document.getElementById('diagnosticFile');

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
    let currentDate = new Date(); // Tracks the displayed month
    let selectedDate = null; // Tracks the clicked date (YYYY-MM-DD)

    // --- Helpers ---

    function showToast(title, message, type = 'success') {
        toastTitle.textContent = title;
        toastMessage.textContent = message;

        toast.className = `fixed bottom-5 right-5 bg-white shadow-lg rounded-lg p-4 transform transition-all duration-300 max-w-sm z-50 border-l-4 ${type === 'success' ? 'border-green-500' : 'border-red-500'}`;

        // Show
        setTimeout(() => {
            toast.classList.remove('translate-y-20', 'opacity-0');
        }, 10);

        // Hide after 3s
        setTimeout(() => {
            toast.classList.add('translate-y-20', 'opacity-0');
        }, 4000);
    }

    function openModal(date, time) {
        modalDate.textContent = date;
        modalTime.textContent = time;
        formDate.value = date;
        formTime.value = time;

        bookingModal.classList.remove('hidden');
        setTimeout(() => {
            bookingModal.classList.add('show');
        }, 10);
    }

    function closeModal() {
        bookingModal.classList.remove('show');
        setTimeout(() => {
            bookingModal.classList.add('hidden');
            bookingForm.reset();
            diagnosisSection.classList.add('hidden');
            fileUploadContainer.classList.add('hidden');
        }, 300);
    }

    // --- File Processing ---

    async function processFile(file) {
        if (!file) return null;

        if (file.type === 'application/pdf') {
            return {
                base64: await fileToBase64(file),
                type: file.type
            };
        }

        if (file.type.startsWith('image/')) {
            const compressedBase64 = await compressImage(file);
            return {
                base64: compressedBase64,
                type: 'image/jpeg'
            };
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

    // --- Calendar Logic ---

    function renderCalendar(date) {
        calendarGrid.innerHTML = '';
        const year = date.getFullYear();
        const month = date.getMonth();

        // Update Header
        const monthName = new Intl.DateTimeFormat('ro-RO', { month: 'long', year: 'numeric' }).format(date);
        currentMonthYear.textContent = monthName.charAt(0).toUpperCase() + monthName.slice(1);

        // First day of month & number of days
        const firstDayIndex = new Date(year, month, 1).getDay(); // 0 = Sunday
        const lastDay = new Date(year, month + 1, 0).getDate();

        // Previous month filler
        for (let i = 0; i < firstDayIndex; i++) {
            const div = document.createElement('div');
            div.className = 'calendar-day empty';
            calendarGrid.appendChild(div);
        }

        // Days
        for (let i = 1; i <= lastDay; i++) {
            const dayDiv = document.createElement('div');
            dayDiv.textContent = i;

            const currentDayDate = new Date(year, month, i);
            const y = currentDayDate.getFullYear();
            const m = String(currentDayDate.getMonth() + 1).padStart(2, '0');
            const d = String(currentDayDate.getDate()).padStart(2, '0');
            const formattedDate = `${y}-${m}-${d}`;

            const isWednesday = currentDayDate.getDay() === 3;

            // Availability Restrictions:
            // 1. February (index 1) to April (index 3) 2026
            const isValidMonth = year === 2026 && month >= 1 && month <= 3;
            // 2. Disable April 8th 2026
            const isExcludedDate = formattedDate === '2026-04-08';

            // Allow only future dates (or today)
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            const isPast = currentDayDate < today;

            dayDiv.className = 'calendar-day';

            if (isWednesday && !isPast && isValidMonth && !isExcludedDate) {
                dayDiv.classList.add('active-wednesday');
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
        selectedDateDisplay.textContent = new Intl.DateTimeFormat('ro-RO', { day: 'numeric', month: 'long', year: 'numeric' }).format(new Date(date));

        // UI Transition
        const dateSelection = document.getElementById('date-selection');
        const bookingContainer = document.getElementById('booking-container');

        dateSelection.classList.add('minimized');

        // Smoother, slightly longer transition for 'breathable' layout
        setTimeout(() => {
            slotsSection.classList.remove('hidden');
            setTimeout(() => {
                slotsSection.classList.add('active');
                // Scroll to slots for mobile/smaller screens
                if (window.innerWidth < 1024) {
                    slotsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            }, 100);
        }, 400);

        // Highlight selected with Emerald
        document.querySelectorAll('.calendar-day').forEach(d => d.classList.remove('selected'));
        element.classList.add('selected');
        element.style.backgroundColor = '#10B981'; // Emerald-500
        element.style.color = 'white';

        fetchSlots(date);
    }

    function resetView() {
        const dateSelection = document.getElementById('date-selection');
        dateSelection.classList.remove('minimized');
        slotsSection.classList.remove('active');
        setTimeout(() => {
            slotsSection.classList.add('hidden');
        }, 300);

        // Deselect
        document.querySelectorAll('.calendar-day').forEach(d => d.classList.remove('selected'));
        selectedDate = null;

        // Scroll to top (Position 0)
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    resetBookingBtn.onclick = resetView;

    prevMonthBtn.onclick = () => {
        const testDate = new Date(currentDate);
        testDate.setMonth(testDate.getMonth() - 1);
        // Only allow navigation within 2026 Feb - Apr
        if (testDate.getFullYear() === 2026 && testDate.getMonth() >= 1) {
            currentDate.setMonth(currentDate.getMonth() - 1);
            renderCalendar(currentDate);
        }
    };

    nextMonthBtn.onclick = () => {
        const testDate = new Date(currentDate);
        testDate.setMonth(testDate.getMonth() + 1);
        // Only allow navigation within 2026 Feb - Apr
        if (testDate.getFullYear() === 2026 && testDate.getMonth() <= 3) {
            currentDate.setMonth(currentDate.getMonth() + 1);
            renderCalendar(currentDate);
        }
    };

    // Toggle diagnosis visibility based on Consultation Type
    consultationType.addEventListener('change', () => {
        if (consultationType.value === 'Prima Consultație') {
            diagnosisSection.classList.remove('hidden');
        } else {
            diagnosisSection.classList.add('hidden');
            hasDiagnosis.checked = false;
            fileUploadContainer.classList.add('hidden');
            diagnosticFileInput.value = '';
        }
    });

    hasDiagnosis.addEventListener('change', () => {
        if (hasDiagnosis.checked) {
            fileUploadContainer.classList.remove('hidden');
        } else {
            fileUploadContainer.classList.add('hidden');
            diagnosticFileInput.value = '';
        }
    });

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
                        <path d="M5 6a2 2 0 012-2h1v10H5V6z"></path>
                    </svg>
                    <p class="text-lg font-medium">Document PDF</p>
                </div>
            `;
            fileDownloadLink.innerHTML = `
                <a href="${base64}" download="diagnostic.pdf" 
                   class="inline-block bg-medical-600 text-white px-6 py-2 rounded-lg hover:bg-medical-700">
                   Descarcă PDF
                </a>
            `;
        } else {
            fileViewerContent.innerHTML = `<img src="${base64}" class="max-w-full h-auto rounded shadow-lg">`;
        }

        fileViewerModal.classList.remove('hidden');
    }

    // Initial Render
    renderCalendar(currentDate);


    // --- Slots Logic ---

    async function fetchSlots(date) {
        slotsGrid.innerHTML = '<div class="col-span-full text-center py-4 text-gray-500">Se încarcă intervalele...</div>';
        noSlotsMessage.classList.add('hidden');

        try {
            const res = await fetch(`/api/slots?date=${date}`);
            const slots = await res.json();

            if (res.status !== 200) {
                slotsGrid.innerHTML = `<div class="col-span-full text-center text-red-500">Eroare: ${slots.error}</div>`;
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

        slots.forEach(slot => {
            const btn = document.createElement('button');
            // Premium Emerald Slot Buttons
            btn.className = `slot-btn py-4 px-3 rounded-xl border-2 text-base font-bold transition-all duration-300 ${slot.available
                ? 'bg-white border-neutral-100 text-neutral-800 hover:border-emerald-500 hover:text-emerald-500 hover:scale-105 shadow-sm'
                : 'bg-neutral-50 border-neutral-50 text-neutral-200 cursor-not-allowed opacity-40'
                }`;
            btn.textContent = slot.time;
            btn.disabled = !slot.available;

            if (slot.available) {
                btn.onclick = () => {
                    console.log('Slot clicked:', slot.time);
                    openModal(date, slot.time);
                };
            }

            slotsGrid.appendChild(btn);
        });
    }

    // --- Booking Logic ---

    closeModalBtn.addEventListener('click', closeModal);
    bookingModal.addEventListener('click', (e) => {
        if (e.target === bookingModal) closeModal();
    });

    bookingForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const firstName = document.getElementById('firstName').value;
        const lastName = document.getElementById('lastName').value;
        const name = `${lastName} ${firstName}`;
        const phone = document.getElementById('phone').value;
        const cnp = document.getElementById('cnp').value;
        const type = document.getElementById('type').value;
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

        const submitBtn = bookingForm.querySelector('button[type="submit"]');
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
                showToast('Succes', 'Programarea a fost confirmată!');
                closeModal();
                fetchSlots(date);
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

    // --- Admin Logic ---

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

    // Ensure admin start date is a Wednesday
    while (adminActiveDate.getDay() !== 3) {
        adminActiveDate.setDate(adminActiveDate.getDate() + 1);
    }

    // Toggle Login Modal
    adminLoginBtn.addEventListener('click', () => {
        adminLoginModal.classList.remove('hidden');
        setTimeout(() => adminLoginModal.classList.add('show'), 10);
    });

    closeAdminLogin.addEventListener('click', () => {
        adminLoginModal.classList.remove('show');
        setTimeout(() => adminLoginModal.classList.add('hidden'), 300);
    });

    // Login Submission
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

    // Dashboard Logic
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
        adminActiveDate.setDate(adminActiveDate.getDate() - 7); // Jump to previous Wednesday
        updateAdminDateDisplay();
        fetchAdminAppointments();
    };

    nextAdminDate.onclick = () => {
        adminActiveDate.setDate(adminActiveDate.getDate() + 7); // Jump to next Wednesday
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
                storageText.textContent = `${data.usedSizeMB} MB folosiți din ${data.totalSizeMB} MB (${data.percentUsed}%)`;

                // Change color if getting full
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
        timelineGrid.innerHTML = '<div class="p-10 text-center text-gray-500">Se încarcă programările...</div>';

        try {
            const res = await fetch('/api/admin/appointments', {
                headers: { 'x-admin-token': token }
            });

            const appointments = await res.json().catch(() => null);

            if (!res.ok) {
                throw new Error(appointments?.error || `Server error: ${res.status}`);
            }

            console.log('Fetched appointments:', appointments);

            if (!Array.isArray(appointments)) {
                throw new Error('Data format error: output is not an array.');
            }

            // Filter appointments for the active date
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
                <span class="text-[10px] opacity-50 font-sans tracking-normal uppercase">${err.message}</span>
            </div>`;
        }
    }

    function renderTimeline(appointments) {
        timelineGrid.innerHTML = '';

        // Generate slots from 09:00 to 13:40 (matching your clinic hours and 20-min slots)
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

            // Find appointments for this slot
            const appsInSlot = appointments.filter(a => a.time === time);

            appsInSlot.forEach((app) => {
                const card = document.createElement('div');
                card.className = `appointment-card ${app.type === 'Control' ? 'app-type-control' : 'app-type-prima'}`;

                card.innerHTML = `
                    <div class="flex items-center gap-4 w-full">
                        <span class="font-black text-gray-800">➊ ${app.name}</span>
                        ${app.type === 'Prima Consultație' ? '<span class="app-new-badge">(NOU)</span>' : ''}
                        <span class="text-gray-600">|</span>
                        <span><strong class="text-[9px] uppercase opacity-60">Tel:</strong> ${app.phone}</span>
                        <span class="text-gray-600">|</span>
                        <span><strong class="text-[9px] uppercase opacity-60">CNP:</strong> ${app.cnp}</span>
                        <span class="text-gray-600">|</span>
                        <span><strong class="text-[9px] uppercase opacity-60">Tip:</strong> ${app.type}</span>
                        ${app.diagnosticFile ? `
                            <button class="ml-auto bg-medical-600 text-white rounded px-2 py-0.5 text-[10px] hover:bg-medical-700 view-file-link shadow-sm">DOC</button>
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
        const confirm1 = confirm("Ești sigur că vrei să ștergi TOATE programările? Această acțiune este ireversibilă.");
        if (!confirm1) return;

        const confirm2 = confirm("CONFIRMARE FINALĂ: Toate datele pacienților și fișierele încărcate vor fi șterse definitiv. Continuăm?");
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
                showToast('Eroare', data.error || 'Nu s-a putut reseta baza de date.', 'error');
            }
        } catch (err) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    });

    exportExcelBtn.addEventListener('click', () => {
        // Direct download
        window.location.href = '/api/admin/export';
    });

    closeDashboard.addEventListener('click', () => {
        adminDashboard.classList.add('hidden');
    });

    // Auto-open if logged in (Optional, maybe annoying if user just wants to see site)
    // if (localStorage.getItem('adminToken')) {
    //     openDashboard();
    // }
});
