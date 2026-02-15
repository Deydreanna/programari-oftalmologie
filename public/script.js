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
                    const canvas = document.createElement('canvas');
                    if (width > height) {
                        if (width > MAX_WIDTH) {
                            height *= MAX_WIDTH / width;
                            width = MAX_WIDTH;
                        }
                    } else {
                        if (height > MAX_HEIGHT) {
                            width *= MAX_HEIGHT / height;
                            height = MAX_HEIGHT;
                        }
                    }
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

            // Fix: Use local date components to avoid timezone shift from toISOString()
            // const formattedDate = currentDayDate.toISOString().split('T')[0];
            const y = currentDayDate.getFullYear();
            const m = String(currentDayDate.getMonth() + 1).padStart(2, '0');
            const d = String(currentDayDate.getDate()).padStart(2, '0');
            const formattedDate = `${y}-${m}-${d}`;
            const isWednesday = currentDayDate.getDay() === 3;

            // Allow only future dates (or today)
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            const isPast = currentDayDate < today;

            dayDiv.className = 'calendar-day';

            if (isWednesday && !isPast) {
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

    async function selectDate(dateStr, element) {
        // Deselect previous
        const prevSelected = document.querySelector('.calendar-day.selected');
        if (prevSelected) prevSelected.classList.remove('selected');

        // Select new
        element.classList.add('selected');
        selectedDate = dateStr;

        // UI Transition
        const dateSelection = document.getElementById('date-selection');
        dateSelection.classList.add('minimized');

        // UI Updates
        selectedDateDisplay.textContent = `(${dateStr})`;

        // Show slots with animation
        slotsSection.classList.remove('hidden');
        setTimeout(() => {
            slotsSection.classList.add('active');
        }, 50);

        dateError.classList.add('hidden');

        await fetchSlots(dateStr);
    }

    prevMonthBtn.onclick = () => {
        currentDate.setMonth(currentDate.getMonth() - 1);
        renderCalendar(currentDate);
    };

    nextMonthBtn.onclick = () => {
        currentDate.setMonth(currentDate.getMonth() + 1);
        renderCalendar(currentDate);
    };

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
            btn.className = `slot-btn py-2 px-1 rounded border text-sm font-medium ${slot.available
                ? 'bg-white border-medical-200 text-medical-600 hover:bg-medical-50 hover:border-medical-500'
                : 'bg-gray-100 border-gray-200 text-gray-400 cursor-not-allowed'
                }`;
            btn.textContent = slot.time;
            btn.disabled = !slot.available;

            if (slot.available) {
                btn.onclick = () => openModal(date, slot.time);
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
    const appointmentsTableBody = document.getElementById('appointmentsTableBody');

    // Toggle Login Modal
    adminLoginBtn.addEventListener('click', () => {
        adminLoginModal.classList.remove('hidden');
    });

    closeAdminLogin.addEventListener('click', () => {
        adminLoginModal.classList.add('hidden');
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
        fetchAdminAppointments();
    }

    async function fetchAdminAppointments() {
        const token = localStorage.getItem('adminToken');
        appointmentsTableBody.innerHTML = '<tr><td colspan="6" class="px-6 py-4 text-center">Se încarcă...</td></tr>';

        try {
            const res = await fetch('/api/admin/appointments', {
                headers: { 'x-admin-token': token }
            });

            if (res.status === 403) {
                logout();
                return;
            }

            const appointments = await res.json();
            renderAdminAppointments(appointments);
        } catch (err) {
            appointmentsTableBody.innerHTML = '<tr><td colspan="6" class="px-6 py-4 text-center text-red-500">Eroare la încărcare.</td></tr>';
        }
    }

    function renderAdminAppointments(appointments) {
        appointmentsTableBody.innerHTML = '';

        if (appointments.length === 0) {
            appointmentsTableBody.innerHTML = '<tr><td colspan="6" class="px-6 py-4 text-center text-gray-500">Nu există programări.</td></tr>';
            return;
        }

        appointments.forEach(app => {
            const row = document.createElement('tr');
            row.className = 'hover:bg-gray-50';
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${app.date}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-medium">${app.time}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${app.name}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">${app.cnp || '-'}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${app.phone}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${app.type === 'Control' ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'}">
                        ${app.type}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${app.diagnosticFile
                    ? `<button class="view-file-btn text-medical-600 hover:text-medical-800 font-medium underline">Vezi</button>`
                    : '<span class="text-gray-300">-</span>'}
                </td>
            `;

            if (app.diagnosticFile) {
                row.querySelector('.view-file-btn').onclick = () => {
                    openFileViewer(app.diagnosticFile, app.fileType);
                };
            }

            appointmentsTableBody.appendChild(row);
        });
    }

    // Logout
    function logout() {
        localStorage.removeItem('adminToken');
        adminDashboard.classList.add('hidden');
        showToast('Deconectare', 'Te-ai deconectat cu succes.');
    }

    adminLogout.addEventListener('click', logout);

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
