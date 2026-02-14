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
        }, 300);
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

        // UI Updates
        selectedDateDisplay.textContent = `(${dateStr})`;
        slotsSection.classList.remove('hidden');
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
                body: JSON.stringify({ name, phone, cnp, type, date, time })
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
            `;
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
