
document.addEventListener('DOMContentLoaded', () => {
    const byId = (id) => document.getElementById(id);

    const el = {
        authGuest: byId('authGuest'),
        authUser: byId('authUser'),
        authUserName: byId('authUserName'),
        logoutBtn: byId('logoutBtn'),
        adminAuthRequired: byId('adminAuthRequired'),
        adminAccessDenied: byId('adminAccessDenied'),
        adminApp: byId('adminApp'),
        closeDashboard: byId('closeDashboard'),
        exportExcelBtn: byId('exportExcelBtn'),
        timelineGrid: byId('timelineGrid'),
        currentAdminDateDisplay: byId('currentAdminDateDisplay'),
        prevAdminDate: byId('prevAdminDate'),
        nextAdminDate: byId('nextAdminDate'),
        timelineHeaderCount: byId('timelineHeaderCount'),
        appointmentDoctorFilter: byId('appointmentDoctorFilter'),
        manageUsersBtn: byId('manageUsersBtn'),
        manageDoctorsBtn: byId('manageDoctorsBtn'),
        userManagerContainer: byId('userManagerContainer'),
        doctorManagerContainer: byId('doctorManagerContainer'),
        timelineContainer: byId('timelineContainer'),
        backToTimeline: byId('backToTimeline'),
        backToTimelineFromDoctors: byId('backToTimelineFromDoctors'),
        userTableBody: byId('userTableBody'),
        doctorTableBody: byId('doctorTableBody'),
        resetDatabaseBtn: byId('resetDatabaseBtn'),
        cancelDayAppointmentsBtn: byId('cancelDayAppointmentsBtn'),
        adminActionButtons: byId('adminActionButtons'),
        createUserCard: byId('createUserCard'),
        createUserForm: byId('createUserForm'),
        newUserDisplayName: byId('newUserDisplayName'),
        newUserEmail: byId('newUserEmail'),
        newUserPhone: byId('newUserPhone'),
        newUserPassword: byId('newUserPassword'),
        newUserRole: byId('newUserRole'),
        newUserManagedDoctors: byId('newUserManagedDoctors'),
        createUserSubmit: byId('createUserSubmit'),
        createDoctorForm: byId('createDoctorForm'),
        createDoctorSubmit: byId('createDoctorSubmit'),
        doctorSlug: byId('doctorSlug'),
        doctorDisplayName: byId('doctorDisplayName'),
        doctorSpecialty: byId('doctorSpecialty'),
        doctorIsActive: byId('doctorIsActive'),
        doctorWorkdayStart: byId('doctorWorkdayStart'),
        doctorWorkdayEnd: byId('doctorWorkdayEnd'),
        doctorDuration: byId('doctorDuration'),
        doctorMonthsToShow: byId('doctorMonthsToShow'),
        doctorWeekdays: byId('doctorWeekdays'),
        toast: byId('toast'),
        toastTitle: byId('toastTitle'),
        toastMessage: byId('toastMessage')
    };

    if (!el.adminApp || !el.toast || !el.timelineGrid) {
        return;
    }

    let initialized = false;
    let adminActiveDate = new Date();
    adminActiveDate.setHours(0, 0, 0, 0);

    let doctorsCache = [];
    let appointmentsCache = [];
    let usersCache = [];
    let searchTerm = '';

    const isStaffRole = (role) => role === 'viewer' || role === 'scheduler' || role === 'superadmin';
    const isSuperadmin = () => (AUTH.getUser()?.role || '') === 'superadmin';
    const isSchedulerOrSuperadmin = () => ['scheduler', 'superadmin'].includes(AUTH.getUser()?.role || '');

    function toISODate(date) {
        const y = date.getFullYear();
        const m = String(date.getMonth() + 1).padStart(2, '0');
        const d = String(date.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
    }

    function clearNode(node) {
        while (node.firstChild) {
            node.removeChild(node.firstChild);
        }
    }

    function setSingleMessage(container, text, className) {
        clearNode(container);
        const div = document.createElement('div');
        div.className = className;
        div.textContent = text;
        container.appendChild(div);
    }

    function showToast(title, message, type = 'success') {
        el.toastTitle.textContent = title;
        el.toastMessage.textContent = message;
        el.toast.className = `fixed bottom-5 right-5 bg-brand-800 shadow-xl rounded-xl p-5 transform transition-all duration-300 max-w-sm z-50 border-l-4 border border-brand-600/30 ${type === 'success' ? 'border-l-brand-400' : 'border-l-red-400'}`;
        el.toastTitle.className = `font-bold ${type === 'success' ? 'text-brand-100' : 'text-red-300'}`;
        el.toastMessage.className = `text-sm mt-1 ${type === 'success' ? 'text-brand-300' : 'text-red-200'}`;

        setTimeout(() => {
            el.toast.classList.remove('translate-y-20', 'opacity-0');
        }, 10);
        setTimeout(() => {
            el.toast.classList.add('translate-y-20', 'opacity-0');
        }, 12000);
    }

    async function requestStepUp(action, actionLabel) {
        const password = window.prompt(`Confirmati parola pentru ${actionLabel}:`);
        if (!password) return null;

        try {
            const res = await AUTH.apiFetch('/api/auth/step-up', {
                method: 'POST',
                body: JSON.stringify({ password, action })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok || !data.stepUpToken) {
                showToast('Eroare', data.error || 'Confirmarea pasului suplimentar a esuat.', 'error');
                return null;
            }
            return data.stepUpToken;
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune la validarea pasului suplimentar.', 'error');
            return null;
        }
    }

    function updateAuthUI(user) {
        if (!user) {
            el.authGuest.classList.remove('hidden');
            el.authUser.classList.add('hidden');
            return;
        }

        el.authGuest.classList.add('hidden');
        el.authUser.classList.remove('hidden');
        el.authUserName.textContent = `${user.displayName} [${user.role || 'viewer'}]`;
    }

    function showScreen(mode) {
        el.adminApp.classList.add('hidden');
        el.adminAuthRequired.classList.add('hidden');
        el.adminAccessDenied.classList.add('hidden');

        if (mode === 'auth') {
            el.adminAuthRequired.classList.remove('hidden');
        } else if (mode === 'denied') {
            el.adminAccessDenied.classList.remove('hidden');
        } else {
            el.adminApp.classList.remove('hidden');
        }
    }

    function getAdminActiveDateISO() {
        return toISODate(adminActiveDate);
    }

    function updateAdminDateDisplay() {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const isToday = adminActiveDate.getTime() === today.getTime();
        const dateStr = new Intl.DateTimeFormat('ro-RO', { day: 'numeric', month: 'long', year: 'numeric' }).format(adminActiveDate);
        el.currentAdminDateDisplay.textContent = (isToday ? 'Azi, ' : '') + dateStr;
    }

    function setupAdminSearch() {
        if (!el.adminActionButtons || byId('adminSearchInput')) {
            return;
        }

        const searchInput = document.createElement('input');
        searchInput.id = 'adminSearchInput';
        searchInput.type = 'text';
        searchInput.placeholder = 'Cauta nume, telefon sau email...';
        searchInput.className = 'px-4 py-2 rounded-xl bg-brand-800 border border-brand-600/30 text-brand-100 placeholder-brand-400/50 text-sm focus:outline-none focus:border-brand-400 transition-all w-full md:w-64 order-first md:order-none';

        searchInput.addEventListener('input', () => {
            searchTerm = searchInput.value.toLowerCase();
            renderTimelineForCurrentFilters();
        });

        el.adminActionButtons.prepend(searchInput);
    }

    async function fetchAdminStats() {
        if (!isSuperadmin()) return;

        const storageIndicator = byId('storage-indicator');
        const storageBar = byId('storage-bar');
        const storageText = byId('storage-text');

        if (!storageIndicator || !storageBar || !storageText) {
            return;
        }

        try {
            const res = await AUTH.apiFetch('/api/admin/stats');
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                return;
            }

            storageIndicator.classList.remove('hidden');
            storageBar.style.width = `${Math.min(Number(data.percentUsed) || 0, 100)}%`;
            storageText.textContent = `${data.usedSizeMB} MB / ${data.totalSizeMB} MB (${data.percentUsed}%)`;

            storageBar.classList.toggle('bg-red-500', Number(data.percentUsed) > 80);
            storageBar.classList.toggle('bg-brand-400', Number(data.percentUsed) <= 80);
        } catch (_) {
            // no-op
        }
    }

    function fillDoctorSelectors() {
        if (el.appointmentDoctorFilter) {
            const currentValue = el.appointmentDoctorFilter.value;
            clearNode(el.appointmentDoctorFilter);

            const allOption = document.createElement('option');
            allOption.value = '';
            allOption.textContent = 'Toți medicii';
            el.appointmentDoctorFilter.appendChild(allOption);

            doctorsCache.forEach((doctor) => {
                const option = document.createElement('option');
                option.value = String(doctor._id);
                option.textContent = `${doctor.displayName} (${doctor.slug})`;
                el.appointmentDoctorFilter.appendChild(option);
            });

            if ([...el.appointmentDoctorFilter.options].some((opt) => opt.value === currentValue)) {
                el.appointmentDoctorFilter.value = currentValue;
            }
        }

        if (el.newUserManagedDoctors) {
            const selectedValues = new Set(Array.from(el.newUserManagedDoctors.selectedOptions).map((opt) => opt.value));
            clearNode(el.newUserManagedDoctors);
            doctorsCache.forEach((doctor) => {
                const option = document.createElement('option');
                option.value = String(doctor._id);
                option.textContent = `${doctor.displayName} (${doctor.slug})`;
                option.selected = selectedValues.has(option.value);
                el.newUserManagedDoctors.appendChild(option);
            });
        }
    }

    async function fetchDoctors() {
        try {
            const res = await AUTH.apiFetch('/api/admin/doctors');
            const data = await res.json().catch(() => []);
            if (!res.ok) {
                doctorsCache = [];
                fillDoctorSelectors();
                return;
            }
            doctorsCache = Array.isArray(data) ? data : [];
            fillDoctorSelectors();
            renderDoctorsTable();
        } catch (_) {
            doctorsCache = [];
            fillDoctorSelectors();
        }
    }
    function getFilteredAppointments() {
        const activeDate = getAdminActiveDateISO();
        const doctorFilter = String(el.appointmentDoctorFilter?.value || '');

        return appointmentsCache
            .filter((app) => app.date === activeDate)
            .filter((app) => !doctorFilter || String(app.doctorId || '') === doctorFilter)
            .filter((app) => {
                if (!searchTerm) return true;
                return String(app.name || '').toLowerCase().includes(searchTerm)
                    || String(app.phone || '').toLowerCase().includes(searchTerm)
                    || String(app.email || '').toLowerCase().includes(searchTerm)
                    || String(app.doctorSnapshotName || '').toLowerCase().includes(searchTerm);
            });
    }

    function renderTimeline(appointments) {
        clearNode(el.timelineGrid);

        if (!appointments.length) {
            setSingleMessage(el.timelineGrid, 'Nu exista programari pentru filtrele selectate.', 'p-10 text-center text-brand-400 font-medium');
            return;
        }

        const allowResend = isSchedulerOrSuperadmin();
        const allowDelete = isSuperadmin();

        const sorted = [...appointments].sort((a, b) => {
            if (a.time === b.time) {
                return String(a.name || '').localeCompare(String(b.name || ''));
            }
            return String(a.time || '').localeCompare(String(b.time || ''));
        });

        const labeled = (label, value) => {
            const wrapper = document.createElement('span');
            wrapper.className = 'text-brand-300';
            const strong = document.createElement('strong');
            strong.className = 'font-inter text-[11px] uppercase text-brand-400/50';
            strong.textContent = `${label}:`;
            wrapper.appendChild(strong);
            wrapper.appendChild(document.createTextNode(` ${value}`));
            return wrapper;
        };

        sorted.forEach((app) => {
            const row = document.createElement('div');
            row.className = 'timeline-row';

            const hourLabel = document.createElement('div');
            hourLabel.className = 'timeline-hour';
            hourLabel.textContent = app.time || '--:--';

            const slotsArea = document.createElement('div');
            slotsArea.className = 'timeline-slots';

            const card = document.createElement('div');
            card.className = `appointment-card ${(app.type === 'Control') ? 'app-type-control' : 'app-type-prima'}`;

            const content = document.createElement('div');
            content.className = 'flex items-center gap-3 flex-wrap';

            const nameEl = document.createElement('span');
            nameEl.className = 'font-bold text-brand-100';
            nameEl.textContent = app.name || '';
            content.appendChild(nameEl);

            if (app.type === 'Prima Consultatie' || app.type === 'Prima Consultație') {
                const badge = document.createElement('span');
                badge.className = 'app-new-badge';
                badge.textContent = 'NOU';
                content.appendChild(badge);
            }

            content.appendChild(labeled('Medic', app.doctorSnapshotName || '-'));
            content.appendChild(labeled('Email', app.email || '-'));
            content.appendChild(labeled('Tel', app.phone || '-'));
            content.appendChild(labeled('Tip', app.type || '-'));

            const status = document.createElement('span');
            status.className = `px-2 py-0.5 rounded-lg text-[10px] font-bold uppercase ${app.emailSent ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`;
            status.textContent = app.emailSent ? 'Trimis' : 'Netrimis';
            content.appendChild(status);

            if (allowResend) {
                const resendBtn = document.createElement('button');
                resendBtn.className = 'resend-email-btn bg-brand-400/10 hover:bg-brand-400/20 text-brand-400 px-2 py-1 rounded-lg text-[10px] font-bold uppercase transition-all';
                resendBtn.textContent = 'Trimite Manual';

                resendBtn.onclick = async (event) => {
                    event.stopPropagation();
                    resendBtn.disabled = true;
                    const originalText = resendBtn.textContent;
                    resendBtn.textContent = 'Se trimite...';
                    try {
                        const res = await AUTH.apiFetch(`/api/admin/resend-email/${app._id}`, { method: 'POST' });
                        const data = await res.json().catch(() => ({}));
                        if (res.ok) {
                            showToast('Succes', data.message || 'Email trimis.');
                            await fetchAdminAppointments();
                        } else {
                            showToast('Eroare', data.error || 'Eroare la trimitere.', 'error');
                        }
                    } catch (_) {
                        showToast('Eroare', 'Eroare de conexiune.', 'error');
                    } finally {
                        resendBtn.disabled = false;
                        resendBtn.textContent = originalText;
                    }
                };

                content.appendChild(resendBtn);
            }

            if (allowDelete) {
                const cancelBtn = document.createElement('button');
                cancelBtn.className = 'cancel-appointment-btn bg-red-500/10 hover:bg-red-500/20 text-red-300 px-2 py-1 rounded-lg text-[10px] font-bold uppercase transition-all';
                cancelBtn.textContent = 'Anuleaza';

                cancelBtn.onclick = async (event) => {
                    event.stopPropagation();
                    const confirmDelete = window.confirm(`Esti sigur ca vrei sa anulezi programarea pacientului ${app.name || ''}?`);
                    if (!confirmDelete) return;

                    const stepUpToken = await requestStepUp('appointment_delete', 'stergerea programarii');
                    if (!stepUpToken) return;

                    try {
                        const res = await AUTH.apiFetch(`/api/admin/appointment/${app._id}`, {
                            method: 'DELETE',
                            headers: { 'X-Step-Up-Token': stepUpToken }
                        });
                        const data = await res.json().catch(() => ({}));
                        if (res.ok) {
                            showToast('Succes', data.message || 'Programare anulata.');
                            await fetchAdminAppointments();
                            fetchAdminStats();
                        } else {
                            showToast('Eroare', data.error || 'Nu s-a putut anula programarea.', 'error');
                        }
                    } catch (_) {
                        showToast('Eroare', 'Eroare de conexiune.', 'error');
                    }
                };

                content.appendChild(cancelBtn);
            }

            card.appendChild(content);
            slotsArea.appendChild(card);

            row.appendChild(hourLabel);
            row.appendChild(slotsArea);
            el.timelineGrid.appendChild(row);
        });
    }

    function renderTimelineForCurrentFilters() {
        const filtered = getFilteredAppointments();
        el.timelineHeaderCount.textContent = `(${filtered.length}) Programari`;
        renderTimeline(filtered);
    }

    async function fetchAdminAppointments() {
        setSingleMessage(el.timelineGrid, 'Se incarca programarile...', 'p-10 text-center text-gray-400 font-medium font-inter');

        try {
            const res = await AUTH.apiFetch('/api/admin/appointments');
            const data = await res.json().catch(() => []);

            if (!res.ok) {
                throw new Error(data?.error || `Server error: ${res.status}`);
            }

            appointmentsCache = Array.isArray(data) ? data : [];
            renderTimelineForCurrentFilters();
        } catch (error) {
            setSingleMessage(el.timelineGrid, String(error?.message || 'Eroare la incarcare.'), 'p-10 text-center text-red-400 font-medium');
        }
    }

    async function fetchUsers() {
        clearNode(el.userTableBody);
        const loadingRow = document.createElement('tr');
        const loadingCell = document.createElement('td');
        loadingCell.colSpan = 6;
        loadingCell.className = 'p-10 text-center text-brand-400';
        loadingCell.textContent = 'Se incarca lista de utilizatori...';
        loadingRow.appendChild(loadingCell);
        el.userTableBody.appendChild(loadingRow);

        try {
            const res = await AUTH.apiFetch('/api/admin/users');
            const data = await res.json().catch(() => []);
            if (!res.ok) {
                showToast('Eroare', data.error || 'Eroare la preluare utilizatori.', 'error');
                return;
            }
            usersCache = Array.isArray(data) ? data : [];
            renderUsers(usersCache);
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune server.', 'error');
        }
    }

    async function openEditUserDialog(user) {
        const displayName = window.prompt('Nume afisat:', user.displayName || '');
        if (displayName === null) return;
        const email = window.prompt('Email:', user.email || '');
        if (email === null) return;
        const phone = window.prompt('Telefon:', user.phone || '');
        if (phone === null) return;
        const role = window.prompt('Rol (viewer/scheduler/superadmin):', user.role || 'viewer');
        if (role === null) return;

        const currentManaged = Array.isArray(user.managedDoctorIds) ? user.managedDoctorIds.join(',') : '';
        const doctorOptions = doctorsCache.map((doctor) => `${doctor._id} => ${doctor.displayName}`).join('\\n');
        const doctorIdsInput = window.prompt(`Doctor IDs asignati (separate prin virgula):\\n${doctorOptions}`, currentManaged);
        if (doctorIdsInput === null) return;

        const newPassword = window.prompt('Parola noua (lasati gol pentru neschimbat):', '');
        if (newPassword === null) return;

        const managedDoctorIds = doctorIdsInput
            .split(',')
            .map((v) => v.trim())
            .filter(Boolean);

        const payload = {
            displayName: displayName.trim(),
            email: email.trim(),
            phone: phone.trim(),
            role: role.trim(),
            managedDoctorIds
        };
        if (newPassword.trim()) {
            payload.password = newPassword;
        }

        const stepUpToken = await requestStepUp('user_update', 'modificarea utilizatorului');
        if (!stepUpToken) return;

        try {
            const res = await AUTH.apiFetch(`/api/admin/users/${user._id}`, {
                method: 'PATCH',
                headers: { 'X-Step-Up-Token': stepUpToken },
                body: JSON.stringify(payload)
            });
            const data = await res.json().catch(() => ({}));
            if (res.ok) {
                showToast('Succes', 'Utilizator actualizat.');
                await fetchUsers();
            } else {
                showToast('Eroare', data.error || 'Nu s-a putut actualiza utilizatorul.', 'error');
            }
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    }

    async function deleteUser(user) {
        const confirmed = window.confirm(`Esti sigur ca vrei sa stergi utilizatorul ${user.displayName || user.email}?`);
        if (!confirmed) return;

        const stepUpToken = await requestStepUp('user_delete', 'stergerea utilizatorului');
        if (!stepUpToken) return;

        try {
            const res = await AUTH.apiFetch(`/api/admin/users/${user._id}`, {
                method: 'DELETE',
                headers: { 'X-Step-Up-Token': stepUpToken }
            });
            const data = await res.json().catch(() => ({}));
            if (res.ok) {
                showToast('Succes', data.message || 'Utilizator sters.');
                await fetchUsers();
            } else {
                showToast('Eroare', data.error || 'Nu s-a putut sterge utilizatorul.', 'error');
            }
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    }

    function renderUsers(users) {
        clearNode(el.userTableBody);

        const currentUser = AUTH.getUser() || {};
        users.forEach((user) => {
            const row = document.createElement('tr');
            row.className = 'border-b border-brand-600/10 hover:bg-brand-600/5 transition-colors';

            const nameCell = document.createElement('td');
            nameCell.className = 'py-4 font-medium';
            nameCell.textContent = user.displayName || '';

            const emailCell = document.createElement('td');
            emailCell.className = 'py-4 text-brand-400';
            emailCell.textContent = user.email || '';

            const phoneCell = document.createElement('td');
            phoneCell.className = 'py-4 text-brand-400';
            phoneCell.textContent = user.phone || '';

            const roleCell = document.createElement('td');
            roleCell.className = 'py-4 text-center';
            roleCell.textContent = user.role || 'viewer';

            const doctorsCell = document.createElement('td');
            doctorsCell.className = 'py-4 text-brand-300';
            const managedDoctors = Array.isArray(user.managedDoctors) ? user.managedDoctors : [];
            doctorsCell.textContent = managedDoctors.length
                ? managedDoctors.map((doctor) => doctor.displayName).join(', ')
                : '-';

            const actionsCell = document.createElement('td');
            actionsCell.className = 'py-4 text-right';
            const actionWrap = document.createElement('div');
            actionWrap.className = 'flex items-center gap-2 justify-end';

            const editBtn = document.createElement('button');
            editBtn.className = 'admin-action-btn bg-brand-600/20 text-brand-300 border-brand-600/30 hover:bg-brand-600/30';
            editBtn.textContent = 'Editeaza';
            editBtn.onclick = () => openEditUserDialog(user);

            actionWrap.appendChild(editBtn);

            const isSelf = String(user.email || '') === String(currentUser.email || '');
            if (!isSelf) {
                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'admin-action-btn bg-red-900/30 text-red-300 border-red-800/40 hover:bg-red-900/50';
                deleteBtn.textContent = 'Sterge';
                deleteBtn.onclick = () => deleteUser(user);
                actionWrap.appendChild(deleteBtn);
            }

            actionsCell.appendChild(actionWrap);

            row.appendChild(nameCell);
            row.appendChild(emailCell);
            row.appendChild(phoneCell);
            row.appendChild(roleCell);
            row.appendChild(doctorsCell);
            row.appendChild(actionsCell);
            el.userTableBody.appendChild(row);
        });
    }

    async function createUser() {
        if (!isSuperadmin()) {
            showToast('Acces interzis', 'Doar superadmin poate crea utilizatori.', 'error');
            return;
        }

        const managedDoctorIds = Array.from(el.newUserManagedDoctors.selectedOptions).map((opt) => opt.value);

        const payload = {
            displayName: el.newUserDisplayName.value.trim(),
            email: el.newUserEmail.value.trim(),
            phone: el.newUserPhone.value.trim(),
            password: el.newUserPassword.value,
            role: el.newUserRole.value,
            managedDoctorIds
        };

        if (!payload.displayName || !payload.email || !payload.phone || !payload.password) {
            showToast('Eroare', 'Completeaza toate campurile utilizatorului.', 'error');
            return;
        }

        if (payload.password.length < 10) {
            showToast('Eroare', 'Parola trebuie sa aiba minim 10 caractere.', 'error');
            return;
        }

        el.createUserSubmit.disabled = true;
        try {
            const res = await AUTH.apiFetch('/api/admin/users', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showToast('Eroare', data.error || 'Nu s-a putut crea utilizatorul.', 'error');
                return;
            }

            showToast('Succes', `Utilizatorul ${data.user?.displayName || payload.displayName} a fost creat.`);
            el.createUserForm.reset();
            await fetchUsers();
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        } finally {
            el.createUserSubmit.disabled = false;
        }
    }
    function weekdaysToArray(input) {
        return String(input || '')
            .split(',')
            .map((item) => Number(item.trim()))
            .filter((value) => Number.isInteger(value) && value >= 0 && value <= 6);
    }

    async function createDoctor() {
        const weekdays = weekdaysToArray(el.doctorWeekdays.value);
        if (!weekdays.length) {
            showToast('Eroare', 'Introdu cel putin o zi valida (0-6).', 'error');
            return;
        }

        const payload = {
            slug: el.doctorSlug.value.trim().toLowerCase(),
            displayName: el.doctorDisplayName.value.trim(),
            specialty: el.doctorSpecialty.value.trim() || 'Oftalmologie',
            isActive: el.doctorIsActive.value === 'true',
            bookingSettings: {
                consultationDurationMinutes: Number(el.doctorDuration.value),
                workdayStart: el.doctorWorkdayStart.value,
                workdayEnd: el.doctorWorkdayEnd.value,
                monthsToShow: Number(el.doctorMonthsToShow.value),
                timezone: 'Europe/Bucharest'
            },
            availabilityRules: { weekdays },
            blockedDates: []
        };

        if (!payload.slug || !payload.displayName) {
            showToast('Eroare', 'Slug si nume afisat sunt obligatorii.', 'error');
            return;
        }

        el.createDoctorSubmit.disabled = true;
        try {
            const res = await AUTH.apiFetch('/api/admin/doctors', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showToast('Eroare', data.error || 'Nu s-a putut crea medicul.', 'error');
                return;
            }
            showToast('Succes', 'Medic creat.');
            el.createDoctorForm.reset();
            await fetchDoctors();
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        } finally {
            el.createDoctorSubmit.disabled = false;
        }
    }

    async function patchDoctor(doctorId, payload, successMsg) {
        try {
            const res = await AUTH.apiFetch(`/api/admin/doctors/${doctorId}`, {
                method: 'PATCH',
                body: JSON.stringify(payload)
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showToast('Eroare', data.error || 'Nu s-a putut actualiza medicul.', 'error');
                return false;
            }
            showToast('Succes', successMsg || 'Medic actualizat.');
            await fetchDoctors();
            await fetchAdminAppointments();
            return true;
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
            return false;
        }
    }

    async function openEditDoctorDialog(doctor) {
        const displayName = window.prompt('Nume afisat:', doctor.displayName || '');
        if (displayName === null) return;
        const specialty = window.prompt('Specialitate:', doctor.specialty || 'Oftalmologie');
        if (specialty === null) return;

        const start = window.prompt('Ora inceput (HH:mm):', doctor.bookingSettings?.workdayStart || '09:00');
        if (start === null) return;
        const end = window.prompt('Ora sfarsit (HH:mm):', doctor.bookingSettings?.workdayEnd || '14:00');
        if (end === null) return;
        const duration = window.prompt('Durata consultatie (minute):', String(doctor.bookingSettings?.consultationDurationMinutes || 20));
        if (duration === null) return;
        const monthsToShow = window.prompt('Luni vizibile:', String(doctor.bookingSettings?.monthsToShow || 3));
        if (monthsToShow === null) return;
        const weekdays = window.prompt('Zile disponibile (0-6, separate prin virgula):', String((doctor.availabilityRules?.weekdays || []).join(',')));
        if (weekdays === null) return;
        const isActiveRaw = window.prompt('Activ? (true/false):', String(!!doctor.isActive));
        if (isActiveRaw === null) return;

        const weekdaysList = weekdaysToArray(weekdays);
        if (!weekdaysList.length) {
            showToast('Eroare', 'Lista de zile este invalida.', 'error');
            return;
        }

        await patchDoctor(doctor._id, {
            displayName: displayName.trim(),
            specialty: specialty.trim(),
            isActive: isActiveRaw.trim().toLowerCase() === 'true',
            bookingSettings: {
                consultationDurationMinutes: Number(duration),
                workdayStart: start.trim(),
                workdayEnd: end.trim(),
                monthsToShow: Number(monthsToShow),
                timezone: doctor.bookingSettings?.timezone || 'Europe/Bucharest'
            },
            availabilityRules: { weekdays: weekdaysList }
        }, 'Medic actualizat.');
    }

    async function blockDoctorDate(doctor) {
        const date = window.prompt('Data de blocat (YYYY-MM-DD):');
        if (!date) return;

        try {
            const res = await AUTH.apiFetch(`/api/admin/doctors/${doctor._id}/block-date`, {
                method: 'POST',
                body: JSON.stringify({ date: date.trim() })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showToast('Eroare', data.error || 'Nu s-a putut bloca data.', 'error');
                return;
            }
            showToast('Succes', `Ziua ${date} a fost blocata pentru ${doctor.displayName}.`);
            await fetchDoctors();
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    }

    async function unblockDoctorDate(doctor) {
        const date = window.prompt('Data de reactivat (YYYY-MM-DD):');
        if (!date) return;

        try {
            const res = await AUTH.apiFetch(`/api/admin/doctors/${doctor._id}/block-date/${date.trim()}`, {
                method: 'DELETE'
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showToast('Eroare', data.error || 'Nu s-a putut reactiva data.', 'error');
                return;
            }
            showToast('Succes', `Ziua ${date} a fost reactivata pentru ${doctor.displayName}.`);
            await fetchDoctors();
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    }

    function renderDoctorsTable() {
        if (!el.doctorTableBody) return;

        clearNode(el.doctorTableBody);
        if (!doctorsCache.length) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 6;
            cell.className = 'p-10 text-center text-brand-400';
            cell.textContent = 'Nu exista medici disponibili.';
            row.appendChild(cell);
            el.doctorTableBody.appendChild(row);
            return;
        }

        doctorsCache.forEach((doctor) => {
            const row = document.createElement('tr');
            row.className = 'border-b border-brand-600/10 hover:bg-brand-600/5 transition-colors';

            const nameCell = document.createElement('td');
            nameCell.className = 'py-4 font-medium';
            nameCell.textContent = doctor.displayName || '';

            const slugCell = document.createElement('td');
            slugCell.className = 'py-4 text-brand-400';
            slugCell.textContent = doctor.slug || '';

            const scheduleCell = document.createElement('td');
            scheduleCell.className = 'py-4 text-brand-300';
            scheduleCell.textContent = `${doctor.bookingSettings?.workdayStart || '-'}-${doctor.bookingSettings?.workdayEnd || '-'} / ${doctor.bookingSettings?.consultationDurationMinutes || '-'} min`;

            const weekdaysCell = document.createElement('td');
            weekdaysCell.className = 'py-4 text-brand-300';
            weekdaysCell.textContent = Array.isArray(doctor.availabilityRules?.weekdays)
                ? doctor.availabilityRules.weekdays.join(', ')
                : '-';

            const activeCell = document.createElement('td');
            activeCell.className = 'py-4 text-brand-300';
            activeCell.textContent = doctor.isActive ? 'Da' : 'Nu';

            const actionsCell = document.createElement('td');
            actionsCell.className = 'py-4 text-right';
            const actionWrap = document.createElement('div');
            actionWrap.className = 'flex items-center gap-2 justify-end';

            const editBtn = document.createElement('button');
            editBtn.className = 'admin-action-btn bg-brand-600/20 text-brand-300 border-brand-600/30 hover:bg-brand-600/30';
            editBtn.textContent = 'Editeaza';
            editBtn.onclick = () => openEditDoctorDialog(doctor);
            actionWrap.appendChild(editBtn);

            const blockBtn = document.createElement('button');
            blockBtn.className = 'admin-action-btn bg-orange-900/30 text-orange-300 border-orange-800/40 hover:bg-orange-900/50';
            blockBtn.textContent = 'Blocheaza zi';
            blockBtn.onclick = () => blockDoctorDate(doctor);
            actionWrap.appendChild(blockBtn);

            const unblockBtn = document.createElement('button');
            unblockBtn.className = 'admin-action-btn bg-brand-600/20 text-brand-300 border-brand-600/30 hover:bg-brand-600/30';
            unblockBtn.textContent = 'Reactiveaza zi';
            unblockBtn.onclick = () => unblockDoctorDate(doctor);
            actionWrap.appendChild(unblockBtn);

            const toggleBtn = document.createElement('button');
            toggleBtn.className = 'admin-action-btn bg-brand-600/20 text-brand-300 border-brand-600/30 hover:bg-brand-600/30';
            toggleBtn.textContent = doctor.isActive ? 'Dezactiveaza' : 'Activeaza';
            toggleBtn.onclick = () => patchDoctor(doctor._id, { isActive: !doctor.isActive }, 'Status medic actualizat.');
            actionWrap.appendChild(toggleBtn);

            actionsCell.appendChild(actionWrap);

            row.appendChild(nameCell);
            row.appendChild(slugCell);
            row.appendChild(scheduleCell);
            row.appendChild(weekdaysCell);
            row.appendChild(activeCell);
            row.appendChild(actionsCell);
            el.doctorTableBody.appendChild(row);
        });
    }
    function showTimelineSection() {
        el.userManagerContainer.classList.add('hidden');
        el.doctorManagerContainer.classList.add('hidden');
        el.timelineContainer.classList.remove('hidden');
    }

    function showUserSection() {
        el.timelineContainer.classList.add('hidden');
        el.doctorManagerContainer.classList.add('hidden');
        el.userManagerContainer.classList.remove('hidden');
    }

    function showDoctorSection() {
        el.timelineContainer.classList.add('hidden');
        el.userManagerContainer.classList.add('hidden');
        el.doctorManagerContainer.classList.remove('hidden');
    }

    function registerEvents() {
        el.logoutBtn.addEventListener('click', async () => {
            await AUTH.logout();
            window.location.href = '/login.html';
        });

        el.prevAdminDate.onclick = () => {
            adminActiveDate.setDate(adminActiveDate.getDate() - 1);
            updateAdminDateDisplay();
            renderTimelineForCurrentFilters();
        };

        el.nextAdminDate.onclick = () => {
            adminActiveDate.setDate(adminActiveDate.getDate() + 1);
            updateAdminDateDisplay();
            renderTimelineForCurrentFilters();
        };

        el.appointmentDoctorFilter?.addEventListener('change', () => {
            renderTimelineForCurrentFilters();
        });

        el.manageUsersBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate gestiona utilizatorii.', 'error');
                return;
            }
            showUserSection();
            await fetchUsers();
        });

        el.manageDoctorsBtn?.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate gestiona medicii.', 'error');
                return;
            }
            showDoctorSection();
            await fetchDoctors();
        });

        el.backToTimeline?.addEventListener('click', () => {
            showTimelineSection();
        });

        el.backToTimelineFromDoctors?.addEventListener('click', () => {
            showTimelineSection();
        });

        el.createUserForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            createUser();
        });

        el.createDoctorForm?.addEventListener('submit', async (event) => {
            event.preventDefault();
            createDoctor();
        });

        el.resetDatabaseBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate reseta baza de date.', 'error');
                return;
            }

            const confirmReset = window.confirm('Esti sigur ca vrei sa stergi TOATE programarile?');
            if (!confirmReset) return;

            const stepUpToken = await requestStepUp('appointments_reset', 'resetarea bazei de date');
            if (!stepUpToken) return;

            try {
                const res = await AUTH.apiFetch('/api/admin/reset', {
                    method: 'POST',
                    headers: { 'X-Step-Up-Token': stepUpToken }
                });
                const data = await res.json().catch(() => ({}));
                if (res.ok) {
                    showToast('Succes', data.message || 'Baza de date a fost resetata.');
                    await fetchAdminAppointments();
                    fetchAdminStats();
                } else {
                    showToast('Eroare', data.error || 'Nu s-a putut reseta baza de date.', 'error');
                }
            } catch (_) {
                showToast('Eroare', 'Eroare de conexiune.', 'error');
            }
        });

        el.cancelDayAppointmentsBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate bloca zile.', 'error');
                return;
            }

            const doctorId = String(el.appointmentDoctorFilter?.value || '');
            if (!doctorId) {
                showToast('Atentie', 'Selecteaza un medic din filtru pentru a bloca ziua.', 'error');
                return;
            }

            const selectedDate = getAdminActiveDateISO();
            const confirmed = window.confirm(`Blocam ziua ${selectedDate} pentru medicul selectat?`);
            if (!confirmed) return;

            try {
                const res = await AUTH.apiFetch(`/api/admin/doctors/${doctorId}/block-date`, {
                    method: 'POST',
                    body: JSON.stringify({ date: selectedDate })
                });
                const data = await res.json().catch(() => ({}));
                if (res.ok) {
                    showToast('Succes', `Ziua ${selectedDate} a fost blocata.`);
                    await fetchDoctors();
                } else {
                    showToast('Eroare', data.error || 'Nu s-a putut bloca ziua.', 'error');
                }
            } catch (_) {
                showToast('Eroare', 'Eroare de conexiune.', 'error');
            }
        });

        el.exportExcelBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate exporta date.', 'error');
                return;
            }

            const stepUpToken = await requestStepUp('appointments_export', 'exportul datelor');
            if (!stepUpToken) return;

            try {
                const res = await AUTH.apiFetch('/api/admin/export', {
                    headers: { 'X-Step-Up-Token': stepUpToken }
                });

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
            } catch (_) {
                showToast('Eroare', 'Eroare de conexiune.', 'error');
            }
        });

        el.closeDashboard.addEventListener('click', () => {
            window.location.href = '/';
        });
    }

    async function initAdminPanel() {
        if (initialized) {
            return;
        }

        initialized = true;
        setupAdminSearch();
        updateAdminDateDisplay();

        await fetchDoctors();
        await fetchAdminAppointments();
        fetchAdminStats();

        const superadmin = isSuperadmin();
        el.manageUsersBtn.classList.toggle('hidden', !superadmin);
        el.manageDoctorsBtn?.classList.toggle('hidden', !superadmin);
        el.resetDatabaseBtn.classList.toggle('hidden', !superadmin);
        el.cancelDayAppointmentsBtn.classList.toggle('hidden', !superadmin);
        el.exportExcelBtn.classList.toggle('hidden', !superadmin);
        el.createUserCard.classList.toggle('hidden', !superadmin);
        if (el.createDoctorForm) {
            el.createDoctorForm.parentElement.classList.toggle('hidden', !superadmin);
        }

        registerEvents();
    }

    async function bootstrap() {
        updateAuthUI(AUTH.getUser());

        const verifiedUser = await AUTH.verify();
        updateAuthUI(verifiedUser);

        if (!verifiedUser) {
            showScreen('auth');
            return;
        }

        if (!isStaffRole(verifiedUser.role || '')) {
            showScreen('denied');
            return;
        }

        showScreen('admin');
        await initAdminPanel();
    }

    bootstrap();
});
