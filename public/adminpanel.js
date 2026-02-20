
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
        manageUsersBtn: byId('manageUsersBtn'),
        userManagerContainer: byId('userManagerContainer'),
        timelineContainer: byId('timelineContainer'),
        backToTimeline: byId('backToTimeline'),
        userTableBody: byId('userTableBody'),
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
        createUserSubmit: byId('createUserSubmit'),
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
    while (adminActiveDate.getDay() !== 3) {
        adminActiveDate.setDate(adminActiveDate.getDate() + 1);
    }

    const isStaffRole = (role) => role === 'viewer' || role === 'scheduler' || role === 'superadmin';
    const isSuperadmin = () => (AUTH.getUser()?.role || '') === 'superadmin';
    const isSchedulerOrSuperadmin = () => ['scheduler', 'superadmin'].includes(AUTH.getUser()?.role || '');

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

    function getAdminActiveDateISO() {
        const y = adminActiveDate.getFullYear();
        const m = String(adminActiveDate.getMonth() + 1).padStart(2, '0');
        const d = String(adminActiveDate.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
    }

    function updateAdminDateDisplay() {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const isToday = adminActiveDate.getTime() === today.getTime();
        const dateStr = new Intl.DateTimeFormat('ro-RO', { day: 'numeric', month: 'long' }).format(adminActiveDate);
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
            fetchAdminAppointments(searchInput.value.toLowerCase());
        });

        el.adminActionButtons.prepend(searchInput);
    }

    async function fetchAdminStats() {
        const storageIndicator = byId('storage-indicator');
        const storageBar = byId('storage-bar');
        const storageText = byId('storage-text');

        if (!storageIndicator || !storageBar || !storageText) {
            return;
        }

        try {
            const res = await AUTH.apiFetch('/api/admin/stats');
            const data = await res.json();
            if (!res.ok) {
                return;
            }

            storageIndicator.classList.remove('hidden');
            storageBar.style.width = `${Math.min(data.percentUsed, 100)}%`;
            storageText.textContent = `${data.usedSizeMB} MB / ${data.totalSizeMB} MB (${data.percentUsed}%)`;

            storageBar.classList.toggle('bg-red-500', data.percentUsed > 80);
            storageBar.classList.toggle('bg-medical-500', data.percentUsed <= 80);
        } catch (error) {
            console.error('Error fetching stats:', error);
        }
    }

    async function fetchAdminAppointments(filterTerm = '') {
        setSingleMessage(el.timelineGrid, 'Se incarca programarile...', 'p-10 text-center text-gray-400 font-medium font-inter');

        try {
            const res = await AUTH.apiFetch('/api/admin/appointments');
            const appointments = await res.json().catch(() => null);

            if (!res.ok) {
                throw new Error(appointments?.error || `Server error: ${res.status}`);
            }

            const activeDate = getAdminActiveDateISO();
            const filtered = appointments.filter((app) => {
                if (app.date !== activeDate) return false;
                if (!filterTerm) return true;

                return app.name.toLowerCase().includes(filterTerm)
                    || app.phone.includes(filterTerm)
                    || (app.email && app.email.toLowerCase().includes(filterTerm));
            });

            renderTimeline(filtered);
            el.timelineHeaderCount.textContent = `(${filtered.length}) Programari`;
        } catch (error) {
            console.error('Admin Fetch Error:', error);
            setSingleMessage(el.timelineGrid, String(error?.message || 'Eroare la incarcare.'), 'p-10 text-center text-red-400 font-medium');
        }
    }

    function renderTimeline(appointments) {
        clearNode(el.timelineGrid);
        const allowResend = isSchedulerOrSuperadmin();
        const allowDelete = isSuperadmin();

        const clinicHours = [];
        for (let hour = 9; hour < 14; hour += 1) {
            for (let min = 0; min < 60; min += 20) {
                if (hour === 13 && min > 40) break;
                clinicHours.push(`${String(hour).padStart(2, '0')}:${String(min).padStart(2, '0')}`);
            }
        }

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

        clinicHours.forEach((time) => {
            const row = document.createElement('div');
            row.className = 'timeline-row';

            const hourLabel = document.createElement('div');
            hourLabel.className = 'timeline-hour';
            hourLabel.textContent = time;

            const slotsArea = document.createElement('div');
            slotsArea.className = 'timeline-slots';

            appointments.filter((app) => app.time === time).forEach((app) => {
                const card = document.createElement('div');
                card.className = `appointment-card ${app.type === 'Control' ? 'app-type-control' : 'app-type-prima'}`;

                const content = document.createElement('div');
                content.className = 'flex items-center gap-3 flex-wrap';

                const nameEl = document.createElement('span');
                nameEl.className = 'font-bold text-brand-100';
                nameEl.textContent = app.name || '';
                content.appendChild(nameEl);

                if (app.type === 'Prima ConsultaÈ›ie') {
                    const badge = document.createElement('span');
                    badge.className = 'app-new-badge';
                    badge.textContent = 'NOU';
                    content.appendChild(badge);
                }

                content.appendChild(labeled('Email', app.email || '-'));
                content.appendChild(labeled('Tel', app.phone || '-'));
                content.appendChild(labeled('Tip', app.type || '-'));

                const status = document.createElement('span');
                status.className = `px-2 py-0.5 rounded-lg text-[10px] font-bold uppercase ${app.emailSent ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`;
                status.textContent = app.emailSent ? 'Trimis' : 'Netrimis';
                content.appendChild(status);

                let resendBtn = null;
                if (allowResend) {
                    resendBtn = document.createElement('button');
                    resendBtn.className = 'resend-email-btn bg-brand-400/10 hover:bg-brand-400/20 text-brand-400 px-2 py-1 rounded-lg text-[10px] font-bold uppercase transition-all';
                    resendBtn.textContent = 'Trimite Manual';
                    content.appendChild(resendBtn);
                }

                let cancelBtn = null;
                if (allowDelete) {
                    cancelBtn = document.createElement('button');
                    cancelBtn.className = 'cancel-appointment-btn bg-red-500/10 hover:bg-red-500/20 text-red-300 px-2 py-1 rounded-lg text-[10px] font-bold uppercase transition-all';
                    cancelBtn.textContent = 'Anuleaza';
                    content.appendChild(cancelBtn);
                }

                if (app.diagnosticFileMeta) {
                    const docTag = document.createElement('span');
                    docTag.className = 'ml-auto bg-brand-600/20 px-3 py-1 rounded-lg text-xs font-bold text-brand-300';
                    docTag.textContent = `DOC: ${app.diagnosticFileMeta.mime || 'metadata'}`;
                    content.appendChild(docTag);
                }

                if (resendBtn) {
                    resendBtn.onclick = async (event) => {
                        event.stopPropagation();
                        resendBtn.disabled = true;
                        const originalText = resendBtn.textContent;
                        resendBtn.textContent = 'Se trimite...';

                        try {
                            const res = await AUTH.apiFetch(`/api/admin/resend-email/${app._id}`, { method: 'POST' });
                            const data = await res.json();
                            if (res.ok) {
                                showToast('Succes', data.message);
                                setTimeout(() => fetchAdminAppointments(''), 1200);
                            } else {
                                const message = data.details ? `${data.error}: ${data.details}` : (data.error || 'Eroare server');
                                showToast('Eroare', message, 'error');
                            }
                        } catch (_) {
                            showToast('Eroare', 'Eroare de conexiune.', 'error');
                        } finally {
                            resendBtn.disabled = false;
                            resendBtn.textContent = originalText;
                        }
                    };
                }

                if (cancelBtn) {
                    cancelBtn.onclick = async (event) => {
                        event.stopPropagation();
                        const confirm1 = confirm(`Esti sigur ca vrei sa anulezi programarea pacientului ${app.name || ''}?`);
                        if (!confirm1) return;
                        const confirm2 = confirm('CONFIRMARE FINALA: Programarea va fi stearsa definitiv. Continuam?');
                        if (!confirm2) return;

                        const stepUpToken = await requestStepUp('appointment_delete', 'stergerea programarii');
                        if (!stepUpToken) return;

                        try {
                            const res = await AUTH.apiFetch(`/api/admin/appointment/${app._id}`, {
                                method: 'DELETE',
                                headers: { 'X-Step-Up-Token': stepUpToken }
                            });
                            const data = await res.json();
                            if (res.ok) {
                                showToast('Succes', data.message || 'Programarea a fost anulata.');
                                fetchAdminAppointments();
                                fetchAdminStats();
                            } else {
                                showToast('Eroare', data.error || 'Nu s-a putut anula programarea.', 'error');
                            }
                        } catch (_) {
                            showToast('Eroare', 'Eroare de conexiune.', 'error');
                        }
                    };
                }

                card.appendChild(content);
                slotsArea.appendChild(card);
            });

            row.appendChild(hourLabel);
            row.appendChild(slotsArea);
            el.timelineGrid.appendChild(row);
        });
    }

    async function fetchUsers() {
        clearNode(el.userTableBody);

        const loadingRow = document.createElement('tr');
        const loadingCell = document.createElement('td');
        loadingCell.colSpan = 4;
        loadingCell.className = 'p-10 text-center text-brand-400';
        loadingCell.textContent = 'Se incarca lista de utilizatori...';
        loadingRow.appendChild(loadingCell);
        el.userTableBody.appendChild(loadingRow);

        try {
            const res = await AUTH.apiFetch('/api/admin/users');
            const users = await res.json();
            if (!res.ok) {
                showToast('Eroare', users.error || 'Eroare la preluare utilizatori.', 'error');
                return;
            }
            renderUsers(users);
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune server.', 'error');
        }
    }

    function renderUsers(users) {
        clearNode(el.userTableBody);
        const currentUser = AUTH.getUser() || {};

        users.forEach((user) => {
            const row = document.createElement('tr');
            row.className = 'border-b border-brand-600/10 hover:bg-brand-600/5 transition-colors';

            const isSelf = user.email === currentUser.email;
            const isSuperAdminUser = user.role === 'superadmin';

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

            const roleBtn = document.createElement('button');
            roleBtn.className = `role-toggle-btn w-12 h-6 rounded-full relative transition-all duration-300 ${user.role === 'scheduler' ? 'bg-brand-400' : (isSuperAdminUser ? 'bg-medical-500' : 'bg-brand-700')}`;

            if (isSelf || isSuperAdminUser) {
                roleBtn.disabled = true;
                roleBtn.style.opacity = '0.5';
                roleBtn.style.cursor = 'not-allowed';
            }

            const knob = document.createElement('div');
            knob.className = `w-4 h-4 bg-brand-900 rounded-full absolute top-1 transition-all duration-300 ${user.role === 'scheduler' ? 'left-7' : 'left-1'}`;
            roleBtn.appendChild(knob);
            roleCell.appendChild(roleBtn);

            if (isSuperAdminUser) {
                const superTag = document.createElement('span');
                superTag.className = 'block text-[10px] uppercase font-bold text-medical-500 mt-1';
                superTag.textContent = 'Super Admin';
                roleCell.appendChild(superTag);
            }

            if (!isSelf && !isSuperAdminUser) {
                roleBtn.title = user.role === 'scheduler' ? 'Schimba la viewer' : 'Schimba la scheduler';
                roleBtn.onclick = async () => {
                    const newRole = user.role === 'scheduler' ? 'viewer' : 'scheduler';
                    const stepUpToken = await requestStepUp('user_role_change', 'modificarea rolului utilizatorului');
                    if (!stepUpToken) return;
                    toggleUserRole(user._id, newRole, stepUpToken);
                };
            }

            row.appendChild(nameCell);
            row.appendChild(emailCell);
            row.appendChild(phoneCell);
            row.appendChild(roleCell);
            el.userTableBody.appendChild(row);
        });
    }

    async function toggleUserRole(userId, role, stepUpToken) {
        try {
            const res = await AUTH.apiFetch('/api/admin/users/role', {
                method: 'POST',
                headers: { 'X-Step-Up-Token': stepUpToken },
                body: JSON.stringify({ userId, role })
            });
            const data = await res.json();
            if (res.ok) {
                showToast('Succes', data.message);
                fetchUsers();
            } else {
                showToast('Eroare', data.error || 'Eroare server.', 'error');
            }
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    }

    async function createUser() {
        if (!isSuperadmin()) {
            showToast('Acces interzis', 'Doar superadmin poate crea utilizatori.', 'error');
            return;
        }

        const payload = {
            displayName: el.newUserDisplayName.value.trim(),
            email: el.newUserEmail.value.trim(),
            phone: el.newUserPhone.value.trim(),
            password: el.newUserPassword.value,
            role: el.newUserRole.value
        };

        if (!payload.displayName || !payload.email || !payload.phone || !payload.password) {
            showToast('Eroare', 'Completeaza toate campurile utilizatorului.', 'error');
            return;
        }

        if (payload.password.length < 6) {
            showToast('Eroare', 'Parola trebuie sa aiba cel putin 6 caractere.', 'error');
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

            if (!el.userManagerContainer.classList.contains('hidden')) {
                fetchUsers();
            }
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        } finally {
            el.createUserSubmit.disabled = false;
        }
    }

    function registerEvents() {
        el.logoutBtn.addEventListener('click', async () => {
            await AUTH.logout();
            window.location.href = '/login.html';
        });

        el.prevAdminDate.onclick = () => {
            adminActiveDate.setDate(adminActiveDate.getDate() - 7);
            updateAdminDateDisplay();
            fetchAdminAppointments();
        };

        el.nextAdminDate.onclick = () => {
            adminActiveDate.setDate(adminActiveDate.getDate() + 7);
            updateAdminDateDisplay();
            fetchAdminAppointments();
        };

        el.manageUsersBtn.addEventListener('click', () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate gestiona utilizatorii.', 'error');
                return;
            }
            el.timelineContainer.classList.add('hidden');
            el.userManagerContainer.classList.remove('hidden');
            fetchUsers();
        });

        el.backToTimeline.addEventListener('click', () => {
            el.userManagerContainer.classList.add('hidden');
            el.timelineContainer.classList.remove('hidden');
        });

        el.createUserForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            createUser();
        });

        el.resetDatabaseBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate reseta baza de date.', 'error');
                return;
            }

            const confirm1 = confirm('Esti sigur ca vrei sa stergi TOATE programarile?');
            if (!confirm1) return;
            const confirm2 = confirm('CONFIRMARE FINALA: Toate datele vor fi sterse definitiv. Continuam?');
            if (!confirm2) return;

            const stepUpToken = await requestStepUp('appointments_reset', 'resetarea bazei de date');
            if (!stepUpToken) return;

            try {
                const res = await AUTH.apiFetch('/api/admin/reset', {
                    method: 'POST',
                    headers: { 'X-Step-Up-Token': stepUpToken }
                });
                const data = await res.json();
                if (res.ok) {
                    showToast('Succes', 'Baza de date a fost resetata.');
                    fetchAdminAppointments();
                    fetchAdminStats();
                } else {
                    showToast('Eroare', data.error || 'Nu s-a putut reseta.', 'error');
                }
            } catch (_) {
                showToast('Eroare', 'Eroare de conexiune.', 'error');
            }
        });

        el.cancelDayAppointmentsBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate anula programarile unei zile.', 'error');
                return;
            }

            const selectedDate = getAdminActiveDateISO();
            const confirm1 = confirm(`Esti sigur ca vrei sa anulezi TOATE programarile din ${selectedDate}?`);
            if (!confirm1) return;
            const confirm2 = confirm('CONFIRMARE FINALA: Toate programarile din ziua selectata vor fi sterse definitiv. Continuam?');
            if (!confirm2) return;

            const stepUpToken = await requestStepUp('appointments_delete_by_date', 'stergerea programarilor pe zi');
            if (!stepUpToken) return;

            try {
                const res = await AUTH.apiFetch('/api/admin/appointments/by-date', {
                    method: 'DELETE',
                    headers: { 'X-Step-Up-Token': stepUpToken },
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

    function initAdminPanel() {
        if (initialized) {
            return;
        }

        initialized = true;
        setupAdminSearch();
        updateAdminDateDisplay();
        fetchAdminAppointments();
        fetchAdminStats();

        const superadmin = isSuperadmin();
        el.manageUsersBtn.classList.toggle('hidden', !superadmin);
        el.resetDatabaseBtn.classList.toggle('hidden', !superadmin);
        el.cancelDayAppointmentsBtn.classList.toggle('hidden', !superadmin);
        el.exportExcelBtn.classList.toggle('hidden', !superadmin);
        el.createUserCard.classList.toggle('hidden', !superadmin);

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
        initAdminPanel();
    }

    bootstrap();
});
