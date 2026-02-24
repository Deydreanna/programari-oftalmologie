
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
        appointmentSearchInput: byId('appointmentSearchInput'),
        appointmentDoctorFilter: byId('appointmentDoctorFilter'),
        manageUsersBtn: byId('manageUsersBtn'),
        manageDoctorsBtn: byId('manageDoctorsBtn'),
        editDayScheduleBtn: byId('editDayScheduleBtn'),
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
        createDoctorCard: byId('createDoctorCard'),
        toggleCreateDoctorBtn: byId('toggleCreateDoctorBtn'),
        doctorSlug: byId('doctorSlug'),
        doctorDisplayName: byId('doctorDisplayName'),
        doctorSpecialty: byId('doctorSpecialty'),
        doctorIsActive: byId('doctorIsActive'),
        doctorMonthsToShow: byId('doctorMonthsToShow'),
        doctorDayConfigList: byId('doctorDayConfigList'),
        adminCalendarGrid: byId('adminCalendarGrid'),
        adminCalendarMonthLabel: byId('adminCalendarMonthLabel'),
        adminCalendarPrevMonth: byId('adminCalendarPrevMonth'),
        adminCalendarNextMonth: byId('adminCalendarNextMonth'),
        adminModalOverlay: byId('adminModalOverlay'),
        adminModalDialog: byId('adminModalDialog'),
        adminModalTitle: byId('adminModalTitle'),
        adminModalDescription: byId('adminModalDescription'),
        adminModalBody: byId('adminModalBody'),
        adminModalError: byId('adminModalError'),
        adminModalActions: byId('adminModalActions'),
        adminModalClose: byId('adminModalClose'),
        toast: byId('toast'),
        toastClose: byId('toastClose'),
        toastTitle: byId('toastTitle'),
        toastMessage: byId('toastMessage'),
        appointmentDrawer: byId('appointmentDrawer'),
        appointmentDrawerClose: byId('appointmentDrawerClose'),
        drawerTimeInterval: byId('drawerTimeInterval'),
        drawerPatientName: byId('drawerPatientName'),
        drawerPatientPhone: byId('drawerPatientPhone'),
        drawerPatientEmail: byId('drawerPatientEmail'),
        drawerPatientCnp: byId('drawerPatientCnp'),
        drawerDoctorName: byId('drawerDoctorName'),
        drawerType: byId('drawerType'),
        drawerStatus: byId('drawerStatus'),
        drawerInlineSuccess: byId('drawerInlineSuccess'),
        drawerInlineError: byId('drawerInlineError'),
        drawerActionGroup: byId('drawerActionGroup'),
        drawerResendBtn: byId('drawerResendBtn'),
        drawerCancelSection: byId('drawerCancelSection'),
        drawerCancelBtn: byId('drawerCancelBtn')
    };

    if (!el.adminApp || !el.toast || !el.timelineGrid) {
        return;
    }

    let initialized = false;
    let adminActiveDate = new Date();
    adminActiveDate.setHours(0, 0, 0, 0);
    let adminCalendarMonth = new Date(adminActiveDate.getFullYear(), adminActiveDate.getMonth(), 1);

    let doctorsCache = [];
    let appointmentsCache = [];
    let usersCache = [];
    let scheduler = null;
    let drawerAppointmentId = '';
    let searchTerm = '';
    let eventsBound = false;
    let isCreateDoctorFormOpen = false;
    let activeModalCleanup = null;
    let toastTimer = null;

    const WEEKDAY_LABELS = ['Duminica', 'Luni', 'Marti', 'Miercuri', 'Joi', 'Vineri', 'Sambata'];
    const WEEKDAY_SHORT = ['Du', 'Lu', 'Ma', 'Mi', 'Jo', 'Vi', 'Sa'];
    const BTN_CLASS = Object.freeze({
        primary: 'admin-action-btn btn-primary',
        secondary: 'admin-action-btn btn-secondary',
        warning: 'admin-action-btn btn-warning',
        danger: 'admin-action-btn btn-danger',
        ghost: 'admin-action-btn btn-ghost'
    });

    const isStaffRole = (role) => role === 'viewer' || role === 'scheduler' || role === 'superadmin';
    const isSuperadmin = () => (AUTH.getUser()?.role || '') === 'superadmin';
    const isSchedulerOrSuperadmin = () => ['scheduler', 'superadmin'].includes(AUTH.getUser()?.role || '');

    async function safeLogoutAndRedirect() {
        try {
            await AUTH.logout();
        } catch (_) {
            // no-op
        }
        window.location.href = '/login.html';
    }

    if (el.logoutBtn) {
        el.logoutBtn.addEventListener('click', safeLogoutAndRedirect);
    }
    if (el.toastClose) {
        el.toastClose.addEventListener('click', hideToast);
    }

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

    function hideToast() {
        if (toastTimer) {
            clearTimeout(toastTimer);
            toastTimer = null;
        }
        el.toast.classList.add('translate-y-20', 'opacity-0');
    }

    function showToast(title, message, type = 'success') {
        el.toastTitle.textContent = title;
        el.toastMessage.textContent = message;
        el.toast.className = `fixed bottom-5 right-5 bg-brand-800 shadow-xl rounded-xl p-5 transform transition-all duration-300 max-w-sm z-50 border-l-4 border border-brand-600/30 ${type === 'success' ? 'toast-success' : 'toast-error'}`;
        el.toastTitle.className = `font-bold ${type === 'success' ? 'text-brand-100' : 'text-red-300'}`;
        el.toastMessage.className = `text-sm mt-1 ${type === 'success' ? 'text-brand-300' : 'text-red-200'}`;

        setTimeout(() => {
            el.toast.classList.remove('translate-y-20', 'opacity-0');
        }, 10);
        if (toastTimer) {
            clearTimeout(toastTimer);
        }
        toastTimer = setTimeout(() => {
            hideToast();
        }, 9000);
    }

    function setButtonLoading(button, isLoading, loadingLabel = 'Se salveaza...') {
        if (!button) return;
        if (isLoading) {
            if (!button.dataset.originalLabel) {
                button.dataset.originalLabel = button.textContent;
            }
            button.disabled = true;
            button.textContent = loadingLabel;
            return;
        }
        button.disabled = false;
        if (button.dataset.originalLabel) {
            button.textContent = button.dataset.originalLabel;
            delete button.dataset.originalLabel;
        }
    }

    function closeActiveModal() {
        if (typeof activeModalCleanup === 'function') {
            const cleanup = activeModalCleanup;
            activeModalCleanup = null;
            cleanup();
        }
    }

    function openModalFrame({ title, description = '', wide = false, onDismiss = null } = {}) {
        if (!el.adminModalOverlay || !el.adminModalDialog || !el.adminModalTitle || !el.adminModalBody || !el.adminModalActions) {
            return null;
        }

        closeActiveModal();

        el.adminModalTitle.textContent = title || '';
        if (description) {
            el.adminModalDescription.textContent = description;
            el.adminModalDescription.classList.remove('hidden');
        } else {
            el.adminModalDescription.textContent = '';
            el.adminModalDescription.classList.add('hidden');
        }

        clearNode(el.adminModalBody);
        clearNode(el.adminModalActions);
        if (el.adminModalError) {
            el.adminModalError.textContent = '';
            el.adminModalError.classList.add('hidden');
        }

        el.adminModalDialog.classList.toggle('admin-modal-wide', !!wide);
        el.adminModalOverlay.classList.remove('hidden');
        el.adminModalOverlay.setAttribute('aria-hidden', 'false');
        document.body.classList.add('modal-open');

        let closed = false;
        const doClose = () => {
            if (closed) return;
            closed = true;
            el.adminModalOverlay.classList.add('hidden');
            el.adminModalOverlay.setAttribute('aria-hidden', 'true');
            document.body.classList.remove('modal-open');
            el.adminModalDialog.classList.remove('admin-modal-wide');
            if (activeModalCleanup === cleanup) {
                activeModalCleanup = null;
            }
        };

        const dismiss = () => {
            if (typeof onDismiss === 'function') {
                onDismiss();
                return;
            }
            doClose();
        };

        const onOverlayClick = (event) => {
            if (event.target === el.adminModalOverlay) {
                dismiss();
            }
        };
        const onEsc = (event) => {
            if (event.key === 'Escape') {
                dismiss();
            }
        };
        const onCloseClick = () => dismiss();

        const cleanup = () => {
            el.adminModalOverlay.removeEventListener('click', onOverlayClick);
            document.removeEventListener('keydown', onEsc);
            el.adminModalClose?.removeEventListener('click', onCloseClick);
            doClose();
        };

        el.adminModalOverlay.addEventListener('click', onOverlayClick);
        document.addEventListener('keydown', onEsc);
        el.adminModalClose?.addEventListener('click', onCloseClick);
        activeModalCleanup = cleanup;

        return {
            body: el.adminModalBody,
            actions: el.adminModalActions,
            setError: (message) => {
                if (!el.adminModalError) return;
                if (!message) {
                    el.adminModalError.textContent = '';
                    el.adminModalError.classList.add('hidden');
                    return;
                }
                el.adminModalError.textContent = message;
                el.adminModalError.classList.remove('hidden');
            },
            close: cleanup
        };
    }

    function createModalField(labelText, inputEl) {
        const wrap = document.createElement('div');
        const label = document.createElement('label');
        label.className = 'form-label';
        label.textContent = labelText;
        wrap.appendChild(label);
        wrap.appendChild(inputEl);
        return wrap;
    }

    function showConfirmModal({
        title,
        message,
        description = '',
        confirmLabel = 'Confirma',
        cancelLabel = 'Anuleaza',
        danger = false
    } = {}) {
        return new Promise((resolve) => {
            const modal = openModalFrame({
                title,
                description,
                onDismiss: () => {
                    resolve(false);
                    closeActiveModal();
                }
            });
            if (!modal) {
                resolve(false);
                return;
            }

            const text = document.createElement('p');
            text.className = danger ? 'admin-modal-danger-text' : 'text-sm text-brand-200';
            text.textContent = message || '';
            modal.body.appendChild(text);

            const cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = BTN_CLASS.ghost;
            cancelBtn.textContent = cancelLabel;
            cancelBtn.addEventListener('click', () => {
                resolve(false);
                modal.close();
            });

            const confirmBtn = document.createElement('button');
            confirmBtn.type = 'button';
            confirmBtn.className = danger ? BTN_CLASS.danger : BTN_CLASS.primary;
            confirmBtn.textContent = confirmLabel;
            confirmBtn.addEventListener('click', () => {
                resolve(true);
                modal.close();
            });

            modal.actions.appendChild(cancelBtn);
            modal.actions.appendChild(confirmBtn);
            confirmBtn.focus();
        });
    }

    function askStepUpPassword(actionLabel) {
        return new Promise((resolve) => {
            const modal = openModalFrame({
                title: 'Confirmare suplimentara',
                description: `Introdu parola pentru ${actionLabel}.`,
                onDismiss: () => {
                    resolve(null);
                    closeActiveModal();
                }
            });
            if (!modal) {
                resolve(null);
                return;
            }

            const passwordInput = document.createElement('input');
            passwordInput.type = 'password';
            passwordInput.className = 'form-input';
            passwordInput.autocomplete = 'current-password';
            passwordInput.placeholder = 'Parola contului curent';
            modal.body.appendChild(createModalField('Parola', passwordInput));

            const helper = document.createElement('p');
            helper.className = 'admin-modal-helper';
            helper.textContent = 'Tokenul de step-up este valid doar pentru actiunea curenta.';
            modal.body.appendChild(helper);

            const cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = BTN_CLASS.ghost;
            cancelBtn.textContent = 'Anuleaza';
            cancelBtn.addEventListener('click', () => {
                resolve(null);
                modal.close();
            });

            const confirmBtn = document.createElement('button');
            confirmBtn.type = 'button';
            confirmBtn.className = BTN_CLASS.primary;
            confirmBtn.textContent = 'Confirma';
            confirmBtn.addEventListener('click', () => {
                const password = String(passwordInput.value || '').trim();
                if (!password) {
                    modal.setError('Parola este obligatorie.');
                    passwordInput.focus();
                    return;
                }
                resolve(password);
                modal.close();
            });

            passwordInput.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    confirmBtn.click();
                }
            });

            modal.actions.appendChild(cancelBtn);
            modal.actions.appendChild(confirmBtn);
            passwordInput.focus();
        });
    }

    async function requestStepUp(action, actionLabel) {
        const password = await askStepUpPassword(actionLabel);
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

    function parseTimeToMinutes(value) {
        const [hours, minutes] = String(value || '').split(':').map(Number);
        if (!Number.isInteger(hours) || !Number.isInteger(minutes)) return NaN;
        return (hours * 60) + minutes;
    }

    function isValidScheduleWindow(startTime, endTime, duration, { requireDivisible = true } = {}) {
        const startMinutes = parseTimeToMinutes(startTime);
        const endMinutes = parseTimeToMinutes(endTime);
        const slotDuration = Number(duration);
        if (!Number.isFinite(startMinutes) || !Number.isFinite(endMinutes)) return false;
        if (!Number.isInteger(slotDuration) || slotDuration < 5 || slotDuration > 120) return false;
        const intervalMinutes = endMinutes - startMinutes;
        if (intervalMinutes <= 0 || intervalMinutes < slotDuration) return false;
        if (requireDivisible && (intervalMinutes % slotDuration !== 0)) return false;
        return true;
    }

    function startOfDay(date) {
        const out = new Date(date);
        out.setHours(0, 0, 0, 0);
        return out;
    }

    function getDoctorDayConfigs(doctor) {
        if (!doctor || !doctor.availabilityRules) return [];
        const fromConfigs = Array.isArray(doctor.availabilityRules.dayConfigs)
            ? doctor.availabilityRules.dayConfigs
            : [];
        if (fromConfigs.length > 0) {
            return fromConfigs
                .map((config) => ({
                    weekday: Number(config.weekday),
                    startTime: String(config.startTime || ''),
                    endTime: String(config.endTime || ''),
                    consultationDurationMinutes: Number(config.consultationDurationMinutes)
                }))
                .filter((config) => Number.isInteger(config.weekday) && config.weekday >= 0 && config.weekday <= 6);
        }
        const weekdays = Array.isArray(doctor.availabilityRules.weekdays) ? doctor.availabilityRules.weekdays : [];
        return weekdays.map((weekday) => ({
            weekday: Number(weekday),
            startTime: String(doctor.bookingSettings?.workdayStart || '09:00'),
            endTime: String(doctor.bookingSettings?.workdayEnd || '14:00'),
            consultationDurationMinutes: Number(doctor.bookingSettings?.consultationDurationMinutes || 20)
        }));
    }

    function getCalendarContextDoctors() {
        const selectedDoctorId = String(el.appointmentDoctorFilter?.value || '');
        if (selectedDoctorId) {
            const doctor = doctorsCache.find((entry) => String(entry._id) === selectedDoctorId);
            return doctor ? [doctor] : [];
        }
        return doctorsCache.filter((doctor) => !!doctor.isActive);
    }

    function getDoctorRangeEndDate(doctor) {
        const monthsToShow = Number(doctor?.bookingSettings?.monthsToShow || 1);
        const today = startOfDay(new Date());
        const out = new Date(today);
        out.setMonth(out.getMonth() + monthsToShow);
        return startOfDay(out);
    }

    function isDateInDoctorRange(date, doctor) {
        const targetDate = startOfDay(date);
        const today = startOfDay(new Date());
        const maxDate = getDoctorRangeEndDate(doctor);
        return targetDate >= today && targetDate <= maxDate;
    }

    function doctorHasProgramOnDate(doctor, date) {
        const dateISO = toISODate(date);
        if (!doctor || !isDateInDoctorRange(date, doctor)) return false;
        const dayConfigs = getDoctorDayConfigs(doctor);
        const weekday = date.getDay();
        const hasWeekdayConfig = dayConfigs.some((config) => config.weekday === weekday);
        if (!hasWeekdayConfig) return false;
        const blockedDates = Array.isArray(doctor.blockedDates) ? doctor.blockedDates : [];
        return !blockedDates.includes(dateISO);
    }

    function getCalendarBounds() {
        const today = startOfDay(new Date());
        const minMonth = new Date(today.getFullYear(), today.getMonth(), 1);
        const contextDoctors = getCalendarContextDoctors();
        if (!contextDoctors.length) {
            return { minMonth, maxMonth: minMonth };
        }
        let maxDate = startOfDay(today);
        contextDoctors.forEach((doctor) => {
            const doctorMax = getDoctorRangeEndDate(doctor);
            if (doctorMax > maxDate) {
                maxDate = doctorMax;
            }
        });
        const maxMonth = new Date(maxDate.getFullYear(), maxDate.getMonth(), 1);
        return { minMonth, maxMonth };
    }

    function clampAdminDateWithinBounds() {
        const { minMonth, maxMonth } = getCalendarBounds();
        const minDate = startOfDay(new Date(minMonth));
        const maxDate = startOfDay(new Date(maxMonth.getFullYear(), maxMonth.getMonth() + 1, 0));
        if (adminActiveDate < minDate) {
            adminActiveDate = minDate;
        }
        if (adminActiveDate > maxDate) {
            adminActiveDate = maxDate;
        }
        adminCalendarMonth = new Date(adminActiveDate.getFullYear(), adminActiveDate.getMonth(), 1);
    }

    function renderAdminCalendar() {
        if (!el.adminCalendarGrid || !el.adminCalendarMonthLabel) {
            return;
        }

        clearNode(el.adminCalendarGrid);
        const { minMonth, maxMonth } = getCalendarBounds();
        if (adminCalendarMonth < minMonth) {
            adminCalendarMonth = new Date(minMonth);
        }
        if (adminCalendarMonth > maxMonth) {
            adminCalendarMonth = new Date(maxMonth);
        }

        const currentMonthLabel = new Intl.DateTimeFormat('ro-RO', { month: 'long', year: 'numeric' }).format(adminCalendarMonth);
        el.adminCalendarMonthLabel.textContent = currentMonthLabel.charAt(0).toUpperCase() + currentMonthLabel.slice(1);

        const year = adminCalendarMonth.getFullYear();
        const month = adminCalendarMonth.getMonth();
        const firstDayIndex = new Date(year, month, 1).getDay();
        const lastDay = new Date(year, month + 1, 0).getDate();
        const today = startOfDay(new Date());
        const contextDoctors = getCalendarContextDoctors();

        for (let i = 0; i < firstDayIndex; i += 1) {
            const empty = document.createElement('div');
            empty.className = 'admin-calendar-day disabled';
            empty.style.visibility = 'hidden';
            el.adminCalendarGrid.appendChild(empty);
        }

        for (let day = 1; day <= lastDay; day += 1) {
            const dateObj = startOfDay(new Date(year, month, day));
            const dateISO = toISODate(dateObj);
            const inBounds = dateObj >= today && dateObj <= startOfDay(new Date(maxMonth.getFullYear(), maxMonth.getMonth() + 1, 0));
            const hasProgram = contextDoctors.some((doctor) => doctorHasProgramOnDate(doctor, dateObj));

            const dayBtn = document.createElement('button');
            dayBtn.type = 'button';
            dayBtn.className = 'admin-calendar-day';
            dayBtn.textContent = String(day);
            dayBtn.title = `${dateISO}${hasProgram ? ' - program activ' : ''}`;

            if (!inBounds) {
                dayBtn.classList.add('disabled');
                dayBtn.disabled = true;
            } else {
                if (hasProgram) {
                    dayBtn.classList.add('has-program');
                }
                if (adminActiveDate.getTime() === dateObj.getTime()) {
                    dayBtn.classList.add('selected');
                }
                if (today.getTime() === dateObj.getTime()) {
                    dayBtn.classList.add('today');
                }

                dayBtn.addEventListener('click', () => {
                    adminActiveDate = dateObj;
                    updateAdminDateDisplay();
                    fetchAdminAppointments();
                    renderAdminCalendar();
                });
            }

            el.adminCalendarGrid.appendChild(dayBtn);
        }

        if (el.adminCalendarPrevMonth) {
            el.adminCalendarPrevMonth.disabled = adminCalendarMonth <= minMonth;
        }
        if (el.adminCalendarNextMonth) {
            el.adminCalendarNextMonth.disabled = adminCalendarMonth >= maxMonth;
        }
    }

    function updateDayConfigRowState(row) {
        const enabled = !!row.querySelector('.day-enabled')?.checked;
        row.querySelectorAll('.day-start, .day-end, .day-duration').forEach((input) => {
            input.disabled = !enabled;
            input.classList.toggle('opacity-60', !enabled);
        });
    }

    function renderDayConfigRows(container, initialConfigs = null) {
        if (!container) return;

        clearNode(container);
        const configMap = new Map();
        (Array.isArray(initialConfigs) ? initialConfigs : []).forEach((config) => {
            configMap.set(Number(config.weekday), {
                startTime: String(config.startTime || '09:00'),
                endTime: String(config.endTime || '14:00'),
                consultationDurationMinutes: Number(config.consultationDurationMinutes || 20)
            });
        });

        WEEKDAY_LABELS.forEach((label, weekday) => {
            const config = configMap.get(weekday) || {
                startTime: '09:00',
                endTime: '14:00',
                consultationDurationMinutes: 20
            };

            const row = document.createElement('div');
            row.className = 'admin-day-config-row';
            row.dataset.weekday = String(weekday);

            const checkboxWrap = document.createElement('label');
            checkboxWrap.className = 'flex items-center gap-2 text-sm text-brand-300 font-semibold';
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'day-enabled w-4 h-4 rounded border-brand-600 accent-brand-400';
            checkbox.checked = configMap.size ? configMap.has(weekday) : weekday === 3;
            checkboxWrap.appendChild(checkbox);
            checkboxWrap.appendChild(document.createTextNode(`${WEEKDAY_SHORT[weekday]} - ${label}`));

            const startInput = document.createElement('input');
            startInput.type = 'time';
            startInput.className = 'form-input day-start';
            startInput.value = config.startTime;

            const endInput = document.createElement('input');
            endInput.type = 'time';
            endInput.className = 'form-input day-end';
            endInput.value = config.endTime;

            const durationInput = document.createElement('input');
            durationInput.type = 'number';
            durationInput.min = '5';
            durationInput.max = '120';
            durationInput.className = 'form-input day-duration';
            durationInput.value = String(config.consultationDurationMinutes);

            row.appendChild(checkboxWrap);
            row.appendChild(startInput);
            row.appendChild(endInput);
            row.appendChild(durationInput);
            container.appendChild(row);

            checkbox.addEventListener('change', () => updateDayConfigRowState(row));
            updateDayConfigRowState(row);
        });
    }

    function renderDoctorDayConfigList(initialConfigs = null) {
        renderDayConfigRows(el.doctorDayConfigList, initialConfigs);
    }

    function collectDayConfigsFromContainer(container) {
        if (!container) return [];
        const rows = Array.from(container.querySelectorAll('.admin-day-config-row'));
        const dayConfigs = [];

        for (const row of rows) {
            const weekday = Number(row.dataset.weekday);
            const enabled = row.querySelector('.day-enabled')?.checked;
            if (!enabled) continue;

            const startTime = String(row.querySelector('.day-start')?.value || '').trim();
            const endTime = String(row.querySelector('.day-end')?.value || '').trim();
            const consultationDurationMinutes = Number(row.querySelector('.day-duration')?.value);

            if (!startTime || !endTime || !Number.isInteger(consultationDurationMinutes)) {
                throw new Error(`Completeaza toate campurile pentru ${WEEKDAY_LABELS[weekday]}.`);
            }
            if (!isValidScheduleWindow(startTime, endTime, consultationDurationMinutes, { requireDivisible: true })) {
                throw new Error(`Configuratia pentru ${WEEKDAY_LABELS[weekday]} este invalida sau intervalul nu se imparte perfect la durata.`);
            }

            dayConfigs.push({
                weekday,
                startTime,
                endTime,
                consultationDurationMinutes
            });
        }

        if (!dayConfigs.length) {
            throw new Error('Selecteaza cel putin o zi de consultatie.');
        }

        return dayConfigs.sort((a, b) => a.weekday - b.weekday);
    }

    function collectDoctorDayConfigsFromForm() {
        return collectDayConfigsFromContainer(el.doctorDayConfigList);
    }

    function setupAdminSearch() {
        if (!el.appointmentSearchInput || el.appointmentSearchInput.dataset.bound === '1') {
            return;
        }

        // Prevent browser autofill/restored values from silently filtering timeline results.
        searchTerm = '';
        el.appointmentSearchInput.value = '';
        el.appointmentSearchInput.dataset.bound = '1';
        const syncSearchTerm = () => {
            searchTerm = String(el.appointmentSearchInput.value || '').toLowerCase().trim();
            renderTimelineForCurrentFilters();
        };
        el.appointmentSearchInput.addEventListener('input', syncSearchTerm);
        el.appointmentSearchInput.addEventListener('search', syncSearchTerm);
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

            const allowAllDoctorsOption = isSuperadmin();
            if (allowAllDoctorsOption) {
                const allOption = document.createElement('option');
                allOption.value = '';
                allOption.textContent = 'Toți medicii';
                el.appointmentDoctorFilter.appendChild(allOption);
            }

            doctorsCache.forEach((doctor) => {
                const option = document.createElement('option');
                option.value = String(doctor._id);
                option.textContent = `${doctor.displayName} (${doctor.slug})${doctor.isActive ? '' : ' [inactiv]'}`;
                el.appointmentDoctorFilter.appendChild(option);
            });

            const hasCurrentValue = [...el.appointmentDoctorFilter.options].some((opt) => opt.value === currentValue);
            if (hasCurrentValue) {
                el.appointmentDoctorFilter.value = currentValue;
            } else if (allowAllDoctorsOption) {
                el.appointmentDoctorFilter.value = '';
            } else {
                const firstDoctorOption = [...el.appointmentDoctorFilter.options].find((opt) => opt.value);
                el.appointmentDoctorFilter.value = firstDoctorOption?.value || '';
            }
        }

        if (el.newUserManagedDoctors) {
            const selectedValues = new Set(Array.from(el.newUserManagedDoctors.selectedOptions).map((opt) => opt.value));
            clearNode(el.newUserManagedDoctors);
            doctorsCache.forEach((doctor) => {
                const option = document.createElement('option');
                option.value = String(doctor._id);
                option.textContent = `${doctor.displayName} (${doctor.slug})${doctor.isActive ? '' : ' [inactiv]'}`;
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
                clampAdminDateWithinBounds();
                updateAdminDateDisplay();
                renderAdminCalendar();
                return;
            }
            doctorsCache = Array.isArray(data) ? data : [];
            fillDoctorSelectors();
            clampAdminDateWithinBounds();
            updateAdminDateDisplay();
            renderAdminCalendar();
            renderDoctorsTable();
            renderTimelineForCurrentFilters();
        } catch (_) {
            doctorsCache = [];
            fillDoctorSelectors();
            clampAdminDateWithinBounds();
            updateAdminDateDisplay();
            renderAdminCalendar();
        }
    }

    function getAppointmentId(entry) {
        return String(entry?.id || entry?._id || '').trim();
    }

    function minutesToHHMM(totalMinutes) {
        const safe = Math.max(0, Number(totalMinutes) || 0);
        const hours = Math.floor(safe / 60);
        const minutes = safe % 60;
        return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
    }

    function getAppointmentTimeInterval(entry) {
        const startMinutes = Number(entry?.startMinutes);
        if (Number.isFinite(startMinutes)) {
            const durationMinutes = Number(entry?.durationMinutes);
            const endMinutes = startMinutes + (Number.isFinite(durationMinutes) ? durationMinutes : 20);
            return `${minutesToHHMM(startMinutes)} - ${minutesToHHMM(endMinutes)}`;
        }
        return '-';
    }

    function getAppointmentStatusLabel(entry) {
        const status = String(entry?.status || '').toLowerCase();
        if (status === 'sent' || status === 'trimis') return 'Trimis';
        if (status === 'confirmed' || status === 'confirmat') return 'Confirmat';
        if (status === 'cancelled' || status === 'anulat') return 'Anulat';
        if (status === 'unsent' || status === 'netrimis') return 'Netrimis';
        return status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Netrimis';
    }

    function findAppointmentById(appointmentId) {
        const targetId = String(appointmentId || '').trim();
        if (!targetId) return null;
        return appointmentsCache.find((entry) => getAppointmentId(entry) === targetId) || null;
    }

    function clearDrawerFeedback() {
        if (el.drawerInlineError) {
            el.drawerInlineError.textContent = '';
            el.drawerInlineError.classList.add('hidden');
        }
        if (el.drawerInlineSuccess) {
            el.drawerInlineSuccess.textContent = '';
            el.drawerInlineSuccess.classList.add('hidden');
        }
    }

    function setDrawerError(message) {
        if (!el.drawerInlineError) return;
        if (el.drawerInlineSuccess) {
            el.drawerInlineSuccess.textContent = '';
            el.drawerInlineSuccess.classList.add('hidden');
        }
        el.drawerInlineError.textContent = String(message || 'A aparut o eroare.');
        el.drawerInlineError.classList.remove('hidden');
    }

    function setDrawerSuccess(message) {
        if (!el.drawerInlineSuccess) return;
        if (el.drawerInlineError) {
            el.drawerInlineError.textContent = '';
            el.drawerInlineError.classList.add('hidden');
        }
        el.drawerInlineSuccess.textContent = String(message || 'Operatiune finalizata.');
        el.drawerInlineSuccess.classList.remove('hidden');
    }

    function closeAppointmentDrawer() {
        drawerAppointmentId = '';
        clearDrawerFeedback();
        if (el.appointmentDrawer) {
            el.appointmentDrawer.classList.remove('is-open');
            el.appointmentDrawer.setAttribute('aria-hidden', 'true');
        }
    }

    function openAppointmentDrawer(entry) {
        if (!el.appointmentDrawer) return;
        const appointment = entry || findAppointmentById(drawerAppointmentId);
        const appointmentId = getAppointmentId(appointment);
        if (!appointment || !appointmentId) {
            closeAppointmentDrawer();
            return;
        }

        drawerAppointmentId = appointmentId;
        clearDrawerFeedback();

        const fullPatientName = String(appointment.patientName || appointment.name || '').trim();
        if (el.drawerPatientName) {
            el.drawerPatientName.textContent = fullPatientName || '-';
        }

        const patientPhone = String(appointment.patientPhone || appointment.phone || '').trim();
        if (el.drawerPatientPhone) {
            if (patientPhone) {
                el.drawerPatientPhone.textContent = `Telefon: ${patientPhone}`;
                el.drawerPatientPhone.classList.remove('hidden');
            } else {
                el.drawerPatientPhone.textContent = '';
                el.drawerPatientPhone.classList.add('hidden');
            }
        }

        const patientEmail = String(appointment.patientEmail || appointment.email || '').trim();
        if (el.drawerPatientEmail) {
            if (patientEmail) {
                el.drawerPatientEmail.textContent = `Email: ${patientEmail}`;
                el.drawerPatientEmail.classList.remove('hidden');
            } else {
                el.drawerPatientEmail.textContent = '';
                el.drawerPatientEmail.classList.add('hidden');
            }
        }

        const patientCnp = String(appointment.patientCnp || appointment.cnp || '').trim();
        if (el.drawerPatientCnp) {
            if (patientCnp) {
                el.drawerPatientCnp.textContent = `CNP: ${patientCnp}`;
                el.drawerPatientCnp.classList.remove('hidden');
            } else {
                el.drawerPatientCnp.textContent = '';
                el.drawerPatientCnp.classList.add('hidden');
            }
        }

        if (el.drawerDoctorName) {
            el.drawerDoctorName.textContent = String(appointment.doctorName || appointment.doctorSnapshotName || '-');
        }
        if (el.drawerType) {
            el.drawerType.textContent = String(appointment.type || '-');
        }
        if (el.drawerStatus) {
            el.drawerStatus.textContent = getAppointmentStatusLabel(appointment);
        }
        if (el.drawerTimeInterval) {
            el.drawerTimeInterval.textContent = getAppointmentTimeInterval(appointment);
        }

        const allowResend = isSchedulerOrSuperadmin();
        const allowCancel = isSchedulerOrSuperadmin();

        el.drawerResendBtn?.classList.toggle('hidden', !allowResend);
        el.drawerCancelSection?.classList.toggle('hidden', !allowCancel);
        el.drawerActionGroup?.classList.toggle('hidden', !allowResend && !allowCancel);

        if (el.appointmentDrawer) {
            el.appointmentDrawer.classList.add('is-open');
            el.appointmentDrawer.setAttribute('aria-hidden', 'false');
        }
    }

    function refreshDrawerFromCache() {
        if (!drawerAppointmentId) return;
        const nextEntry = findAppointmentById(drawerAppointmentId);
        if (!nextEntry) {
            closeAppointmentDrawer();
            return;
        }
        openAppointmentDrawer(nextEntry);
    }

    async function handleDrawerResendAction() {
        clearDrawerFeedback();
        const appointment = findAppointmentById(drawerAppointmentId);
        if (!appointment) {
            setDrawerError('Programarea selectata nu mai este disponibila.');
            return;
        }
        if (!isSchedulerOrSuperadmin()) {
            setDrawerError('Nu aveti drept de trimitere manuala.');
            return;
        }

        const appointmentId = getAppointmentId(appointment);
        setButtonLoading(el.drawerResendBtn, true, 'Se trimite...');
        try {
            const res = await AUTH.apiFetch(`/api/admin/resend-email/${appointmentId}`, { method: 'POST' });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setDrawerError(data.error || 'Eroare la trimiterea manuala.');
                return;
            }
            setDrawerSuccess(data.message || 'Email trimis.');
            await fetchAdminAppointments();
        } catch (_) {
            setDrawerError('Eroare de conexiune.');
        } finally {
            setButtonLoading(el.drawerResendBtn, false);
        }
    }

    async function handleDrawerCancelAction() {
        clearDrawerFeedback();
        const appointment = findAppointmentById(drawerAppointmentId);
        if (!appointment) {
            setDrawerError('Programarea selectata nu mai este disponibila.');
            return;
        }
        if (!isSchedulerOrSuperadmin()) {
            setDrawerError('Nu aveti drept de anulare.');
            return;
        }

        const confirmed = await showConfirmModal({
            title: 'Esti sigur?',
            message: 'Vrei sa anulezi aceasta programare?',
            confirmLabel: 'Da',
            cancelLabel: 'Nu',
            danger: true
        });
        if (!confirmed) {
            return;
        }

        setButtonLoading(el.drawerCancelBtn, true, 'Se anuleaza...');
        try {
            const appointmentId = getAppointmentId(appointment);
            const res = await AUTH.apiFetch(`/api/admin/appointment/${appointmentId}`, {
                method: 'DELETE'
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setDrawerError(data.error || 'Nu s-a putut anula programarea.');
                return;
            }

            closeAppointmentDrawer();
            await fetchAdminAppointments();
            fetchAdminStats();
        } catch (_) {
            setDrawerError('Eroare de conexiune.');
        } finally {
            setButtonLoading(el.drawerCancelBtn, false);
        }
    }

    function ensureScheduler() {
        if (scheduler) {
            return scheduler;
        }

        if (!window.AdminScheduler || typeof window.AdminScheduler.createScheduler !== 'function') {
            return null;
        }

        scheduler = window.AdminScheduler.createScheduler({
            mount: el.timelineGrid,
            config: {
                startHour: '08:00',
                endHour: '15:00',
                pxPerMinute: 2.5,
                onAppointmentClick: (appointment) => {
                    openAppointmentDrawer(appointment);
                }
            }
        });

        return scheduler;
    }

    function getSchedulerDoctorsForView() {
        const selectedDoctorId = String(el.appointmentDoctorFilter?.value || '').trim();
        if (selectedDoctorId) {
            const selectedDoctor = doctorsCache.find((doctor) => String(doctor._id || '') === selectedDoctorId);
            if (selectedDoctor) {
                return [selectedDoctor];
            }

            const fromAppointments = appointmentsCache.find((entry) => String(entry.doctorId || '') === selectedDoctorId);
            return [{
                _id: selectedDoctorId,
                displayName: String(fromAppointments?.doctorName || 'Medic selectat')
            }];
        }

        const activeDoctors = doctorsCache.filter((doctor) => !!doctor.isActive);
        return activeDoctors.length ? activeDoctors : doctorsCache;
    }

    function getFilteredAppointments() {
        if (!searchTerm) {
            return appointmentsCache;
        }

        return appointmentsCache.filter((app) => {
            return String(app.patientName || app.name || '').toLowerCase().includes(searchTerm)
                || String(app.patientPhone || app.phone || '').toLowerCase().includes(searchTerm)
                || String(app.patientEmail || app.email || '').toLowerCase().includes(searchTerm)
                || String(app.patientCnp || app.cnp || '').toLowerCase().includes(searchTerm);
        });
    }

    function renderTimelineForCurrentFilters({ isLoading = false, errorMessage = '' } = {}) {
        const schedulerInstance = ensureScheduler();
        if (!schedulerInstance) {
            setSingleMessage(el.timelineGrid, 'Modulul scheduler nu a putut fi incarcat.', 'p-10 text-center text-red-400 font-medium');
            return;
        }

        const filtered = getFilteredAppointments();
        if (isLoading) {
            el.timelineHeaderCount.textContent = '(...) Programari';
        } else if (errorMessage) {
            el.timelineHeaderCount.textContent = '(0) Programari';
        } else {
            el.timelineHeaderCount.textContent = `(${filtered.length}) Programari`;
        }

        schedulerInstance.render({
            appointments: filtered,
            doctors: getSchedulerDoctorsForView(),
            selectedDoctorId: String(el.appointmentDoctorFilter?.value || '').trim(),
            isLoading,
            errorMessage
        });
    }

    async function fetchAdminAppointments() {
        renderTimelineForCurrentFilters({ isLoading: true });

        try {
            const selectedDate = getAdminActiveDateISO();
            const selectedDoctorId = String(el.appointmentDoctorFilter?.value || '').trim();
            const params = new URLSearchParams({ date: selectedDate });
            if (selectedDoctorId) {
                params.set('doctorId', selectedDoctorId);
            }

            const res = await AUTH.apiFetch(`/api/admin/appointments?${params.toString()}`);
            const data = await res.json().catch(() => []);

            if (!res.ok) {
                throw new Error(data?.error || `Server error: ${res.status}`);
            }

            appointmentsCache = Array.isArray(data) ? data : [];
            renderTimelineForCurrentFilters();
            refreshDrawerFromCache();
        } catch (error) {
            appointmentsCache = [];
            renderTimelineForCurrentFilters({
                errorMessage: String(error?.message || 'Eroare la incarcare.')
            });
        }
    }

    async function fetchUsers() {
        clearNode(el.userTableBody);
        const loadingRow = document.createElement('tr');
        const loadingCell = document.createElement('td');
        loadingCell.colSpan = 6;
        const loadingWrap = document.createElement('div');
        loadingWrap.className = 'admin-empty-state is-loading';
        loadingWrap.textContent = 'Se incarca lista de utilizatori...';
        loadingCell.appendChild(loadingWrap);
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
        const payload = await new Promise((resolve) => {
            const modal = openModalFrame({
                title: 'Editeaza utilizator',
                description: 'Actualizeaza datele utilizatorului si rolul de acces.',
                wide: true,
                onDismiss: () => {
                    resolve(null);
                    closeActiveModal();
                }
            });
            if (!modal) {
                resolve(null);
                return;
            }

            const grid = document.createElement('div');
            grid.className = 'admin-modal-grid';

            const displayNameInput = document.createElement('input');
            displayNameInput.type = 'text';
            displayNameInput.className = 'form-input';
            displayNameInput.value = String(user.displayName || '');
            grid.appendChild(createModalField('Nume afisat', displayNameInput));

            const roleSelect = document.createElement('select');
            roleSelect.className = 'form-input';
            ['viewer', 'scheduler', 'superadmin'].forEach((value) => {
                const option = document.createElement('option');
                option.value = value;
                option.textContent = value;
                option.selected = String(user.role || '') === value;
                roleSelect.appendChild(option);
            });
            grid.appendChild(createModalField('Rol', roleSelect));

            const emailInput = document.createElement('input');
            emailInput.type = 'email';
            emailInput.className = 'form-input';
            emailInput.value = String(user.email || '');
            grid.appendChild(createModalField('Email', emailInput));

            const phoneInput = document.createElement('input');
            phoneInput.type = 'text';
            phoneInput.className = 'form-input';
            phoneInput.value = String(user.phone || '');
            grid.appendChild(createModalField('Telefon', phoneInput));

            const passwordInput = document.createElement('input');
            passwordInput.type = 'password';
            passwordInput.className = 'form-input';
            passwordInput.placeholder = 'Gol daca nu schimbi parola';
            passwordInput.autocomplete = 'new-password';
            grid.appendChild(createModalField('Parola noua (optional)', passwordInput));

            const managedSelect = document.createElement('select');
            managedSelect.className = 'form-input min-h-[140px]';
            managedSelect.multiple = true;
            const selectedSet = new Set(Array.isArray(user.managedDoctorIds) ? user.managedDoctorIds : []);
            doctorsCache.forEach((doctor) => {
                const option = document.createElement('option');
                option.value = String(doctor._id);
                option.textContent = `${doctor.displayName} (${doctor.slug})${doctor.isActive ? '' : ' [inactiv]'}`;
                option.selected = selectedSet.has(option.value);
                managedSelect.appendChild(option);
                selectedSet.delete(option.value);
            });
            selectedSet.forEach((legacyId) => {
                const option = document.createElement('option');
                option.value = String(legacyId);
                option.textContent = `${legacyId} [medic indisponibil]`;
                option.selected = true;
                managedSelect.appendChild(option);
            });
            const managedWrap = document.createElement('div');
            managedWrap.className = 'admin-modal-grid admin-modal-grid-1';
            const managedField = createModalField('Doctori asignati', managedSelect);
            const managedHint = document.createElement('p');
            managedHint.className = 'admin-modal-helper';
            managedHint.textContent = 'Selectie multipla: Ctrl/Cmd + click.';
            managedField.appendChild(managedHint);
            managedWrap.appendChild(managedField);

            modal.body.appendChild(grid);
            modal.body.appendChild(managedWrap);

            const cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = BTN_CLASS.ghost;
            cancelBtn.textContent = 'Anuleaza';
            cancelBtn.addEventListener('click', () => {
                resolve(null);
                modal.close();
            });

            const saveBtn = document.createElement('button');
            saveBtn.type = 'button';
            saveBtn.className = BTN_CLASS.primary;
            saveBtn.textContent = 'Salveaza';
            saveBtn.addEventListener('click', () => {
                const displayName = String(displayNameInput.value || '').trim();
                const email = String(emailInput.value || '').trim();
                const phone = String(phoneInput.value || '').trim();
                const role = String(roleSelect.value || '').trim();
                const password = String(passwordInput.value || '');
                const managedDoctorIds = Array.from(managedSelect.selectedOptions).map((option) => String(option.value || '').trim()).filter(Boolean);

                if (!displayName || !email || !phone) {
                    modal.setError('Nume, email si telefon sunt obligatorii.');
                    return;
                }
                if (!['viewer', 'scheduler', 'superadmin'].includes(role)) {
                    modal.setError('Rol invalid.');
                    return;
                }

                const nextPayload = {
                    displayName,
                    email,
                    phone,
                    role,
                    managedDoctorIds
                };
                if (password.trim()) {
                    nextPayload.password = password;
                }

                resolve(nextPayload);
                modal.close();
            });

            modal.actions.appendChild(cancelBtn);
            modal.actions.appendChild(saveBtn);
            displayNameInput.focus();
        });

        if (!payload) return;

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
        const confirmed = await showConfirmModal({
            title: 'Sterge utilizator',
            message: `Esti sigur ca vrei sa stergi utilizatorul ${user.displayName || user.email}?`,
            confirmLabel: 'Sterge utilizator',
            danger: true
        });
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
        if (!Array.isArray(users) || users.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 6;
            const empty = document.createElement('div');
            empty.className = 'admin-empty-state';
            empty.textContent = 'Nu exista utilizatori inregistrati.';
            cell.appendChild(empty);
            row.appendChild(cell);
            el.userTableBody.appendChild(row);
            return;
        }

        const currentUser = AUTH.getUser() || {};
        users.forEach((user) => {
            const row = document.createElement('tr');
            row.className = 'border-b border-brand-600/10 hover:bg-brand-600/5 transition-colors';

            const nameCell = document.createElement('td');
            nameCell.className = 'py-4 font-medium cell-truncate';
            nameCell.title = user.displayName || '';
            nameCell.textContent = user.displayName || '';

            const emailCell = document.createElement('td');
            emailCell.className = 'py-4 cell-secondary cell-truncate';
            emailCell.title = user.email || '';
            emailCell.textContent = user.email || '';

            const phoneCell = document.createElement('td');
            phoneCell.className = 'py-4 cell-secondary';
            phoneCell.textContent = user.phone || '';

            const roleCell = document.createElement('td');
            roleCell.className = 'py-4 text-center';
            const roleBadge = document.createElement('span');
            const role = String(user.role || 'viewer').toLowerCase();
            const roleLabelByKey = {
                viewer: 'Regular',
                scheduler: 'Admin',
                superadmin: 'Superadmin'
            };
            roleBadge.className = `role-badge ${role}`;
            roleBadge.textContent = roleLabelByKey[role] || role;
            roleCell.appendChild(roleBadge);

            const doctorsCell = document.createElement('td');
            doctorsCell.className = 'py-4 cell-secondary cell-truncate';
            const managedDoctors = Array.isArray(user.managedDoctors) ? user.managedDoctors : [];
            const managedText = managedDoctors.length
                ? managedDoctors.map((doctor) => doctor.displayName).join(', ')
                : '-';
            doctorsCell.textContent = managedText;
            doctorsCell.title = managedText;

            const actionsCell = document.createElement('td');
            actionsCell.className = 'py-4 text-right';
            const actionWrap = document.createElement('div');
            actionWrap.className = 'admin-action-group';

            const editBtn = document.createElement('button');
            editBtn.className = BTN_CLASS.secondary;
            editBtn.textContent = 'Editeaza';
            editBtn.onclick = () => openEditUserDialog(user);

            actionWrap.appendChild(editBtn);

            const isSelf = String(user.email || '') === String(currentUser.email || '');
            if (!isSelf) {
                const deleteBtn = document.createElement('button');
                deleteBtn.className = BTN_CLASS.danger;
                deleteBtn.textContent = 'Sterge';
                deleteBtn.onclick = async () => {
                    setButtonLoading(deleteBtn, true, 'Se sterge...');
                    try {
                        await deleteUser(user);
                    } finally {
                        setButtonLoading(deleteBtn, false);
                    }
                };
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

        setButtonLoading(el.createUserSubmit, true, 'Se salveaza...');
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
            setButtonLoading(el.createUserSubmit, false);
        }
    }
    async function createDoctor() {
        let dayConfigs;
        try {
            dayConfigs = collectDoctorDayConfigsFromForm();
        } catch (error) {
            showToast('Eroare', String(error?.message || 'Configuratie invalida pentru zile.'), 'error');
            return;
        }

        const monthsToShow = Number(el.doctorMonthsToShow.value);
        if (!Number.isInteger(monthsToShow) || monthsToShow < 1 || monthsToShow > 12) {
            showToast('Eroare', 'Luni vizibile trebuie sa fie intre 1 si 12.', 'error');
            return;
        }

        const firstConfig = dayConfigs[0];
        const payload = {
            slug: el.doctorSlug.value.trim().toLowerCase(),
            displayName: el.doctorDisplayName.value.trim(),
            specialty: el.doctorSpecialty.value.trim() || 'Oftalmologie',
            isActive: el.doctorIsActive.value === 'true',
            bookingSettings: {
                consultationDurationMinutes: firstConfig.consultationDurationMinutes,
                workdayStart: firstConfig.startTime,
                workdayEnd: firstConfig.endTime,
                monthsToShow,
                timezone: 'Europe/Bucharest'
            },
            availabilityRules: {
                weekdays: dayConfigs.map((config) => config.weekday),
                dayConfigs
            },
            blockedDates: []
        };

        if (!payload.slug || !payload.displayName) {
            showToast('Eroare', 'Slug si nume afisat sunt obligatorii.', 'error');
            return;
        }

        setButtonLoading(el.createDoctorSubmit, true, 'Se salveaza...');
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
            renderDoctorDayConfigList();
            isCreateDoctorFormOpen = false;
            updateCreateDoctorVisibility();
            await fetchDoctors();
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        } finally {
            setButtonLoading(el.createDoctorSubmit, false);
        }
    }

    function updateCreateDoctorVisibility({ focusForm = false } = {}) {
        const canCreateDoctor = isSuperadmin();
        const showForm = canCreateDoctor && isCreateDoctorFormOpen;

        if (el.createDoctorCard) {
            el.createDoctorCard.classList.toggle('hidden', !showForm);
        }

        if (el.toggleCreateDoctorBtn) {
            el.toggleCreateDoctorBtn.classList.toggle('hidden', !canCreateDoctor);
            el.toggleCreateDoctorBtn.textContent = showForm ? 'Ascunde formularul' : 'Creeaza medic nou';
            el.toggleCreateDoctorBtn.setAttribute('aria-expanded', showForm ? 'true' : 'false');
        }

        if (showForm && focusForm) {
            el.doctorSlug?.focus();
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
        const payload = await new Promise((resolve) => {
            const modal = openModalFrame({
                title: `Editeaza medic: ${doctor.displayName || ''}`,
                description: `Slug: ${doctor.slug || '-'}`,
                wide: true,
                onDismiss: () => {
                    resolve(null);
                    closeActiveModal();
                }
            });
            if (!modal) {
                resolve(null);
                return;
            }

            const grid = document.createElement('div');
            grid.className = 'admin-modal-grid';

            const displayNameInput = document.createElement('input');
            displayNameInput.type = 'text';
            displayNameInput.className = 'form-input';
            displayNameInput.value = String(doctor.displayName || '');
            grid.appendChild(createModalField('Nume afisat', displayNameInput));

            const specialtyInput = document.createElement('input');
            specialtyInput.type = 'text';
            specialtyInput.className = 'form-input';
            specialtyInput.value = String(doctor.specialty || 'Oftalmologie');
            grid.appendChild(createModalField('Specialitate', specialtyInput));

            const monthsInput = document.createElement('input');
            monthsInput.type = 'number';
            monthsInput.min = '1';
            monthsInput.max = '12';
            monthsInput.className = 'form-input';
            monthsInput.value = String(doctor.bookingSettings?.monthsToShow || 3);
            grid.appendChild(createModalField('Luni vizibile', monthsInput));

            const activeSelect = document.createElement('select');
            activeSelect.className = 'form-input';
            [
                { value: 'true', label: 'Da' },
                { value: 'false', label: 'Nu' }
            ].forEach((entry) => {
                const option = document.createElement('option');
                option.value = entry.value;
                option.textContent = entry.label;
                activeSelect.appendChild(option);
            });
            activeSelect.value = doctor.isActive ? 'true' : 'false';
            grid.appendChild(createModalField('Activ', activeSelect));

            modal.body.appendChild(grid);

            const scheduleToggleWrap = document.createElement('label');
            scheduleToggleWrap.className = 'flex items-center gap-2 text-sm text-brand-300 font-semibold';
            const scheduleToggle = document.createElement('input');
            scheduleToggle.type = 'checkbox';
            scheduleToggle.className = 'w-4 h-4 rounded border-brand-600 accent-brand-400';
            scheduleToggle.checked = false;
            scheduleToggleWrap.appendChild(scheduleToggle);
            scheduleToggleWrap.appendChild(document.createTextNode('Actualizeaza programul saptamanal'));
            modal.body.appendChild(scheduleToggleWrap);

            const dayConfigContainer = document.createElement('div');
            dayConfigContainer.className = 'space-y-2 hidden';
            renderDayConfigRows(dayConfigContainer, getDoctorDayConfigs(doctor));
            modal.body.appendChild(dayConfigContainer);

            const hint = document.createElement('p');
            hint.className = 'admin-modal-helper hidden';
            hint.textContent = 'Intervalele trebuie sa fie divizibile perfect la durata consultatiei.';
            modal.body.appendChild(hint);

            const syncScheduleVisibility = () => {
                const visible = !!scheduleToggle.checked;
                dayConfigContainer.classList.toggle('hidden', !visible);
                hint.classList.toggle('hidden', !visible);
            };
            scheduleToggle.addEventListener('change', syncScheduleVisibility);
            syncScheduleVisibility();

            const cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = BTN_CLASS.ghost;
            cancelBtn.textContent = 'Anuleaza';
            cancelBtn.addEventListener('click', () => {
                resolve(null);
                modal.close();
            });

            const saveBtn = document.createElement('button');
            saveBtn.type = 'button';
            saveBtn.className = BTN_CLASS.primary;
            saveBtn.textContent = 'Salveaza';
            saveBtn.addEventListener('click', () => {
                const displayName = String(displayNameInput.value || '').trim();
                const specialty = String(specialtyInput.value || '').trim() || 'Oftalmologie';
                const monthsToShow = Number(monthsInput.value);
                const isActive = activeSelect.value === 'true';
                if (!displayName) {
                    modal.setError('Numele afisat este obligatoriu.');
                    return;
                }
                if (!Number.isInteger(monthsToShow) || monthsToShow < 1 || monthsToShow > 12) {
                    modal.setError('Luni vizibile trebuie sa fie intre 1 si 12.');
                    return;
                }

                const nextPayload = { displayName, specialty, isActive };
                if (scheduleToggle.checked) {
                    let dayConfigs;
                    try {
                        dayConfigs = collectDayConfigsFromContainer(dayConfigContainer);
                    } catch (error) {
                        modal.setError(String(error?.message || 'Configuratie invalida pentru program.'));
                        return;
                    }
                    const firstConfig = dayConfigs[0];
                    nextPayload.bookingSettings = {
                        consultationDurationMinutes: firstConfig.consultationDurationMinutes,
                        workdayStart: firstConfig.startTime,
                        workdayEnd: firstConfig.endTime,
                        monthsToShow,
                        timezone: doctor.bookingSettings?.timezone || 'Europe/Bucharest'
                    };
                    nextPayload.availabilityRules = {
                        weekdays: dayConfigs.map((config) => config.weekday),
                        dayConfigs
                    };
                } else {
                    nextPayload.bookingSettings = {
                        consultationDurationMinutes: Number(doctor.bookingSettings?.consultationDurationMinutes || 20),
                        workdayStart: doctor.bookingSettings?.workdayStart || '09:00',
                        workdayEnd: doctor.bookingSettings?.workdayEnd || '14:00',
                        monthsToShow,
                        timezone: doctor.bookingSettings?.timezone || 'Europe/Bucharest'
                    };
                }

                resolve(nextPayload);
                modal.close();
            });

            modal.actions.appendChild(cancelBtn);
            modal.actions.appendChild(saveBtn);
            displayNameInput.focus();
        });

        if (!payload) return;
        await patchDoctor(doctor._id, payload, 'Medic actualizat.');
    }

    function openDateModal({ title, description, label, confirmLabel, initialDate = '' }) {
        return new Promise((resolve) => {
            const modal = openModalFrame({
                title,
                description,
                onDismiss: () => {
                    resolve(null);
                    closeActiveModal();
                }
            });
            if (!modal) {
                resolve(null);
                return;
            }

            const dateInput = document.createElement('input');
            dateInput.type = 'date';
            dateInput.className = 'form-input';
            dateInput.value = initialDate;
            modal.body.appendChild(createModalField(label, dateInput));

            const cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = BTN_CLASS.ghost;
            cancelBtn.textContent = 'Anuleaza';
            cancelBtn.addEventListener('click', () => {
                resolve(null);
                modal.close();
            });

            const confirmBtn = document.createElement('button');
            confirmBtn.type = 'button';
            confirmBtn.className = BTN_CLASS.primary;
            confirmBtn.textContent = confirmLabel;
            confirmBtn.addEventListener('click', () => {
                const value = String(dateInput.value || '').trim();
                if (!value) {
                    modal.setError('Data este obligatorie.');
                    return;
                }
                resolve(value);
                modal.close();
            });

            modal.actions.appendChild(cancelBtn);
            modal.actions.appendChild(confirmBtn);
            dateInput.focus();
        });
    }

    async function blockDoctorDate(doctor) {
        const date = await openDateModal({
            title: 'Blocheaza o zi pentru medic',
            description: doctor.displayName || '',
            label: 'Data de blocat',
            confirmLabel: 'Blocheaza',
            initialDate: getAdminActiveDateISO()
        });
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
        const date = await openDateModal({
            title: 'Reactiveaza o zi pentru medic',
            description: doctor.displayName || '',
            label: 'Data de reactivat',
            confirmLabel: 'Reactiveaza',
            initialDate: getAdminActiveDateISO()
        });
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

    async function deleteDoctor(doctor) {
        if (!isSuperadmin()) {
            showToast('Acces interzis', 'Doar superadmin poate sterge medici.', 'error');
            return;
        }

        const confirmed = await showConfirmModal({
            title: 'Stergere definitiva medic',
            message: `Stergi definitiv medicul ${doctor.displayName}? Actiunea sterge si programarile asociate.`,
            confirmLabel: 'Sterge definitiv',
            danger: true
        });
        if (!confirmed) return;

        const stepUpToken = await requestStepUp('doctor_delete', 'stergerea medicului');
        if (!stepUpToken) return;

        try {
            const res = await AUTH.apiFetch(`/api/admin/doctors/${doctor._id}`, {
                method: 'DELETE',
                headers: { 'X-Step-Up-Token': stepUpToken }
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showToast('Eroare', data.error || 'Nu s-a putut sterge medicul.', 'error');
                return;
            }
            showToast('Succes', data.message || 'Medic sters definitiv.');
            await fetchDoctors();
            await fetchAdminAppointments();
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
        }
    }

    function openDayScheduleModal(current, selectedDate) {
        return new Promise((resolve) => {
            const currentRule = current?.daySchedule?.overrideRule || current?.daySchedule?.defaultRule;
            const defaultRule = current?.daySchedule?.defaultRule || null;
            const hasOverride = !!current?.daySchedule?.overrideRule;

            const modal = openModalFrame({
                title: 'Editeaza program zi',
                description: `Data selectata: ${selectedDate}`,
                onDismiss: () => {
                    resolve(null);
                    closeActiveModal();
                }
            });
            if (!modal) {
                resolve(null);
                return;
            }

            const statusSelect = document.createElement('select');
            statusSelect.className = 'form-input';
            [
                { value: 'active', label: 'Activa' },
                { value: 'blocked', label: 'Blocata' }
            ].forEach((item) => {
                const option = document.createElement('option');
                option.value = item.value;
                option.textContent = item.label;
                statusSelect.appendChild(option);
            });
            statusSelect.value = current?.daySchedule?.blocked ? 'blocked' : 'active';
            modal.body.appendChild(createModalField('Status zi', statusSelect));

            const modeSelect = document.createElement('select');
            modeSelect.className = 'form-input';
            const modeDefault = document.createElement('option');
            modeDefault.value = 'default';
            modeDefault.textContent = 'Program standard';
            if (!defaultRule) {
                modeDefault.disabled = true;
                modeDefault.textContent = 'Program standard indisponibil';
            }
            const modeCustom = document.createElement('option');
            modeCustom.value = 'custom';
            modeCustom.textContent = 'Override personalizat';
            modeSelect.appendChild(modeDefault);
            modeSelect.appendChild(modeCustom);
            modeSelect.value = hasOverride ? 'custom' : 'default';
            if (!defaultRule && modeSelect.value === 'default') {
                modeSelect.value = 'custom';
            }
            modal.body.appendChild(createModalField('Mod program', modeSelect));

            const customGrid = document.createElement('div');
            customGrid.className = 'admin-modal-grid';
            const startInput = document.createElement('input');
            startInput.type = 'time';
            startInput.className = 'form-input';
            startInput.value = currentRule?.startTime || '09:00';
            customGrid.appendChild(createModalField('Ora inceput', startInput));

            const endInput = document.createElement('input');
            endInput.type = 'time';
            endInput.className = 'form-input';
            endInput.value = currentRule?.endTime || '14:00';
            customGrid.appendChild(createModalField('Ora sfarsit', endInput));

            const durationInput = document.createElement('input');
            durationInput.type = 'number';
            durationInput.min = '5';
            durationInput.max = '120';
            durationInput.className = 'form-input';
            durationInput.value = String(Number(currentRule?.consultationDurationMinutes || 20));
            customGrid.appendChild(createModalField('Durata consultatie (minute)', durationInput));
            modal.body.appendChild(customGrid);

            const helper = document.createElement('p');
            helper.className = 'admin-modal-helper';
            helper.textContent = 'Modificarile care invalideaza programari existente vor fi blocate de server.';
            modal.body.appendChild(helper);

            const syncVisibility = () => {
                const active = statusSelect.value === 'active';
                modeSelect.parentElement.classList.toggle('hidden', !active);
                customGrid.classList.toggle('hidden', !active || modeSelect.value !== 'custom');
            };
            statusSelect.addEventListener('change', syncVisibility);
            modeSelect.addEventListener('change', syncVisibility);
            syncVisibility();

            const cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = BTN_CLASS.ghost;
            cancelBtn.textContent = 'Anuleaza';
            cancelBtn.addEventListener('click', () => {
                resolve(null);
                modal.close();
            });

            const saveBtn = document.createElement('button');
            saveBtn.type = 'button';
            saveBtn.className = BTN_CLASS.primary;
            saveBtn.textContent = 'Salveaza';
            saveBtn.addEventListener('click', () => {
                if (statusSelect.value === 'blocked') {
                    resolve({ status: 'blocked', clearOverride: true });
                    modal.close();
                    return;
                }

                if (modeSelect.value === 'default') {
                    resolve({ status: 'active', clearOverride: true });
                    modal.close();
                    return;
                }

                const startTime = String(startInput.value || '').trim();
                const endTime = String(endInput.value || '').trim();
                const consultationDurationMinutes = Number(durationInput.value);
                if (!isValidScheduleWindow(startTime, endTime, consultationDurationMinutes, { requireDivisible: true })) {
                    modal.setError('Interval invalid sau intervalul nu se imparte perfect la durata.');
                    return;
                }

                resolve({
                    status: 'active',
                    clearOverride: false,
                    startTime,
                    endTime,
                    consultationDurationMinutes
                });
                modal.close();
            });

            modal.actions.appendChild(cancelBtn);
            modal.actions.appendChild(saveBtn);
            statusSelect.focus();
        });
    }

    async function editSelectedDaySchedule() {
        if (!isSchedulerOrSuperadmin()) {
            showToast('Acces interzis', 'Nu aveti drept de editare pentru programul zilnic.', 'error');
            return;
        }

        const doctorId = String(el.appointmentDoctorFilter?.value || '');
        if (!doctorId) {
            showToast('Atentie', 'Selecteaza un medic pentru a edita programul zilei.', 'error');
            return;
        }

        const selectedDate = getAdminActiveDateISO();

        let current;
        try {
            const infoRes = await AUTH.apiFetch(`/api/admin/doctors/${doctorId}/day-schedule/${selectedDate}`);
            const info = await infoRes.json().catch(() => ({}));
            if (!infoRes.ok) {
                showToast('Eroare', info.error || 'Nu s-au putut incarca detaliile zilei.', 'error');
                return;
            }
            current = info;
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune.', 'error');
            return;
        }

        const payload = await openDayScheduleModal(current, selectedDate);
        if (!payload) return;

        try {
            const res = await AUTH.apiFetch(`/api/admin/doctors/${doctorId}/day-schedule/${selectedDate}`, {
                method: 'PATCH',
                body: JSON.stringify(payload)
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                if (res.status === 409 && Array.isArray(data.conflictTimes) && data.conflictTimes.length) {
                    showToast('Conflict', `Programari afectate: ${data.conflictTimes.join(', ')}`, 'error');
                } else {
                    showToast('Eroare', data.error || 'Nu s-a putut actualiza ziua.', 'error');
                }
                return;
            }

            showToast('Succes', 'Programul zilei a fost actualizat.');
            await fetchDoctors();
            await fetchAdminAppointments();
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
            const empty = document.createElement('div');
            empty.className = 'admin-empty-state';
            empty.textContent = 'Nu exista medici disponibili.';
            cell.appendChild(empty);
            row.appendChild(cell);
            el.doctorTableBody.appendChild(row);
            return;
        }

        doctorsCache.forEach((doctor) => {
            const row = document.createElement('tr');
            row.className = 'border-b border-brand-600/10 hover:bg-brand-600/5 transition-colors';

            const nameCell = document.createElement('td');
            nameCell.className = 'py-4 font-medium cell-truncate';
            nameCell.title = doctor.displayName || '';
            nameCell.textContent = doctor.displayName || '';

            const slugCell = document.createElement('td');
            slugCell.className = 'py-4 cell-secondary cell-truncate';
            slugCell.title = doctor.slug || '';
            slugCell.textContent = doctor.slug || '';

            const scheduleCell = document.createElement('td');
            scheduleCell.className = 'py-4 cell-secondary';
            const dayConfigs = getDoctorDayConfigs(doctor)
                .slice()
                .sort((a, b) => a.weekday - b.weekday);
            if (dayConfigs.length) {
                const scheduleRows = dayConfigs.map((config) => {
                    const dayLabel = WEEKDAY_SHORT[config.weekday] || '-';
                    return `${dayLabel} ${config.startTime}-${config.endTime} / ${config.consultationDurationMinutes}m`;
                });
                const scheduleList = document.createElement('div');
                scheduleList.className = 'doctor-schedule-list';
                scheduleRows.forEach((entry) => {
                    const scheduleItem = document.createElement('div');
                    scheduleItem.className = 'doctor-schedule-item';
                    scheduleItem.textContent = entry;
                    scheduleList.appendChild(scheduleItem);
                });
                scheduleCell.title = scheduleRows.join(' | ');
                scheduleCell.appendChild(scheduleList);
            } else {
                scheduleCell.textContent = '-';
            }

            const weekdaysCell = document.createElement('td');
            weekdaysCell.className = 'py-4 cell-secondary cell-truncate';
            const weekdaysText = dayConfigs.length
                ? dayConfigs.map((config) => WEEKDAY_SHORT[config.weekday]).join(', ')
                : '-';
            weekdaysCell.textContent = weekdaysText;
            weekdaysCell.title = weekdaysText;

            const activeCell = document.createElement('td');
            activeCell.className = 'py-4 text-brand-300';
            const statusBadge = document.createElement('span');
            statusBadge.className = `status-badge ${doctor.isActive ? 'active' : 'inactive'}`;
            statusBadge.textContent = doctor.isActive ? 'Activ' : 'Inactiv';
            activeCell.appendChild(statusBadge);
            if (!doctor.isActive) {
                row.classList.add('opacity-70');
            }

            const actionsCell = document.createElement('td');
            actionsCell.className = 'py-4 text-right';
            const actionWrap = document.createElement('div');
            actionWrap.className = 'admin-action-group';

            const editBtn = document.createElement('button');
            editBtn.className = BTN_CLASS.secondary;
            editBtn.textContent = 'Editeaza';
            editBtn.onclick = async () => {
                setButtonLoading(editBtn, true, 'Se deschide...');
                try {
                    await openEditDoctorDialog(doctor);
                } finally {
                    setButtonLoading(editBtn, false);
                }
            };
            actionWrap.appendChild(editBtn);

            const blockBtn = document.createElement('button');
            blockBtn.className = BTN_CLASS.warning;
            blockBtn.textContent = 'Blocheaza zi';
            blockBtn.onclick = async () => {
                setButtonLoading(blockBtn, true, 'Se aplica...');
                try {
                    await blockDoctorDate(doctor);
                } finally {
                    setButtonLoading(blockBtn, false);
                }
            };
            actionWrap.appendChild(blockBtn);

            const unblockBtn = document.createElement('button');
            unblockBtn.className = BTN_CLASS.secondary;
            unblockBtn.textContent = 'Reactiveaza zi';
            unblockBtn.onclick = async () => {
                setButtonLoading(unblockBtn, true, 'Se aplica...');
                try {
                    await unblockDoctorDate(doctor);
                } finally {
                    setButtonLoading(unblockBtn, false);
                }
            };
            actionWrap.appendChild(unblockBtn);

            const toggleBtn = document.createElement('button');
            toggleBtn.className = BTN_CLASS.secondary;
            toggleBtn.textContent = doctor.isActive ? 'Dezactiveaza' : 'Activeaza';
            toggleBtn.onclick = async () => {
                setButtonLoading(toggleBtn, true, 'Se actualizeaza...');
                try {
                    await patchDoctor(doctor._id, { isActive: !doctor.isActive }, 'Status medic actualizat.');
                } finally {
                    setButtonLoading(toggleBtn, false);
                }
            };
            actionWrap.appendChild(toggleBtn);

            if (isSuperadmin()) {
                const deleteBtn = document.createElement('button');
                deleteBtn.className = BTN_CLASS.danger;
                deleteBtn.textContent = 'Sterge medic';
                deleteBtn.onclick = async () => {
                    setButtonLoading(deleteBtn, true, 'Se sterge...');
                    try {
                        await deleteDoctor(doctor);
                    } finally {
                        setButtonLoading(deleteBtn, false);
                    }
                };
                actionWrap.appendChild(deleteBtn);
            }

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
        closeAppointmentDrawer();
        el.timelineContainer.classList.add('hidden');
        el.doctorManagerContainer.classList.add('hidden');
        el.userManagerContainer.classList.remove('hidden');
    }

    function showDoctorSection() {
        closeAppointmentDrawer();
        el.timelineContainer.classList.add('hidden');
        el.userManagerContainer.classList.add('hidden');
        el.doctorManagerContainer.classList.remove('hidden');
        isCreateDoctorFormOpen = false;
        updateCreateDoctorVisibility();
    }

    function registerEvents() {
        if (eventsBound) {
            return;
        }
        eventsBound = true;

        el.prevAdminDate.onclick = () => {
            adminActiveDate.setDate(adminActiveDate.getDate() - 1);
            clampAdminDateWithinBounds();
            updateAdminDateDisplay();
            fetchAdminAppointments();
            renderAdminCalendar();
        };

        el.nextAdminDate.onclick = () => {
            adminActiveDate.setDate(adminActiveDate.getDate() + 1);
            clampAdminDateWithinBounds();
            updateAdminDateDisplay();
            fetchAdminAppointments();
            renderAdminCalendar();
        };

        el.appointmentDoctorFilter?.addEventListener('change', () => {
            clampAdminDateWithinBounds();
            updateAdminDateDisplay();
            fetchAdminAppointments();
            renderAdminCalendar();
        });

        el.appointmentDrawerClose?.addEventListener('click', () => {
            closeAppointmentDrawer();
        });

        el.drawerResendBtn?.addEventListener('click', async () => {
            await handleDrawerResendAction();
        });

        el.drawerCancelBtn?.addEventListener('click', async () => {
            await handleDrawerCancelAction();
        });

        el.adminCalendarPrevMonth?.addEventListener('click', () => {
            adminCalendarMonth = new Date(adminCalendarMonth.getFullYear(), adminCalendarMonth.getMonth() - 1, 1);
            renderAdminCalendar();
        });

        el.adminCalendarNextMonth?.addEventListener('click', () => {
            adminCalendarMonth = new Date(adminCalendarMonth.getFullYear(), adminCalendarMonth.getMonth() + 1, 1);
            renderAdminCalendar();
        });

        el.manageUsersBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate gestiona utilizatorii.', 'error');
                return;
            }
            setButtonLoading(el.manageUsersBtn, true, 'Se incarca...');
            try {
                showUserSection();
                await fetchUsers();
            } finally {
                setButtonLoading(el.manageUsersBtn, false);
            }
        });

        el.manageDoctorsBtn?.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate gestiona medicii.', 'error');
                return;
            }
            setButtonLoading(el.manageDoctorsBtn, true, 'Se incarca...');
            try {
                showDoctorSection();
                await fetchDoctors();
            } finally {
                setButtonLoading(el.manageDoctorsBtn, false);
            }
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

        el.toggleCreateDoctorBtn?.addEventListener('click', () => {
            isCreateDoctorFormOpen = !isCreateDoctorFormOpen;
            updateCreateDoctorVisibility({ focusForm: isCreateDoctorFormOpen });
        });

        el.editDayScheduleBtn?.addEventListener('click', async () => {
            setButtonLoading(el.editDayScheduleBtn, true, 'Se incarca...');
            try {
                await editSelectedDaySchedule();
            } finally {
                setButtonLoading(el.editDayScheduleBtn, false);
            }
        });

        el.resetDatabaseBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate reseta baza de date.', 'error');
                return;
            }

            const confirmReset = await showConfirmModal({
                title: 'Reset programari',
                message: 'Esti sigur ca vrei sa stergi TOATE programarile?',
                confirmLabel: 'Reseteaza',
                danger: true
            });
            if (!confirmReset) return;

            const stepUpToken = await requestStepUp('appointments_reset', 'resetarea bazei de date');
            if (!stepUpToken) return;

            setButtonLoading(el.resetDatabaseBtn, true, 'Se reseteaza...');
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
            } finally {
                setButtonLoading(el.resetDatabaseBtn, false);
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
            const confirmed = await showConfirmModal({
                title: 'Anuleaza ziua',
                message: `Blocam ziua ${selectedDate} pentru medicul selectat?`,
                confirmLabel: 'Blocheaza ziua',
                danger: true
            });
            if (!confirmed) return;

            setButtonLoading(el.cancelDayAppointmentsBtn, true, 'Se blocheaza...');
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
            } finally {
                setButtonLoading(el.cancelDayAppointmentsBtn, false);
            }
        });

        el.exportExcelBtn.addEventListener('click', async () => {
            if (!isSuperadmin()) {
                showToast('Acces interzis', 'Doar superadmin poate exporta date.', 'error');
                return;
            }

            const stepUpToken = await requestStepUp('appointments_export', 'exportul datelor');
            if (!stepUpToken) return;

            setButtonLoading(el.exportExcelBtn, true, 'Se exporta...');
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
            } finally {
                setButtonLoading(el.exportExcelBtn, false);
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
        renderDoctorDayConfigList();

        await fetchDoctors();
        await fetchAdminAppointments();
        fetchAdminStats();

        const superadmin = isSuperadmin();
        const schedulerOrSuperadmin = isSchedulerOrSuperadmin();
        el.manageUsersBtn.classList.toggle('hidden', !superadmin);
        el.manageDoctorsBtn?.classList.toggle('hidden', !superadmin);
        el.editDayScheduleBtn?.classList.toggle('hidden', !schedulerOrSuperadmin);
        el.resetDatabaseBtn.classList.toggle('hidden', !superadmin);
        el.cancelDayAppointmentsBtn.classList.toggle('hidden', !superadmin);
        el.exportExcelBtn.classList.toggle('hidden', !superadmin);
        el.createUserCard.classList.toggle('hidden', !superadmin);
        isCreateDoctorFormOpen = false;
        updateCreateDoctorVisibility();

        clampAdminDateWithinBounds();
        updateAdminDateDisplay();
        renderAdminCalendar();

        registerEvents();
    }

    async function bootstrap() {
        try {
            updateAuthUI(AUTH.getUser());

            const verifyWithTimeout = Promise.race([
                AUTH.verify(),
                new Promise((resolve) => setTimeout(() => resolve(null), 12000))
            ]);

            const verifiedUser = await verifyWithTimeout;
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
        } catch (error) {
            console.error('Admin bootstrap failed:', error);
            showScreen('auth');
            showToast('Eroare', 'Panoul nu a putut fi initializat. Reincarca pagina.', 'error');
        }
    }

    bootstrap();
});
