document.addEventListener('DOMContentLoaded', () => {
    const byId = (id) => document.getElementById(id);

    const stepCalendar = byId('step-calendar');
    const stepSlots = byId('step-slots');
    const stepForm = byId('step-form');

    if (!stepCalendar || !stepSlots || !stepForm) {
        return;
    }

    const stepDot1 = byId('stepDot1');
    const stepDot2 = byId('stepDot2');
    const stepDot3 = byId('stepDot3');
    const stepLine1 = byId('stepLine1');
    const stepLine2 = byId('stepLine2');
    const stepLabel2 = byId('stepLabel2');
    const stepLabel3 = byId('stepLabel3');

    const calendarGrid = byId('calendarGrid');
    const currentMonthYear = byId('currentMonthYear');
    const prevMonthBtn = byId('prevMonth');
    const nextMonthBtn = byId('nextMonth');

    const doctorSelect = byId('doctorSelect');
    const doctorSelectHint = byId('doctorSelectHint');
    const selectedDoctorDisplay = byId('selectedDoctorDisplay');

    const slotsGrid = byId('slotsGrid');
    const selectedDateDisplay = byId('selectedDateDisplay');
    const noSlotsMessage = byId('noSlotsMessage');
    const backToCalendar = byId('backToCalendar');

    const bookingForm = byId('bookingForm');
    const formDate = byId('formDate');
    const formTime = byId('formTime');
    const formDoctorId = byId('formDoctorId');
    const formDoctorSlug = byId('formDoctorSlug');
    const formSummaryDoctor = byId('formSummaryDoctor');
    const formSummaryDate = byId('formSummaryDate');
    const formSummaryTime = byId('formSummaryTime');
    const loadingSpinner = byId('loadingSpinner');
    const backToSlots = byId('backToSlots');
    const gdprConsent = byId('gdprConsent');

    const typeSelector = byId('typeSelector');
    const typeInput = byId('type');
    const diagnosisSection = byId('diagnosisSection');
    const hasDiagnosis = byId('hasDiagnosis');
    const fileUploadContainer = byId('fileUploadContainer');
    const diagnosticFileInput = byId('diagnosticFile');
    const dropZone = byId('dropZone');
    const filePreview = byId('filePreview');
    const fileNameDisplay = byId('fileName');
    const removeFileBtn = byId('removeFile');

    const toast = byId('toast');
    const toastTitle = byId('toastTitle');
    const toastMessage = byId('toastMessage');

    let currentDate = new Date();
    let selectedDate = null;
    let selectedDoctor = null;
    let doctorList = [];

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
        if (!toast || !toastTitle || !toastMessage) return;

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

    function toISODateLocal(date) {
        const y = date.getFullYear();
        const m = String(date.getMonth() + 1).padStart(2, '0');
        const d = String(date.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
    }

    function startOfDay(date) {
        const out = new Date(date);
        out.setHours(0, 0, 0, 0);
        return out;
    }

    function getDoctorMonthLimitDate() {
        const today = startOfDay(new Date());
        const monthsToShow = Number(selectedDoctor?.bookingSettings?.monthsToShow || 1);
        const max = new Date(today);
        max.setMonth(max.getMonth() + monthsToShow);
        return max;
    }

    function isDateWithinDoctorRange(dateObj) {
        if (!selectedDoctor) return false;
        const day = startOfDay(dateObj);
        const minDate = startOfDay(new Date());
        const maxDate = startOfDay(getDoctorMonthLimitDate());
        return day >= minDate && day <= maxDate;
    }

    function getDoctorDayConfigs(doctor) {
        if (!doctor || !doctor.availabilityRules) return [];
        const dayConfigs = Array.isArray(doctor.availabilityRules.dayConfigs)
            ? doctor.availabilityRules.dayConfigs
            : [];
        if (dayConfigs.length > 0) {
            return dayConfigs
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
            startTime: String(doctor.bookingSettings?.workdayStart || ''),
            endTime: String(doctor.bookingSettings?.workdayEnd || ''),
            consultationDurationMinutes: Number(doctor.bookingSettings?.consultationDurationMinutes || 20)
        }));
    }

    function isDoctorWeekdayAvailable(dateObj) {
        if (!selectedDoctor) return false;
        const weekdays = getDoctorDayConfigs(selectedDoctor).map((config) => config.weekday);
        return weekdays.includes(dateObj.getDay());
    }

    function isDoctorDateBlocked(formattedDate) {
        if (!selectedDoctor) return false;
        const blockedDates = Array.isArray(selectedDoctor.blockedDates) ? selectedDoctor.blockedDates : [];
        return blockedDates.includes(formattedDate);
    }

    function updateNavButtons() {
        if (!selectedDoctor) {
            prevMonthBtn.disabled = true;
            nextMonthBtn.disabled = true;
            return;
        }

        const today = startOfDay(new Date());
        const minMonth = new Date(today.getFullYear(), today.getMonth(), 1);
        const maxDate = getDoctorMonthLimitDate();
        const maxMonth = new Date(maxDate.getFullYear(), maxDate.getMonth(), 1);
        const currentMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);

        prevMonthBtn.disabled = currentMonth <= minMonth;
        nextMonthBtn.disabled = currentMonth >= maxMonth;
    }

    function goToStep(step) {
        stepCalendar.classList.add('hidden');
        stepSlots.classList.add('hidden');
        stepForm.classList.add('hidden');

        [stepDot1, stepDot2, stepDot3].forEach((dot) => {
            dot.classList.remove('active', 'completed');
        });
        [stepLine1, stepLine2].forEach((line) => {
            line.classList.remove('active');
        });

        if (stepLabel2) {
            stepLabel2.classList.remove('text-brand-300');
            stepLabel2.classList.add('text-brand-400/50');
        }
        if (stepLabel3) {
            stepLabel3.classList.remove('text-brand-300');
            stepLabel3.classList.add('text-brand-400/50');
        }

        if (step === 1) {
            stepCalendar.classList.remove('hidden');
            stepDot1.classList.add('active');
        } else if (step === 2) {
            stepSlots.classList.remove('hidden');
            stepDot1.classList.add('completed');
            stepDot2.classList.add('active');
            stepLine1.classList.add('active');
            if (stepLabel2) {
                stepLabel2.classList.remove('text-brand-400/50');
                stepLabel2.classList.add('text-brand-300');
            }
        } else if (step === 3) {
            stepForm.classList.remove('hidden');
            stepDot1.classList.add('completed');
            stepDot2.classList.add('completed');
            stepDot3.classList.add('active');
            stepLine1.classList.add('active');
            stepLine2.classList.add('active');
            if (stepLabel2) {
                stepLabel2.classList.remove('text-brand-400/50');
                stepLabel2.classList.add('text-brand-300');
            }
            if (stepLabel3) {
                stepLabel3.classList.remove('text-brand-400/50');
                stepLabel3.classList.add('text-brand-300');
            }
        }

        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function renderCalendar(date) {
        clearNode(calendarGrid);

        const year = date.getFullYear();
        const month = date.getMonth();

        const monthName = new Intl.DateTimeFormat('ro-RO', { month: 'long', year: 'numeric' }).format(date);
        currentMonthYear.textContent = monthName.charAt(0).toUpperCase() + monthName.slice(1);

        const firstDayIndex = new Date(year, month, 1).getDay();
        const lastDay = new Date(year, month + 1, 0).getDate();

        for (let i = 0; i < firstDayIndex; i += 1) {
            const div = document.createElement('div');
            div.className = 'calendar-day empty';
            calendarGrid.appendChild(div);
        }

        const today = startOfDay(new Date());

        for (let day = 1; day <= lastDay; day += 1) {
            const dayDiv = document.createElement('div');
            dayDiv.textContent = day;

            const currentDayDate = new Date(year, month, day);
            const normalizedDate = startOfDay(currentDayDate);
            const formattedDate = toISODateLocal(normalizedDate);

            const isPast = normalizedDate < today;
            const isRangeOk = isDateWithinDoctorRange(normalizedDate);
            const isWeekdayOk = isDoctorWeekdayAvailable(normalizedDate);
            const isBlocked = isDoctorDateBlocked(formattedDate);
            const isEnabled = selectedDoctor && !isPast && isRangeOk && isWeekdayOk && !isBlocked;

            dayDiv.className = 'calendar-day';

            if (isEnabled) {
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

        updateNavButtons();
    }

    function updateDoctorUI() {
        const doctorName = selectedDoctor?.displayName || '';
        if (selectedDoctorDisplay) {
            selectedDoctorDisplay.textContent = doctorName;
        }
        if (formSummaryDoctor) {
            formSummaryDoctor.textContent = doctorName;
        }

        if (!doctorSelectHint) return;
        if (!selectedDoctor) {
            doctorSelectHint.textContent = 'Selecteaza un medic pentru a vedea disponibilitatea.';
            return;
        }

        const settings = selectedDoctor.bookingSettings || {};
        const dayConfigs = getDoctorDayConfigs(selectedDoctor);
        const summary = dayConfigs.length
            ? dayConfigs
                .map((config) => `${['Du', 'Lu', 'Ma', 'Mi', 'Jo', 'Vi', 'Sa'][config.weekday]} ${config.startTime}-${config.endTime}/${config.consultationDurationMinutes}m`)
                .join('; ')
            : 'nedefinit';

        doctorSelectHint.textContent = `Program pe zile: ${summary}; luni vizibile ${settings.monthsToShow || '-'}; fus orar ${settings.timezone || 'Europe/Bucharest'}`;
    }

    function resetAfterDoctorChange() {
        selectedDate = null;
        formDate.value = '';
        formTime.value = '';
        formDoctorId.value = selectedDoctor?._id || '';
        formDoctorSlug.value = selectedDoctor?.slug || '';
        selectedDateDisplay.textContent = '';
        formSummaryDate.textContent = '';
        formSummaryTime.textContent = '';
        clearNode(slotsGrid);
        noSlotsMessage.classList.add('hidden');
    }

    function selectDate(dateValue, element) {
        if (!selectedDoctor) {
            showToast('Atentie', 'Selecteaza mai intai un medic.', 'error');
            return;
        }

        selectedDate = dateValue;
        const dateObj = new Date(`${dateValue}T00:00:00`);
        selectedDateDisplay.textContent = new Intl.DateTimeFormat('ro-RO', {
            day: 'numeric',
            month: 'long',
            year: 'numeric'
        }).format(dateObj);

        document.querySelectorAll('.calendar-day').forEach((dayNode) => dayNode.classList.remove('selected'));
        element.classList.add('selected');

        fetchSlots(dateValue);
        goToStep(2);
    }

    async function fetchDoctors() {
        if (!doctorSelect) return;

        doctorSelect.disabled = true;
        try {
            const res = await fetch('/api/public/doctors', { method: 'GET' });
            const payload = await res.json().catch(() => ({}));

            if (!res.ok) {
                throw new Error(payload.error || 'Nu s-a putut incarca lista medicilor.');
            }

            const doctors = Array.isArray(payload.doctors) ? payload.doctors : [];
            doctorList = doctors;

            clearNode(doctorSelect);
            const emptyOpt = document.createElement('option');
            emptyOpt.value = '';
            emptyOpt.textContent = doctors.length ? 'Selecteaza un medic...' : 'Nu exista medici activi';
            doctorSelect.appendChild(emptyOpt);

            doctors.forEach((doctor) => {
                const option = document.createElement('option');
                option.value = doctor._id;
                option.textContent = `${doctor.displayName} (${doctor.specialty || 'Specialitate'})`;
                doctorSelect.appendChild(option);
            });

            doctorSelect.disabled = doctors.length === 0;
            updateDoctorUI();
        } catch (error) {
            doctorSelect.disabled = true;
            doctorSelectHint.textContent = String(error?.message || 'Eroare la incarcarea medicilor.');
            showToast('Eroare', 'Nu s-a putut incarca lista medicilor activi.', 'error');
        }
    }

    async function fetchSlots(dateValue) {
        if (!selectedDoctor) {
            setSingleMessage(slotsGrid, 'Selecteaza un medic.', 'col-span-full text-center py-8 text-gray-400 font-medium');
            return;
        }

        setSingleMessage(slotsGrid, 'Se incarca intervalele...', 'col-span-full text-center py-8 text-gray-400 font-medium');
        noSlotsMessage.classList.add('hidden');

        try {
            const query = new URLSearchParams({
                doctor: selectedDoctor.slug,
                date: dateValue
            });
            const res = await fetch(`/api/slots?${query.toString()}`);
            const payload = await res.json().catch(() => ({}));

            if (!res.ok) {
                setSingleMessage(slotsGrid, String(payload?.error || 'Eroare.'), 'col-span-full text-center text-red-500');
                return;
            }

            const slots = Array.isArray(payload?.slots) ? payload.slots : [];
            renderSlots(slots, dateValue);
        } catch (error) {
            console.error(error);
            setSingleMessage(slotsGrid, 'Eroare de conexiune.', 'col-span-full text-center text-red-500');
        }
    }

    function renderSlots(slots, dateValue) {
        clearNode(slotsGrid);
        const availableSlots = slots.filter((slot) => slot.available);

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
                    formDate.value = dateValue;
                    formTime.value = slot.time;
                    formDoctorId.value = selectedDoctor?._id || '';
                    formDoctorSlug.value = selectedDoctor?.slug || '';

                    const dateObj = new Date(`${dateValue}T00:00:00`);
                    formSummaryDate.textContent = new Intl.DateTimeFormat('ro-RO', {
                        day: 'numeric',
                        month: 'long',
                        year: 'numeric'
                    }).format(dateObj);
                    formSummaryTime.textContent = slot.time;
                    formSummaryDoctor.textContent = selectedDoctor?.displayName || '';

                    goToStep(3);
                };
            }

            slotsGrid.appendChild(btn);
        });
    }

    doctorSelect.addEventListener('change', (event) => {
        const doctorId = String(event.target.value || '');
        selectedDoctor = doctorList.find((doctor) => String(doctor._id) === doctorId) || null;

        resetAfterDoctorChange();
        updateDoctorUI();
        renderCalendar(currentDate);
        goToStep(1);
    });

    prevMonthBtn.onclick = () => {
        if (!selectedDoctor) {
            showToast('Atentie', 'Selecteaza un medic inainte sa navighezi in calendar.', 'error');
            return;
        }

        const testDate = new Date(currentDate);
        testDate.setMonth(testDate.getMonth() - 1);

        const today = startOfDay(new Date());
        const minMonth = new Date(today.getFullYear(), today.getMonth(), 1);
        const testMonth = new Date(testDate.getFullYear(), testDate.getMonth(), 1);

        if (testMonth >= minMonth) {
            currentDate = testDate;
            renderCalendar(currentDate);
        }
    };

    nextMonthBtn.onclick = () => {
        if (!selectedDoctor) {
            showToast('Atentie', 'Selecteaza un medic inainte sa navighezi in calendar.', 'error');
            return;
        }

        const testDate = new Date(currentDate);
        testDate.setMonth(testDate.getMonth() + 1);

        const maxDate = getDoctorMonthLimitDate();
        const maxMonth = new Date(maxDate.getFullYear(), maxDate.getMonth(), 1);
        const testMonth = new Date(testDate.getFullYear(), testDate.getMonth(), 1);

        if (testMonth <= maxMonth) {
            currentDate = testDate;
            renderCalendar(currentDate);
        }
    };

    backToCalendar.onclick = () => {
        selectedDate = null;
        goToStep(1);
    };

    backToSlots.onclick = () => {
        goToStep(2);
    };

    typeSelector.addEventListener('click', (event) => {
        const btn = event.target.closest('.type-btn');
        if (!btn) return;

        typeSelector.querySelectorAll('.type-btn').forEach((node) => node.classList.remove('selected'));
        btn.classList.add('selected');
        typeInput.value = btn.dataset.value;

        if (btn.dataset.value === 'Prima Consultatie' || btn.dataset.value === 'Prima Consultație') {
            diagnosisSection.classList.remove('hidden');
            return;
        }

        diagnosisSection.classList.add('hidden');
        hasDiagnosis.checked = false;
        fileUploadContainer.classList.add('hidden');
        diagnosticFileInput.value = '';
        filePreview.classList.add('hidden');
        dropZone.classList.remove('hidden');
    });

    hasDiagnosis.addEventListener('change', () => {
        if (hasDiagnosis.checked) {
            fileUploadContainer.classList.remove('hidden');
            return;
        }

        fileUploadContainer.classList.add('hidden');
        diagnosticFileInput.value = '';
        filePreview.classList.add('hidden');
        dropZone.classList.remove('hidden');
    });

    function handleFileSelection(file) {
        if (!file) return;

        const maxSize = 5 * 1024 * 1024;
        if (file.size > maxSize) {
            showToast('Eroare', 'Fisierul este prea mare (max 5MB).', 'error');
            return;
        }

        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(file);
        diagnosticFileInput.files = dataTransfer.files;

        fileNameDisplay.textContent = file.name;
        filePreview.classList.remove('hidden');
        dropZone.classList.add('hidden');
    }

    dropZone.addEventListener('click', () => diagnosticFileInput.click());

    dropZone.addEventListener('dragover', (event) => {
        event.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (event) => {
        event.preventDefault();
        dropZone.classList.remove('drag-over');
        if (event.dataTransfer.files.length > 0) {
            handleFileSelection(event.dataTransfer.files[0]);
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

    bookingForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        if (!selectedDoctor) {
            showToast('Atentie', 'Selecteaza un medic.', 'error');
            goToStep(1);
            return;
        }

        if (!gdprConsent.checked) {
            showToast('Atentie', 'Trebuie sa acceptati prelucrarea datelor personale (GDPR).', 'error');
            return;
        }

        const firstName = byId('firstName').value.trim();
        const lastName = byId('lastName').value.trim();
        const name = `${lastName} ${firstName}`.trim();
        const phone = byId('phone').value.trim();
        const email = byId('email').value.trim();
        const type = typeInput.value;
        const dateValue = formDate.value;
        const timeValue = formTime.value;

        if (!dateValue || !timeValue) {
            showToast('Eroare', 'Selecteaza data si ora programarii.', 'error');
            return;
        }

        if (hasDiagnosis.checked && diagnosticFileInput.files[0]) {
            showToast('Info', 'Incarcarea documentelor este temporar indisponibila online. Va rugam aduceti documentele la consultatie.', 'error');
            return;
        }

        if (phone.length < 10) {
            showToast('Eroare', 'Numarul de telefon pare invalid.', 'error');
            return;
        }

        const submitBtn = byId('submitBtn');
        submitBtn.disabled = true;
        loadingSpinner.classList.remove('hidden');

        try {
            const res = await AUTH.apiFetch('/api/book', {
                method: 'POST',
                body: JSON.stringify({
                    name,
                    phone,
                    email,
                    type,
                    date: dateValue,
                    time: timeValue,
                    hasDiagnosis: hasDiagnosis.checked,
                    doctorId: selectedDoctor._id,
                    doctorSlug: selectedDoctor.slug
                })
            });

            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showToast('Eroare', data.error || 'A aparut o eroare.', 'error');
                return;
            }

            showToast('Succes!', 'Confirmarea si invitatia pentru calendar au fost trimise pe adresa dumneavoastra de e-mail.');
            bookingForm.reset();
            typeSelector.querySelectorAll('.type-btn').forEach((node) => node.classList.remove('selected'));
            typeSelector.querySelector('[data-value="Control"]').classList.add('selected');
            typeInput.value = 'Control';
            diagnosisSection.classList.add('hidden');
            fileUploadContainer.classList.add('hidden');
            filePreview.classList.add('hidden');
            dropZone.classList.remove('hidden');

            selectedDate = null;
            formDate.value = '';
            formTime.value = '';
            renderCalendar(currentDate);
            goToStep(1);
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune server.', 'error');
        } finally {
            submitBtn.disabled = false;
            loadingSpinner.classList.add('hidden');
        }
    });

    renderCalendar(currentDate);
    updateDoctorUI();
    fetchDoctors();
});
