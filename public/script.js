document.addEventListener('DOMContentLoaded', () => {
    const stepCalendar = document.getElementById('step-calendar');
    const stepSlots = document.getElementById('step-slots');
    const stepForm = document.getElementById('step-form');

    const requiredNodes = [stepCalendar, stepSlots, stepForm];
    if (requiredNodes.some((node) => !node)) {
        return;
    }

    const stepDot1 = document.getElementById('stepDot1');
    const stepDot2 = document.getElementById('stepDot2');
    const stepDot3 = document.getElementById('stepDot3');
    const stepLine1 = document.getElementById('stepLine1');
    const stepLine2 = document.getElementById('stepLine2');
    const stepLabel2 = document.getElementById('stepLabel2');
    const stepLabel3 = document.getElementById('stepLabel3');

    const calendarGrid = document.getElementById('calendarGrid');
    const currentMonthYear = document.getElementById('currentMonthYear');
    const prevMonthBtn = document.getElementById('prevMonth');
    const nextMonthBtn = document.getElementById('nextMonth');

    const slotsGrid = document.getElementById('slotsGrid');
    const selectedDateDisplay = document.getElementById('selectedDateDisplay');
    const noSlotsMessage = document.getElementById('noSlotsMessage');
    const backToCalendar = document.getElementById('backToCalendar');

    const bookingForm = document.getElementById('bookingForm');
    const formDate = document.getElementById('formDate');
    const formTime = document.getElementById('formTime');
    const formSummaryDate = document.getElementById('formSummaryDate');
    const formSummaryTime = document.getElementById('formSummaryTime');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const backToSlots = document.getElementById('backToSlots');
    const gdprConsent = document.getElementById('gdprConsent');

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

    const toast = document.getElementById('toast');
    const toastTitle = document.getElementById('toastTitle');
    const toastMessage = document.getElementById('toastMessage');

    let currentDate = new Date();
    let selectedDate = null;

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
            stepLabel2.classList.remove('text-medical-600');
            stepLabel2.classList.add('text-gray-400');
        }
        if (stepLabel3) {
            stepLabel3.classList.remove('text-medical-600');
            stepLabel3.classList.add('text-gray-400');
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

        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    backToCalendar.onclick = () => {
        selectedDate = null;
        goToStep(1);
    };

    backToSlots.onclick = () => {
        goToStep(2);
    };

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

        for (let day = 1; day <= lastDay; day += 1) {
            const dayDiv = document.createElement('div');
            dayDiv.textContent = day;

            const currentDayDate = new Date(year, month, day);
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
        selectedDateDisplay.textContent = new Intl.DateTimeFormat('ro-RO', {
            day: 'numeric',
            month: 'long',
            year: 'numeric'
        }).format(dateObj);

        document.querySelectorAll('.calendar-day').forEach((dayNode) => dayNode.classList.remove('selected'));
        element.classList.add('selected');

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

    async function fetchSlots(date) {
        setSingleMessage(slotsGrid, 'Se incarca intervalele...', 'col-span-full text-center py-8 text-gray-400 font-medium');
        noSlotsMessage.classList.add('hidden');

        try {
            const res = await fetch(`/api/slots?date=${date}`);
            const slots = await res.json();

            if (res.status !== 200) {
                setSingleMessage(slotsGrid, String(slots?.error || 'Eroare.'), 'col-span-full text-center text-red-500');
                return;
            }

            renderSlots(slots, date);
        } catch (error) {
            console.error(error);
            setSingleMessage(slotsGrid, 'Eroare de conexiune.', 'col-span-full text-center text-red-500');
        }
    }

    function renderSlots(slots, date) {
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
                    formDate.value = date;
                    formTime.value = slot.time;

                    const dateObj = new Date(date);
                    formSummaryDate.textContent = new Intl.DateTimeFormat('ro-RO', {
                        day: 'numeric',
                        month: 'long',
                        year: 'numeric'
                    }).format(dateObj);
                    formSummaryTime.textContent = slot.time;

                    goToStep(3);
                };
            }

            slotsGrid.appendChild(btn);
        });
    }

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

        if (!gdprConsent.checked) {
            showToast('Atentie', 'Trebuie sa acceptati prelucrarea datelor personale (GDPR).', 'error');
            return;
        }

        const firstName = document.getElementById('firstName').value;
        const lastName = document.getElementById('lastName').value;
        const name = `${lastName} ${firstName}`;
        const phone = document.getElementById('phone').value;
        const email = document.getElementById('email').value;
        const type = typeInput.value;
        const date = formDate.value;
        const time = formTime.value;

        if (hasDiagnosis.checked && diagnosticFileInput.files[0]) {
            showToast('Info', 'Incarcarea documentelor este temporar indisponibila online. Va rugam aduceti documentele la consultatie.', 'error');
            return;
        }

        if (phone.length < 10) {
            showToast('Eroare', 'Numarul de telefon pare invalid.', 'error');
            return;
        }

        const submitBtn = document.getElementById('submitBtn');
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
                    date,
                    time,
                    hasDiagnosis: hasDiagnosis.checked
                })
            });

            const data = await res.json();
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
            goToStep(1);
            renderCalendar(currentDate);
        } catch (_) {
            showToast('Eroare', 'Eroare de conexiune server.', 'error');
        } finally {
            submitBtn.disabled = false;
            loadingSpinner.classList.add('hidden');
        }
    });

    renderCalendar(currentDate);
});
