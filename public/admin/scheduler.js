(function initAdminScheduler(windowObj, documentObj) {
    'use strict';

    const DEFAULT_CONFIG = Object.freeze({
        startHour: '08:00',
        endHour: '14:00',
        pxPerMinute: 2.5,
        minBlockHeight: 28,
        allDoctorsColumnWidth: 220,
        singleDoctorColumnWidth: 340
    });

    const LEGEND_STATUS_ITEMS = Object.freeze([
        { key: 'sent', label: 'Trimis' },
        { key: 'confirmed', label: 'Confirmat' },
        { key: 'pending', label: 'In asteptare' },
        { key: 'unsent', label: 'Netrimis' },
        { key: 'cancelled', label: 'Anulat' }
    ]);

    let schedulerInstanceCount = 0;

    function parseHourToMinutes(value, fallback) {
        const match = String(value || '').trim().match(/^([01]\d|2[0-3]):([0-5]\d)$/);
        if (!match) return fallback;
        return (Number(match[1]) * 60) + Number(match[2]);
    }

    function toMinuteLabel(totalMinutes) {
        const safeMinutes = Math.max(0, Number(totalMinutes) || 0);
        const hours = Math.floor(safeMinutes / 60);
        const minutes = safeMinutes % 60;
        return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
    }

    function clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }

    function normalizeStatus(rawStatus) {
        const status = String(rawStatus || '').trim().toLowerCase();
        if (status === 'sent' || status === 'trimis') {
            return { key: 'sent', label: 'Trimis' };
        }
        if (status === 'confirmed' || status === 'confirmat') {
            return { key: 'confirmed', label: 'Confirmat' };
        }
        if (status === 'cancelled' || status === 'anulat') {
            return { key: 'cancelled', label: 'Anulat' };
        }
        if (status === 'unsent' || status === 'netrimis') {
            return { key: 'unsent', label: 'Netrimis' };
        }
        return { key: 'pending', label: 'In asteptare' };
    }

    function getTypeShortLabel(typeRaw) {
        const type = String(typeRaw || '').trim();
        const normalized = type.toLowerCase();
        if (!type) return '-';
        if (normalized.includes('prima')) return 'Prima';
        if (normalized.includes('control')) return 'Ctrl';
        if (type.length <= 10) return type;
        return `${type.slice(0, 10)}.`;
    }

    function getAppointmentPatientRawName(appointment) {
        return String(appointment?.patientName || appointment?.name || '').trim();
    }

    function maskPatientName(rawName) {
        const letterOrDigitPattern = /[A-Za-z0-9ĂÂÎȘȚăâîșț]/;
        const sanitizePattern = /[^A-Za-z0-9ĂÂÎȘȚăâîșț]/g;
        const normalized = String(rawName || '').trim();
        const parts = normalized.split(/\s+/).filter(Boolean);
        if (!parts.length) return 'Pacient';

        if (parts.length === 1) {
            const singleValue = parts[0];
            if (singleValue.includes('@')) {
                const localPart = singleValue.split('@')[0] || '';
                const initials = localPart
                    .replace(sanitizePattern, '')
                    .slice(0, 2)
                    .toUpperCase();
                return initials ? `${initials}.` : 'Pacient';
            }

            const hasLetterOrDigit = letterOrDigitPattern.test(singleValue);
            if (!hasLetterOrDigit) return 'Pacient';
            if (singleValue.length > 24) {
                const first = singleValue.replace(sanitizePattern, '').charAt(0).toUpperCase();
                return first ? `${first}.` : 'Pacient';
            }
            return singleValue;
        }

        const surname = parts[parts.length - 1];
        const firstInitial = String(parts[0] || '').charAt(0).toUpperCase();
        const hasSurnameText = letterOrDigitPattern.test(surname);
        if (!firstInitial || !hasSurnameText) return 'Pacient';
        return `${surname} ${firstInitial}.`;
    }

    function createNode(tag, className = '', text = '') {
        const node = documentObj.createElement(tag);
        if (className) node.className = className;
        if (text) node.textContent = text;
        return node;
    }

    function debounce(fn, waitMs = 120) {
        let timeoutId = 0;
        const debounced = (...args) => {
            if (timeoutId) {
                windowObj.clearTimeout(timeoutId);
            }
            timeoutId = windowObj.setTimeout(() => {
                timeoutId = 0;
                fn(...args);
            }, waitMs);
        };
        debounced.cancel = () => {
            if (!timeoutId) return;
            windowObj.clearTimeout(timeoutId);
            timeoutId = 0;
        };
        return debounced;
    }

    function normalizeDoctorEntry(rawDoctor) {
        const id = String(rawDoctor?._id || rawDoctor?.id || '').trim();
        if (!id) return null;
        return {
            _id: id,
            displayName: String(rawDoctor?.displayName || rawDoctor?.doctorName || 'Medic').trim() || 'Medic',
            cabinet: String(rawDoctor?.cabinet || rawDoctor?.doctorCabinet || '').trim()
        };
    }

    function normalizeDoctorsForView({ doctors = [], appointments = [], selectedDoctorId = '' } = {}) {
        const result = [];
        const seen = new Set();
        const selected = String(selectedDoctorId || '').trim();

        const addDoctor = (rawDoctor) => {
            const normalized = normalizeDoctorEntry(rawDoctor);
            if (!normalized || seen.has(normalized._id)) return;
            seen.add(normalized._id);
            result.push(normalized);
        };

        const appointmentsDoctorMap = new Map();
        for (const appointment of appointments) {
            const doctorId = String(appointment?.doctorId || '').trim();
            if (!doctorId || appointmentsDoctorMap.has(doctorId)) continue;
            appointmentsDoctorMap.set(doctorId, {
                _id: doctorId,
                displayName: String(appointment?.doctorName || '').trim() || 'Medic'
            });
        }

        if (selected) {
            const selectedDoctor = doctors.find((doctor) => String(doctor?._id || '') === selected);
            if (selectedDoctor) {
                addDoctor(selectedDoctor);
            } else if (appointmentsDoctorMap.has(selected)) {
                addDoctor(appointmentsDoctorMap.get(selected));
            } else {
                addDoctor({ _id: selected, displayName: 'Medic selectat' });
            }
            return result;
        }

        const rawDoctors = Array.isArray(doctors) ? doctors : [];
        const activeDoctors = rawDoctors.filter((doctor) => doctor && doctor.isActive !== false);
        const sourceDoctors = activeDoctors.length ? activeDoctors : rawDoctors;

        sourceDoctors.forEach(addDoctor);
        appointmentsDoctorMap.forEach((doctor) => addDoctor(doctor));

        return result.sort((a, b) => a.displayName.localeCompare(b.displayName, 'ro-RO'));
    }

    function resolveStartMinutes(appointment) {
        const explicitMinutes = Number(appointment?.startMinutes);
        if (Number.isFinite(explicitMinutes)) {
            return explicitMinutes;
        }

        const startIso = String(appointment?.startISO || '').trim();
        if (startIso) {
            const parsedDate = new Date(startIso);
            if (!Number.isNaN(parsedDate.getTime())) {
                return (parsedDate.getHours() * 60) + parsedDate.getMinutes();
            }
        }
        return NaN;
    }

    function resolveDurationMinutes(appointment, fallbackDuration) {
        const explicitDuration = Number(appointment?.durationMinutes);
        if (Number.isInteger(explicitDuration) && explicitDuration > 0) {
            return explicitDuration;
        }
        const startIso = String(appointment?.startISO || '').trim();
        const endIso = String(appointment?.endISO || '').trim();
        if (startIso && endIso) {
            const parsedStart = new Date(startIso);
            const parsedEnd = new Date(endIso);
            const diffMs = parsedEnd.getTime() - parsedStart.getTime();
            if (!Number.isNaN(diffMs) && diffMs > 0) {
                const diffMinutes = Math.round(diffMs / 60000);
                if (diffMinutes > 0) return diffMinutes;
            }
        }
        return fallbackDuration;
    }

    function groupAppointmentsByDoctor(appointments, doctors, selectedDoctorId = '') {
        const grouped = new Map();
        doctors.forEach((doctor) => grouped.set(String(doctor._id), []));

        const singleDoctorId = String(selectedDoctorId || '').trim();
        for (const appointment of appointments) {
            let doctorId = String(appointment?.doctorId || '').trim();
            if (singleDoctorId && doctorId !== singleDoctorId) {
                continue;
            }
            if (!grouped.has(doctorId)) {
                if (singleDoctorId) {
                    doctorId = singleDoctorId;
                } else if (doctors.length === 1) {
                    doctorId = String(doctors[0]._id);
                } else {
                    continue;
                }
            }
            grouped.get(doctorId).push(appointment);
        }

        grouped.forEach((items) => {
            items.sort((a, b) => resolveStartMinutes(a) - resolveStartMinutes(b));
        });

        return grouped;
    }

    function buildDoctorOverlapLayout(
        appointments,
        {
            timelineStartMinutes,
            timelineEndMinutes,
            fallbackDurationMinutes = 20
        } = {}
    ) {
        const normalized = [];
        const startBound = Number(timelineStartMinutes);
        const endBound = Number(timelineEndMinutes);
        if (!Number.isFinite(startBound) || !Number.isFinite(endBound) || endBound <= startBound) {
            return normalized;
        }

        for (const appointment of appointments) {
            const rawStart = resolveStartMinutes(appointment);
            if (!Number.isFinite(rawStart)) continue;

            const durationMinutes = resolveDurationMinutes(appointment, fallbackDurationMinutes);
            const boundedStart = clamp(rawStart, startBound, endBound);
            const boundedEnd = clamp(rawStart + durationMinutes, startBound, endBound);
            if (boundedEnd <= boundedStart) continue;

            normalized.push({
                appointment,
                startMinutes: boundedStart,
                endMinutes: boundedEnd
            });
        }

        normalized.sort((a, b) => {
            if (a.startMinutes === b.startMinutes) {
                return a.endMinutes - b.endMinutes;
            }
            return a.startMinutes - b.startMinutes;
        });

        const groups = [];
        let currentGroup = [];
        let currentGroupEnd = -Infinity;

        for (const item of normalized) {
            if (!currentGroup.length || item.startMinutes < currentGroupEnd) {
                currentGroup.push(item);
                currentGroupEnd = Math.max(currentGroupEnd, item.endMinutes);
                continue;
            }

            groups.push(currentGroup);
            currentGroup = [item];
            currentGroupEnd = item.endMinutes;
        }
        if (currentGroup.length) {
            groups.push(currentGroup);
        }

        const positioned = [];
        for (const group of groups) {
            const laneEndByIndex = [];
            for (const item of group) {
                let laneIndex = -1;
                for (let index = 0; index < laneEndByIndex.length; index += 1) {
                    if (item.startMinutes >= laneEndByIndex[index]) {
                        laneIndex = index;
                        break;
                    }
                }
                if (laneIndex === -1) {
                    laneIndex = laneEndByIndex.length;
                    laneEndByIndex.push(item.endMinutes);
                } else {
                    laneEndByIndex[laneIndex] = item.endMinutes;
                }
                item.laneIndex = laneIndex;
            }

            const laneCount = Math.max(1, laneEndByIndex.length);
            for (const item of group) {
                positioned.push({
                    appointment: item.appointment,
                    startMinutes: item.startMinutes,
                    endMinutes: item.endMinutes,
                    laneIndex: Number(item.laneIndex) || 0,
                    laneCount
                });
            }
        }

        return positioned;
    }

    function applyOverlapHorizontalPosition(
        block,
        {
            laneIndex = 0,
            laneCount = 1,
            singleDoctorMode = false
        } = {}
    ) {
        const safeLaneCount = Math.max(1, Number(laneCount) || 1);
        const safeLaneIndex = clamp(Number(laneIndex) || 0, 0, safeLaneCount - 1);
        const laneWidthPercent = 100 / safeLaneCount;
        const leftPercent = safeLaneIndex * laneWidthPercent;

        const baseInsetPx = singleDoctorMode ? 10 : 7;
        const overlapInsetPx = safeLaneCount > 1 ? 4 : baseInsetPx;

        block.style.left = `calc(${leftPercent}% + ${overlapInsetPx}px)`;
        block.style.width = `calc(${laneWidthPercent}% - ${overlapInsetPx * 2}px)`;
        block.style.right = 'auto';
    }

    function buildBlockAriaLabel(appointment, startMinutes, endMinutes, statusInfo) {
        const patientMask = maskPatientName(getAppointmentPatientRawName(appointment));
        const timeRange = `${toMinuteLabel(startMinutes)} - ${toMinuteLabel(endMinutes)}`;
        const typeLabel = getTypeShortLabel(appointment?.type);
        const statusLabel = statusInfo?.label || 'In asteptare';
        return `Programare ${patientMask}, ${timeRange}, ${typeLabel}, ${statusLabel}. Apasa Enter pentru detalii.`;
    }

    function createScheduler({ mount, config = {} } = {}) {
        if (!mount) {
            return {
                render() {
                    // no-op
                },
                destroy() {
                    // no-op
                }
            };
        }

        const mergedConfig = { ...DEFAULT_CONFIG, ...config };
        const onAppointmentClick = typeof mergedConfig.onAppointmentClick === 'function'
            ? mergedConfig.onAppointmentClick
            : null;
        const schedulerInstanceId = `admin-scheduler-legend-${++schedulerInstanceCount}`;
        let legendExpanded = null;
        let renderHandle = 0;
        let isDestroyed = false;
        let lastMountWidth = mount.clientWidth;
        let latestState = {
            appointments: [],
            doctors: [],
            selectedDoctorId: '',
            isLoading: false,
            errorMessage: ''
        };

        const performRender = () => {
            if (isDestroyed) return;
            mount.innerHTML = '';

            const root = createNode('div', 'admin-scheduler-root');
            mount.appendChild(root);

            if (latestState.isLoading) {
                const loading = createNode('div', 'admin-scheduler-state is-loading');
                loading.setAttribute('role', 'status');
                loading.textContent = 'Se incarca programarile...';
                root.appendChild(loading);
                return;
            }

            if (latestState.errorMessage) {
                const error = createNode('div', 'admin-scheduler-state is-error');
                error.setAttribute('role', 'alert');
                error.textContent = latestState.errorMessage;
                root.appendChild(error);
                return;
            }

            const timelineStartMinutes = parseHourToMinutes(mergedConfig.startHour, 8 * 60);
            const timelineEndMinutes = parseHourToMinutes(mergedConfig.endHour, 14 * 60);
            const pxPerMinute = Number(mergedConfig.pxPerMinute) > 0 ? Number(mergedConfig.pxPerMinute) : 2.5;
            const minBlockHeight = Number(mergedConfig.minBlockHeight) > 0 ? Number(mergedConfig.minBlockHeight) : 28;

            if (timelineEndMinutes <= timelineStartMinutes) {
                const invalidConfig = createNode('div', 'admin-empty-state', 'Configuratia scheduler-ului este invalida.');
                root.appendChild(invalidConfig);
                return;
            }

            const timelineMinutes = timelineEndMinutes - timelineStartMinutes;
            const timelineHeight = Math.max(360, timelineMinutes * pxPerMinute);
            const singleDoctorMode = !!latestState.selectedDoctorId;
            const readableBlockHeight = singleDoctorMode ? 58 : 54;
            const doctorsForView = normalizeDoctorsForView({
                doctors: latestState.doctors,
                appointments: latestState.appointments,
                selectedDoctorId: latestState.selectedDoctorId
            });

            if (!doctorsForView.length) {
                const empty = createNode('div', 'admin-empty-state', 'Nu exista medici disponibili pentru contextul curent.');
                root.appendChild(empty);
                return;
            }

            const isMobileViewport = Boolean(
                typeof windowObj.matchMedia === 'function'
                && windowObj.matchMedia('(max-width: 640px)').matches
            );
            if (legendExpanded === null) {
                legendExpanded = !isMobileViewport;
            }
            if (!isMobileViewport) {
                legendExpanded = true;
            }

            const toolbar = createNode('div', 'admin-scheduler-toolbar');
            const toolbarInfo = createNode(
                'div',
                'admin-scheduler-toolbar-info',
                `${toMinuteLabel(timelineStartMinutes)} - ${toMinuteLabel(timelineEndMinutes)}`
            );
            toolbar.appendChild(toolbarInfo);

            const legend = createNode(
                'div',
                `admin-scheduler-legend${legendExpanded ? '' : ' is-collapsed'}`
            );
            const legendToggle = createNode('button', 'admin-scheduler-legend-toggle', 'Legenda status');
            legendToggle.type = 'button';
            legendToggle.setAttribute('aria-controls', schedulerInstanceId);
            legendToggle.setAttribute('aria-expanded', legendExpanded ? 'true' : 'false');
            legendToggle.setAttribute('aria-label', 'Arata sau ascunde legenda de status');
            legendToggle.addEventListener('click', () => {
                legendExpanded = !legendExpanded;
                queueRender();
            });
            legend.appendChild(legendToggle);

            const legendList = createNode('ul', 'admin-scheduler-legend-list');
            legendList.id = schedulerInstanceId;
            legendList.hidden = !legendExpanded;
            LEGEND_STATUS_ITEMS.forEach((item) => {
                const legendItem = createNode('li', 'admin-scheduler-legend-item');
                const dot = createNode('span', `admin-scheduler-legend-dot status-${item.key}`);
                dot.setAttribute('aria-hidden', 'true');
                const label = createNode('span', '', item.label);
                legendItem.appendChild(dot);
                legendItem.appendChild(label);
                legendList.appendChild(legendItem);
            });
            legend.appendChild(legendList);
            toolbar.appendChild(legend);

            root.appendChild(toolbar);

            if (!latestState.appointments.length) {
                const emptyBanner = createNode(
                    'div',
                    'admin-scheduler-empty-banner',
                    'Nu exista programari pentru data si filtrele curente.'
                );
                root.appendChild(emptyBanner);
            }

            const scroll = createNode('div', 'admin-scheduler-scroll custom-scrollbar');
            const grid = createNode(
                'div',
                `admin-scheduler-grid${singleDoctorMode ? ' is-single' : ''}`
            );

            const doctorColumnWidth = singleDoctorMode
                ? mergedConfig.singleDoctorColumnWidth
                : mergedConfig.allDoctorsColumnWidth;

            grid.style.setProperty('--scheduler-doctor-count', String(Math.max(doctorsForView.length, 1)));
            grid.style.setProperty('--scheduler-column-width', `${doctorColumnWidth}px`);
            grid.style.setProperty('--scheduler-content-height', `${timelineHeight}px`);
            grid.style.setProperty('--scheduler-hour-height', `${60 * pxPerMinute}px`);

            const corner = createNode('div', 'admin-scheduler-corner', 'Ora');
            corner.style.gridColumnStart = '1';
            corner.style.gridRowStart = '1';
            grid.appendChild(corner);

            doctorsForView.forEach((doctor, index) => {
                const header = createNode('div', 'admin-scheduler-doctor-header');
                header.style.gridColumnStart = String(index + 2);
                header.style.gridRowStart = '1';

                const name = createNode('div', 'admin-scheduler-doctor-name', doctor.displayName);
                header.appendChild(name);

                if (doctor.cabinet) {
                    const cabinet = createNode('div', 'admin-scheduler-doctor-cabinet', doctor.cabinet);
                    header.appendChild(cabinet);
                }

                grid.appendChild(header);
            });

            const axis = createNode('div', 'admin-scheduler-time-axis');
            axis.style.gridColumnStart = '1';
            axis.style.gridRowStart = '2';
            const axisInner = createNode('div', 'admin-scheduler-time-axis-inner');
            axisInner.style.height = `${timelineHeight}px`;

            for (let minute = timelineStartMinutes; minute <= timelineEndMinutes; minute += 60) {
                const top = (minute - timelineStartMinutes) * pxPerMinute;
                const mark = createNode('div', 'admin-scheduler-time-mark');
                mark.style.top = `${top}px`;
                axisInner.appendChild(mark);

                const label = createNode('div', 'admin-scheduler-time-label', toMinuteLabel(minute));
                label.style.top = `${top}px`;
                axisInner.appendChild(label);
            }

            axis.appendChild(axisInner);
            grid.appendChild(axis);

            const grouped = groupAppointmentsByDoctor(
                latestState.appointments,
                doctorsForView,
                latestState.selectedDoctorId
            );

            doctorsForView.forEach((doctor, index) => {
                const lane = createNode('div', 'admin-scheduler-lane');
                lane.style.gridColumnStart = String(index + 2);
                lane.style.gridRowStart = '2';
                lane.style.height = `${timelineHeight}px`;

                const laneAppointments = grouped.get(String(doctor._id)) || [];
                const positionedAppointments = buildDoctorOverlapLayout(laneAppointments, {
                    timelineStartMinutes,
                    timelineEndMinutes,
                    fallbackDurationMinutes: 20
                });

                positionedAppointments.forEach((entry) => {
                    const appointment = entry.appointment;
                    const blockStart = entry.startMinutes;
                    const blockEnd = entry.endMinutes;

                    const top = (blockStart - timelineStartMinutes) * pxPerMinute;
                    const height = Math.max(
                        (blockEnd - blockStart) * pxPerMinute,
                        minBlockHeight,
                        readableBlockHeight
                    );

                    const block = createNode('article', 'admin-scheduler-block');
                    block.style.top = `${top}px`;
                    block.style.height = `${height}px`;
                    applyOverlapHorizontalPosition(block, {
                        laneIndex: entry.laneIndex,
                        laneCount: entry.laneCount,
                        singleDoctorMode
                    });

                    const typeLabel = String(appointment?.type || '').toLowerCase();
                    if (typeLabel.includes('prima')) {
                        block.classList.add('is-prima');
                    } else if (typeLabel.includes('control')) {
                        block.classList.add('is-control');
                    }

                    const statusInfo = normalizeStatus(appointment?.status);
                    const patientLabel = maskPatientName(getAppointmentPatientRawName(appointment));
                    const timeRange = `${toMinuteLabel(blockStart)} - ${toMinuteLabel(blockEnd)}`;
                    block.title = `${patientLabel} | ${timeRange}`;
                    block.setAttribute('role', 'button');
                    block.setAttribute('tabindex', '0');
                    block.setAttribute('aria-haspopup', 'dialog');
                    block.setAttribute('aria-label', buildBlockAriaLabel(appointment, blockStart, blockEnd, statusInfo));

                    const patient = createNode('div', 'admin-scheduler-patient', patientLabel);
                    const meta = createNode('div', 'admin-scheduler-meta');
                    const typeChip = createNode('span', 'admin-scheduler-type', getTypeShortLabel(appointment?.type));
                    const timeChip = createNode('span', 'admin-scheduler-time-chip', toMinuteLabel(blockStart));
                    const statusChip = createNode(
                        'span',
                        `admin-scheduler-status status-${statusInfo.key}`,
                        statusInfo.label
                    );

                    meta.appendChild(typeChip);
                    meta.appendChild(timeChip);
                    meta.appendChild(statusChip);
                    block.appendChild(patient);
                    block.appendChild(meta);

                    if (onAppointmentClick) {
                        block.addEventListener('click', () => {
                            onAppointmentClick({ ...appointment });
                        });
                        block.addEventListener('keydown', (event) => {
                            if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault();
                                onAppointmentClick({ ...appointment });
                            }
                        });
                    }

                    lane.appendChild(block);
                });

                if (!positionedAppointments.length) {
                    const emptyLane = createNode('div', 'admin-scheduler-lane-empty', 'Fara programari');
                    lane.appendChild(emptyLane);
                }

                grid.appendChild(lane);
            });

            scroll.appendChild(grid);
            root.appendChild(scroll);
        };

        const queueRender = () => {
            if (isDestroyed || renderHandle) return;
            if (typeof windowObj.requestAnimationFrame === 'function') {
                renderHandle = windowObj.requestAnimationFrame(() => {
                    renderHandle = 0;
                    performRender();
                });
                return;
            }
            renderHandle = windowObj.setTimeout(() => {
                renderHandle = 0;
                performRender();
            }, 16);
        };

        const handleResize = debounce(() => {
            if (isDestroyed) return;
            const nextWidth = mount.clientWidth;
            if (nextWidth === lastMountWidth) return;
            lastMountWidth = nextWidth;
            queueRender();
        }, 140);

        windowObj.addEventListener('resize', handleResize);

        const render = ({
            appointments = latestState.appointments,
            doctors = latestState.doctors,
            selectedDoctorId = latestState.selectedDoctorId,
            isLoading = false,
            errorMessage = ''
        } = {}) => {
            latestState = {
                appointments: Array.isArray(appointments) ? appointments : [],
                doctors: Array.isArray(doctors) ? doctors : [],
                selectedDoctorId: String(selectedDoctorId || '').trim(),
                isLoading: !!isLoading,
                errorMessage: String(errorMessage || '').trim()
            };

            queueRender();
        };

        const destroy = () => {
            isDestroyed = true;
            windowObj.removeEventListener('resize', handleResize);
            if (typeof handleResize.cancel === 'function') {
                handleResize.cancel();
            }
            if (renderHandle) {
                if (typeof windowObj.cancelAnimationFrame === 'function') {
                    windowObj.cancelAnimationFrame(renderHandle);
                } else {
                    windowObj.clearTimeout(renderHandle);
                }
                renderHandle = 0;
            }
            mount.innerHTML = '';
        };

        return {
            render,
            destroy,
            getState() {
                return { ...latestState };
            }
        };
    }

    windowObj.AdminScheduler = Object.freeze({
        createScheduler
    });
})(window, document);
