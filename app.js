document.addEventListener('DOMContentLoaded', () => {
    // --- 1. КОНФИГУРАЦИЯ И УТИЛИТЫ ---
    const CONFIG = {
        PBKDF2_ITERATIONS: 600000, 
        SALT_LENGTH: 16,
        IV_LENGTH: 12,
        MIN_PASSWORD_LENGTH: 8,
        DB_NAME: 'FinanceDB_Secure',
        DB_VERSION: 8, 
    };
    
    const lockScreen = document.getElementById('lock');
    const appScreen = document.getElementById('app');
    const pinInput = document.getElementById('pin-input');
    const pinBtn = document.getElementById('pin-btn');
    const restoreBtnLock = document.getElementById('restore-btn-lock');
    const resetDbBtn = document.getElementById('reset-db-btn'); // FIX 7.2
    const importFileLock = document.getElementById('import-file-lock');
    const mainContent = document.getElementById('main-content');
    
    let cryptoKey = null; 
    let db;
    let isLoggingIn = false;

    function getTodayLocal() { return new Date().toLocaleDateString('sv-SE'); }
    function toLocalISO(d) {
        const y = d.getFullYear();
        const m = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${y}-${m}-${day}`;
    }
    function escapeHtml(str) {
        if (!str) return '';
        return str.toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function formatMoney(amount) {
        if (amount == null || isNaN(amount)) return '0';
        return amount.toString().replace(/\B(?=(\d{3})+(?!\d))/g, " ");
    }
    function monthsBetween(from, to) { return (to.getFullYear() - from.getFullYear()) * 12 + (to.getMonth() - from.getMonth()); }
    function getMedian(arr) {
        if (arr.length === 0) return 0;
        const sorted = [...arr].sort((a, b) => a - b);
        const middle = Math.floor(sorted.length / 2);
        if (sorted.length % 2 === 0) return (sorted[middle - 1] + sorted[middle]) / 2;
        return sorted[middle];
    }
    
    const fpMap = new WeakMap();
    function initFlatpickr(selector, options = {}) {
        document.querySelectorAll(selector).forEach(el => {
            const existing = fpMap.get(el);
            if (existing) existing.destroy();
            fpMap.set(el, flatpickr(el, { locale: "ru", dateFormat: "Y-m-d", disableMobile: true, ...options }));
        });
    }

    // --- 2. ДЕЛЕГИРОВАНИЕ ВВОДА ---
    document.addEventListener('input', (e) => {
        if (e.target.matches('[data-money]')) {
            let value = e.target.value.replace(/\D/g, '');
            e.target.value = value.replace(/\B(?=(\d{3})+(?!\d))/g, " ");
        }
    });

    // --- 3. ИНИЦИАЛИЗАЦИЯ БД ---
    const dbRequest = indexedDB.open(CONFIG.DB_NAME, CONFIG.DB_VERSION); 
    dbRequest.onupgradeneeded = (event) => {
        db = event.target.result;
        const tx = event.target.transaction;
        if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings', { keyPath: 'key' });
        if (!db.objectStoreNames.contains('expenses')) db.createObjectStore('expenses', { keyPath: 'id', autoIncrement: true });
        if (!db.objectStoreNames.contains('incomes')) db.createObjectStore('incomes', { keyPath: 'id', autoIncrement: true });
        if (!db.objectStoreNames.contains('categories')) db.createObjectStore('categories', { keyPath: 'id', autoIncrement: true });
        if (!db.objectStoreNames.contains('goals')) db.createObjectStore('goals', { keyPath: 'id', autoIncrement: true });
        if (!db.objectStoreNames.contains('recurring')) db.createObjectStore('recurring', { keyPath: 'id', autoIncrement: true });
        
        const expensesStore = tx.objectStore('expenses');
        if (!expensesStore.indexNames.contains('by_date')) expensesStore.createIndex('by_date', 'date');
        const incomesStore = tx.objectStore('incomes');
        if (!incomesStore.indexNames.contains('by_date')) incomesStore.createIndex('by_date', 'date');
    };
    dbRequest.onsuccess = (event) => {
        db = event.target.result;
        seedCategories().then(() => checkUserStatus());
    };
    dbRequest.onerror = (event) => {
        console.error("Ошибка БД:", event.target.error);
        pinBtn.textContent = "Ошибка БД";
        Swal.fire({ icon: 'error', title: 'Ошибка БД', text: 'Не удалось открыть базу данных.', background: '#1e1e1e', color: '#fff' });
    };

    async function seedCategories() {
        return new Promise((resolve) => {
            const tx = db.transaction(['categories'], 'readwrite');
            const store = tx.objectStore('categories');
            const countRequest = store.count();
            tx.onerror = (e) => { console.error(e); resolve(); };
            countRequest.onsuccess = () => {
                if (countRequest.result === 0) {
                    const defaultExpenses = ["Жильё и коммуналка", "Питание", "Транспорт", "Здоровье", "Обязательства", "Связь и подписки", "Дети", "Одежда и обувь", "Развлечения и досуг", "Товары для дома и быт", "Домашние животные", "Накопления"];
                    const defaultIncomes = ["Заработная плата", "Аванс", "Подработки и фриланс", "Доход от имущества", "Проценты по вкладам", "Инвестиции", "Социальные выплаты", "Дополнительные поступления"];
                    defaultExpenses.forEach(name => store.add({ name: name, type: 'expense' }));
                    defaultIncomes.forEach(name => store.add({ name: name, type: 'income' }));
                }
            };
            tx.oncomplete = () => resolve();
        });
    }

    // --- 4. КРИПТОГРАФИЯ ---
    async function deriveKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]);
        return await crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt, iterations: CONFIG.PBKDF2_ITERATIONS, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }
    async function encryptData(text, key = null) {
        const k = key || cryptoKey;
        const enc = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));
        const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, k, enc.encode(text));
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        return btoa(String.fromCharCode(...combined));
    }
    async function decryptData(encryptedBase64, key = null) {
        try {
            const k = key || cryptoKey;
            const combined = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));
            const iv = combined.slice(0, CONFIG.IV_LENGTH);
            const data = combined.slice(CONFIG.IV_LENGTH);
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, k, data);
            return new TextDecoder().decode(decrypted);
        } catch (e) { return null; }
    }

    // --- 5. СИНХРОНИЗАЦИЯ СОЛИ ---
    async function getOrCreateSalt() {
        let attempts = 0;
        while (!db && attempts < 30) { await new Promise(r => setTimeout(r, 100)); attempts++; }
        if (!db) throw new Error("DB_NOT_READY");
        
        const saltRecord = await new Promise((resolve) => {
            const req = db.transaction(['settings'], 'readonly').objectStore('settings').get('salt');
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
        });
        const masterCheck = await new Promise((resolve) => {
            const req = db.transaction(['settings'], 'readonly').objectStore('settings').get('masterCheck');
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
        });

        if (saltRecord) return new Uint8Array(atob(saltRecord.value).split('').map(c => c.charCodeAt(0)));
        if (masterCheck) throw new Error("SALT_CORRUPTED");
        
        const newSalt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
        const newSaltBase64 = btoa(String.fromCharCode(...newSalt));
        await new Promise((resolve) => {
            const tx = db.transaction(['settings'], 'readwrite');
            tx.objectStore('settings').put({ key: 'salt', value: newSaltBase64 });
            tx.oncomplete = () => resolve();
        });
        return newSalt;
    }

    async function resetDatabase() {
        return new Promise((resolve, reject) => {
            const stores = ['settings', 'expenses', 'incomes', 'categories', 'goals', 'recurring'];
            const tx = db.transaction(stores, 'readwrite');
            stores.forEach(s => tx.objectStore(s).clear());
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error);
        });
    }

    // --- 6. АВТОРИЗАЦИЯ ---
    async function checkUserStatus() {
        const request = db.transaction(['settings'], 'readonly').objectStore('settings').get('masterCheck');
        request.onsuccess = () => {
            if (!request.result) {
                lockScreen.querySelector('h2').textContent = "Придумайте пароль (мин. 8 символов)";
                pinBtn.textContent = "Создать хранилище";
            } else {
                lockScreen.querySelector('h2').textContent = "Введите пароль";
                pinBtn.textContent = "Разблокировать";
            }
        };
    }

    pinBtn.addEventListener('click', async () => {
        if (isLoggingIn) return;
        if (typeof Swal !== 'undefined') Swal.close(); // FIX 7.1: Очистка зависших оверлеев
        
        isLoggingIn = true;
        const originalText = pinBtn.textContent;
        pinBtn.textContent = "Проверка...";
        
        try {
            const password = pinInput.value;
            if (password.length < CONFIG.MIN_PASSWORD_LENGTH) {
                await Swal.fire({ icon: 'error', title: 'Ошибка', text: `Пароль должен быть минимум ${CONFIG.MIN_PASSWORD_LENGTH} символов!`, background: '#1e1e1e', color: '#fff' });
                return;
            }
            
            let salt;
            try { 
                salt = await getOrCreateSalt(); 
            } catch (e) {
                if (e.message === "SALT_CORRUPTED") {
                    pinInput.value = '';
                    const result = await Swal.fire({
                        icon: 'error', title: 'База повреждена',
                        text: 'Соль шифрования потеряна. Восстановите из бэкапа или создайте новую базу.',
                        background: '#1e1e1e', color: '#fff',
                        showCancelButton: true, confirmButtonText: 'Восстановить из бэкапа', cancelButtonText: 'Сбросить всё',
                        confirmButtonColor: '#4CAF50', cancelButtonColor: '#ff5252'
                    });
                    if (result.isConfirmed) restoreBtnLock.click();
                    else if (result.dismiss === Swal.DismissReason.cancel) {
                        resetDbBtn.click(); // Передаём управление стандартной процедуре сброса
                    }
                    return;
                }
                throw e;
            }
            
            cryptoKey = await deriveKey(password, salt);
            const checkEncrypted = await new Promise((resolve) => {
                const req = db.transaction(['settings'], 'readonly').objectStore('settings').get('masterCheck');
                req.onsuccess = () => resolve(req.result ? req.result.value : null);
            });
            
            if (!checkEncrypted) {
                const encryptedCheck = await encryptData("SUCCESS");
                await new Promise((resolve) => {
                    const tx = db.transaction(['settings'], 'readwrite');
                    tx.objectStore('settings').put({ key: 'masterCheck', value: encryptedCheck });
                    tx.oncomplete = () => resolve();
                });
                await unlockApp(); // FIX 7.1: добавлен await
            } else {
                const decrypted = await decryptData(checkEncrypted);
                if (decrypted === "SUCCESS") {
                    await unlockApp(); // FIX 7.1: добавлен await
                } else {
                    await Swal.fire({ 
                        icon: 'error', title: 'Ошибка', 
                        text: 'Неверный пароль! Если вы его забыли, используйте кнопку "Сбросить всё" на экране входа.', 
                        background: '#1e1e1e', color: '#fff' 
                    });
                    pinInput.value = '';
                    cryptoKey = null;
                }
            }
        } catch (e) {
            console.error(e);
            await Swal.fire({ icon: 'error', title: 'Ошибка', text: 'Не удалось загрузить базу данных.', background: '#1e1e1e', color: '#fff' });
        } finally {
            isLoggingIn = false;
            pinBtn.textContent = originalText;
        }
    });

    pinInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !isLoggingIn) pinBtn.click(); });
    restoreBtnLock.addEventListener('click', () => importFileLock.click());
    importFileLock.addEventListener('change', (e) => { if (e.target.files.length > 0) importBackup(e.target.files[0]); });
    
    // FIX 7.2: Обработчик кнопки сброса базы
    resetDbBtn.addEventListener('click', async () => {
        const confirm = await Swal.fire({
            icon: 'warning', title: 'Точно сбросить?',
            text: 'Все данные будут удалены безвозвратно. Введите RESET для подтверждения.',
            input: 'text', inputPlaceholder: 'RESET', showCancelButton: true,
            confirmButtonText: 'Удалить всё', cancelButtonText: 'Отмена', confirmButtonColor: '#ff5252',
            background: '#1e1e1e', color: '#fff',
            inputValidator: (value) => { if (value !== 'RESET') return 'Введите RESET заглавными буквами'; }
        });
        if (confirm.isConfirmed) {
            await resetDatabase();
            await seedCategories();
            await Swal.fire({ icon: 'success', title: 'Сброшено', text: 'База очищена. Создайте новый пароль.', background: '#1e1e1e', color: '#fff' });
            location.reload();
        }
    });

    async function unlockApp() {
        if (typeof Swal !== 'undefined') Swal.close();
        lockScreen.classList.add('hidden');
        appScreen.classList.remove('hidden');
        try {
            await checkRecurringOperations(); // FIX 7.1: обёрнуто в try/catch
        } catch (e) {
            console.error('Recurring failed:', e);
            // Не блокируем рендер, данные не тронуты (транзакция атомарна)
        }
        loadTab('расходы');
    }

    // --- 7. НАВИГАЦИЯ ---
    const navButtons = document.querySelectorAll('.top-nav button');
    navButtons.forEach(button => {
        button.addEventListener('click', () => loadTab(button.dataset.tab)); // FIX: используем data-tab для надёжности
    });

    function loadTab(tabName) {
        navButtons.forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.tab === tabName) btn.classList.add('active');
        });
        if (tabName === 'доходы') renderIncomesScreen();
        else if (tabName === 'расходы') renderExpensesScreen();
        else if (tabName === 'календарь') renderCalendarScreen();
        else if (tabName === 'отчёт') renderReportScreen();
        else if (tabName === 'планер') renderPlannerScreen();
    }

    // --- 8. ДЕЙСТВИЯ ---
    mainContent.addEventListener('click', (e) => {
        const target = e.target.closest('[data-action]');
        if (!target) return;
        const action = target.dataset.action;
        const id = parseInt(target.dataset.id);
        if (action === 'delete-expense') deleteItem('expenses', id, renderExpensesScreen);
        else if (action === 'delete-income') deleteItem('incomes', id, renderIncomesScreen);
        else if (action === 'delete-goal') deleteItem('goals', id, renderPlannerScreen);
        else if (action === 'edit-expense') openEditModal('expenses', id);
        else if (action === 'edit-income') openEditModal('incomes', id);
    });

    function deleteItem(storeName, id, renderCallback) {
        Swal.fire({
            title: 'Удалить?', icon: 'warning', showCancelButton: true,
            confirmButtonColor: '#ff5252', cancelButtonColor: '#333', confirmButtonText: 'Да', cancelButtonText: 'Отмена',
            background: '#1e1e1e', color: '#fff'
        }).then(async (result) => {
            if (!result.isConfirmed) return;
            if (storeName === 'expenses') {
                const record = await new Promise(resolve => {
                    const req = db.transaction(['expenses'], 'readonly').objectStore('expenses').get(id);
                    req.onsuccess = () => resolve(req.result);
                });
                if (!record) return;
                if (record.goalId) {
                    const tx = db.transaction(['expenses', 'goals'], 'readwrite');
                    tx.objectStore('expenses').delete(id);
                    const goalStore = tx.objectStore('goals');
                    const req = goalStore.get(record.goalId);
                    req.onsuccess = () => {
                        if (req.result) {
                            req.result.saved = Math.max(0, (req.result.saved || 0) - record.amount);
                            goalStore.put(req.result);
                        }
                    };
                    tx.oncomplete = () => renderCallback();
                } else {
                    const tx = db.transaction(['expenses'], 'readwrite');
                    tx.objectStore('expenses').delete(id);
                    tx.oncomplete = () => renderCallback();
                }
            } else {
                const tx = db.transaction([storeName], 'readwrite');
                tx.objectStore(storeName).delete(id);
                tx.oncomplete = () => renderCallback();
            }
        });
    }

    async function openEditModal(storeName, id) {
        const record = await new Promise(resolve => {
            const req = db.transaction([storeName], 'readonly').objectStore(storeName).get(id);
            req.onsuccess = () => resolve(req.result);
        });
        if (!record) return;
        const decryptedName = await decryptData(record.encryptedName);
        
        Swal.fire({
            title: 'Редактировать',
            html: `
                <input id="swal-name" class="swal2-input" placeholder="Комментарий" value="${decryptedName ? escapeHtml(decryptedName) : ''}">
                <input id="swal-amount" class="swal2-input" type="text" inputmode="decimal" placeholder="Сумма" value="${record.amount}">
                <input id="swal-date" class="swal2-input" type="date" value="${record.date}">
                ${storeName === 'expenses' ? `
                <label style="display: flex; align-items: center; justify-content: center; color: white; margin-top: 15px;">
                    <input type="checkbox" id="swal-mandatory" ${record.mandatory ? 'checked' : ''} style="margin-right: 10px;"> Обязательный платеж
                </label>
                ` : ''}
            `,
            background: '#1e1e1e', color: '#fff',
            showCancelButton: true, confirmButtonText: 'Сохранить', cancelButtonText: 'Отмена',
            confirmButtonColor: '#4CAF50', cancelButtonColor: '#333',
            preConfirm: () => {
                const amount = parseFloat(document.getElementById('swal-amount').value.replace(/\s/g, ''));
                if (isNaN(amount) || amount <= 0) {
                    Swal.showValidationMessage('Введите корректную сумму');
                    return false;
                }
                return {
                    name: document.getElementById('swal-name').value.trim() || "Без комментария",
                    amount: amount,
                    date: document.getElementById('swal-date').value,
                    mandatory: storeName === 'expenses' ? document.getElementById('swal-mandatory').checked : false
                };
            }
        }).then(async (result) => {
            if (!result.isConfirmed) return;
            const encryptedName = await encryptData(result.value.name);
            const updatedRecord = { ...record, encryptedName, amount: result.value.amount, date: result.value.date, mandatory: result.value.mandatory };
            
            if (storeName === 'expenses' && record.goalId) {
                const delta = result.value.amount - record.amount;
                const tx = db.transaction(['expenses', 'goals'], 'readwrite');
                tx.objectStore('expenses').put(updatedRecord);
                const goalStore = tx.objectStore('goals');
                const req = goalStore.get(record.goalId);
                req.onsuccess = () => {
                    if (req.result) {
                        req.result.saved = Math.max(0, (req.result.saved || 0) + delta);
                        goalStore.put(req.result);
                    }
                };
                tx.oncomplete = () => {
                    renderExpensesScreen();
                    Swal.fire({ icon: 'success', title: 'Обновлено', toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, background: '#1e1e1e', color: '#fff' });
                };
            } else {
                const tx = db.transaction([storeName], 'readwrite');
                tx.objectStore(storeName).put(updatedRecord);
                tx.oncomplete = () => {
                    if (storeName === 'expenses') renderExpensesScreen();
                    else renderIncomesScreen();
                    Swal.fire({ icon: 'success', title: 'Обновлено', toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, background: '#1e1e1e', color: '#fff' });
                };
            }
        });
    }

    // --- 9. РАСХОДЫ ---
    // FIX 7.4: Добавлены параметры isRecurring и freq, чтобы не читать DOM после await
    async function addExpenseToDB(name, amount, categoryId, mandatory, date, goalId = null, isRecurring = false, freq = null) {
        if (!cryptoKey) return Swal.fire('Ошибка', 'Нет ключа', 'error');
        
        const encryptedName = await encryptData(name);
        const dayOfMonth = parseInt(date.split('-')[2], 10);
        
        // FIX 7.3: Используем дату операции, а не текущую дату
        const runMonth = freq === 'monthly' ? date.slice(0, 7) : null;
        const runYear = freq === 'yearly' ? date.slice(0, 4) : null;

        const stores = isRecurring ? ['expenses', 'goals', 'recurring'] : ['expenses', 'goals'];
        const tx = db.transaction(stores, 'readwrite');
        const expStore = tx.objectStore('expenses');
        const goalStore = tx.objectStore('goals');
        
        expStore.add({ encryptedName, amount, categoryId, mandatory, date, goalId });
        
        if (goalId) {
            const req = goalStore.get(goalId);
            req.onsuccess = () => {
                if (req.result) {
                    req.result.saved = (req.result.saved || 0) + amount;
                    goalStore.put(req.result);
                }
            };
        }
        
        if (isRecurring) {
            const recStore = tx.objectStore('recurring');
            recStore.add({
                type: 'expense', encryptedName, amount, categoryId, mandatory, freq,
                dayOfMonth, goalId,
                lastRunMonth: runMonth,
                lastRunYear: runYear
            });
        }
        
        return new Promise((resolve) => {
            tx.oncomplete = () => {
                renderExpensesScreen();
                Swal.fire({ icon: 'success', title: 'Расход добавлен', toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, background: '#1e1e1e', color: '#fff' });
                resolve();
            };
            tx.onerror = () => {
                console.error('Ошибка добавления расхода:', tx.error);
                Swal.fire({ icon: 'error', title: 'Ошибка', text: 'Не удалось сохранить расход', background: '#1e1e1e', color: '#fff' });
                resolve();
            };
        });
    }

    async function renderExpensesScreen() {
        const tx = db.transaction(['categories', 'goals'], 'readonly');
        const reqCat = tx.objectStore('categories').getAll();
        const reqGoals = tx.objectStore('goals').getAll();
        tx.oncomplete = async () => {
            const allCategories = reqCat.result;
            const allGoals = reqGoals.result;
            const decryptedGoals = await Promise.all(allGoals.map(async g => ({
                id: g.id, name: await decryptData(g.encryptedName) || '(ошибка)'
            })));
            
            let optionsHTML = allCategories.filter(c => c.type === 'expense')
                .map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
            
            mainContent.innerHTML = `
                <h2 style="text-align: center; margin-bottom: 20px;">Расходы</h2>
                <div style="background: #1e1e1e; padding: 15px; border-radius: 10px; margin-bottom: 20px;">
                    <input type="text" id="exp-name" placeholder="Комментарий" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <select id="exp-category" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">${optionsHTML}</select>
                    <select id="exp-goal" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px; display: none;">
                        <option value="">Выберите цель...</option>
                        ${decryptedGoals.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('')}
                    </select>
                    <input type="text" data-money id="exp-amount" placeholder="Сумма (руб)" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <input type="text" id="exp-date" placeholder="Дата" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;" value="${getTodayLocal()}">
                    <label style="display: flex; align-items: center; color: white; margin-bottom: 10px;">
                        <input type="checkbox" id="exp-mandatory" style="margin-right: 10px;"> Обязательный платеж
                    </label>
                    <label style="display: flex; align-items: center; color: white; margin-bottom: 10px;">
                        <input type="checkbox" id="exp-recurring" style="margin-right: 10px;"> Повторяющийся платеж
                    </label>
                    <div id="recurring-options" style="display: none; margin-bottom: 10px; padding-left: 25px;">
                        <select id="exp-frequency" style="width: 100%; padding: 8px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                            <option value="monthly">Каждый месяц</option>
                            <option value="yearly">Каждый год</option>
                        </select>
                    </div>
                    <button id="save-exp-btn" style="width: 100%; padding: 10px; background: #4CAF50; color: white; border: none; border-radius: 5px; font-size: 16px; margin-top: 10px;">Добавить расход</button>
                </div>
                <div id="expenses-list"><p style="color: #888;">Загрузка...</p></div>
            `;
            
            initFlatpickr("#exp-date", { defaultDate: getTodayLocal() });
            
            const expCategory = document.getElementById('exp-category');
            const expGoal = document.getElementById('exp-goal');
            const expRec = document.getElementById('exp-recurring');
            const recOptions = document.getElementById('recurring-options');
            
            expCategory.addEventListener('change', () => {
                const selectedCat = allCategories.find(c => c.id === parseInt(expCategory.value));
                expGoal.style.display = (selectedCat && selectedCat.name === 'Накопления') ? 'block' : 'none';
            });
            expRec.addEventListener('change', () => {
                recOptions.style.display = expRec.checked ? 'block' : 'none';
            });
            
            document.getElementById('save-exp-btn').addEventListener('click', async () => {
                const saveBtn = document.getElementById('save-exp-btn');
                saveBtn.disabled = true; // FIX 7.5: Блокировка кнопки
                saveBtn.textContent = 'Сохранение...';
                
                try {
                    const name = document.getElementById('exp-name').value.trim() || "Без комментария";
                    const amount = parseFloat(document.getElementById('exp-amount').value.replace(/\s/g, ''));
                    const categoryId = parseInt(expCategory.value);
                    const date = document.getElementById('exp-date').value;
                    const goalId = expGoal.style.display !== 'none' && expGoal.value ? parseInt(expGoal.value) : null;
                    
                    // FIX 7.4: Читаем DOM ДО любого await
                    const isRecurring = document.getElementById('exp-recurring').checked;
                    const freq = isRecurring ? (document.getElementById('exp-frequency')?.value || 'monthly') : null;
                    const mandatory = document.getElementById('exp-mandatory').checked;

                    if (isNaN(amount) || amount <= 0) {
                        Swal.fire('Ошибка', 'Укажите сумму больше нуля!', 'error');
                        return;
                    }
                    
                    await addExpenseToDB(name, amount, categoryId, mandatory, date, goalId, isRecurring, freq);
                } finally {
                    saveBtn.disabled = false;
                    saveBtn.textContent = 'Добавить расход';
                }
            });
            
            document.getElementById('exp-amount').addEventListener('keydown', (e) => {
                if (e.key === 'Enter') document.getElementById('save-exp-btn').click();
            });
            
            const reqExp = db.transaction(['expenses'], 'readonly').objectStore('expenses').getAll();
            reqExp.onsuccess = async () => {
                const expenses = reqExp.result;
                const listDiv = document.getElementById('expenses-list');
                if (expenses.length === 0) return listDiv.innerHTML = '<p style="color: #888;">Расходов пока нет.</p>';
                
                const decryptedNames = await Promise.all(expenses.map(e => decryptData(e.encryptedName)));
                let html = '';
                expenses.reverse().forEach((exp, idx) => {
                    const decryptedName = decryptedNames[expenses.length - 1 - idx];
                    const displayName = decryptedName ? escapeHtml(decryptedName) : '(не удалось расшифровать)';
                    const cat = allCategories.find(c => c.id === exp.categoryId);
                    const mandBadge = exp.mandatory ? '<span style="background: #ff5252; color: white; font-size: 10px; padding: 2px 5px; border-radius: 3px; margin-left: 5px;">Обязательный</span>' : '';
                    html += `
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; border-bottom: 1px solid #333;">
                            <div>
                                <div style="font-weight: bold;">${cat ? escapeHtml(cat.name) : "Без категории"} ${mandBadge}</div>
                                <div style="font-size: 12px; color: #888;">${displayName} • ${exp.date}</div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <div style="font-weight: bold; color: #ff5252;">-${formatMoney(exp.amount)} ₽</div>
                                <button data-action="edit-expense" data-id="${exp.id}" style="background: none; border: none; color: #888; font-size: 18px; cursor: pointer; padding: 10px;">✎</button>
                                <button data-action="delete-expense" data-id="${exp.id}" style="background: none; border: none; color: #888; font-size: 20px; cursor: pointer; min-width: 44px; min-height: 44px;">&times;</button>
                            </div>
                        </div>`;
                });
                listDiv.innerHTML = html;
            };
        };
    }

    // --- 10. ДОХОДЫ ---
    async function addIncomeToDB(name, amount, categoryId, date) {
        if (!cryptoKey) return Swal.fire('Ошибка', 'Нет ключа', 'error');
        const encryptedName = await encryptData(name);
        const transaction = db.transaction(['incomes'], 'readwrite');
        transaction.objectStore('incomes').add({ encryptedName, amount, categoryId, date });
        return new Promise(resolve => {
            transaction.oncomplete = () => {
                renderIncomesScreen();
                Swal.fire({ icon: 'success', title: 'Доход добавлен', toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, background: '#1e1e1e', color: '#fff' });
                resolve();
            };
        });
    }

    async function renderIncomesScreen() {
        const tx = db.transaction(['categories'], 'readonly');
        const request = tx.objectStore('categories').getAll();
        request.onsuccess = () => {
            const allCategories = request.result;
            let optionsHTML = allCategories.filter(c => c.type === 'income')
                .map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
            
            mainContent.innerHTML = `
                <h2 style="text-align: center; margin-bottom: 20px;">Доходы</h2>
                <div style="background: #1e1e1e; padding: 15px; border-radius: 10px; margin-bottom: 20px;">
                    <input type="text" id="inc-name" placeholder="Комментарий" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <select id="inc-category" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">${optionsHTML}</select>
                    <input type="text" data-money id="inc-amount" placeholder="Сумма (руб)" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <input type="text" id="inc-date" placeholder="Дата" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;" value="${getTodayLocal()}">
                    <button id="save-inc-btn" style="width: 100%; padding: 10px; background: #2196F3; color: white; border: none; border-radius: 5px; font-size: 16px;">Добавить доход</button>
                </div>
                <div id="incomes-list"><p style="color: #888;">Загрузка...</p></div>
            `;
            
            initFlatpickr("#inc-date", { defaultDate: getTodayLocal() });
            
            document.getElementById('save-inc-btn').addEventListener('click', async () => {
                const saveBtn = document.getElementById('save-inc-btn');
                saveBtn.disabled = true; // FIX 7.5
                saveBtn.textContent = 'Сохранение...';
                try {
                    const name = document.getElementById('inc-name').value.trim() || "Без комментария";
                    const amount = parseFloat(document.getElementById('inc-amount').value.replace(/\s/g, ''));
                    const date = document.getElementById('inc-date').value;
                    if (isNaN(amount) || amount <= 0) {
                        Swal.fire('Ошибка', 'Укажите сумму!', 'error');
                        return;
                    }
                    await addIncomeToDB(name, amount, parseInt(document.getElementById('inc-category').value), date);
                } finally {
                    saveBtn.disabled = false;
                    saveBtn.textContent = 'Добавить доход';
                }
            });
            
            document.getElementById('inc-amount').addEventListener('keydown', (e) => {
                if (e.key === 'Enter') document.getElementById('save-inc-btn').click();
            });
            
            const reqInc = db.transaction(['incomes'], 'readonly').objectStore('incomes').getAll();
            reqInc.onsuccess = async () => {
                const incomes = reqInc.result;
                const listDiv = document.getElementById('incomes-list');
                if (incomes.length === 0) return listDiv.innerHTML = '<p style="color: #888;">Доходов пока нет.</p>';
                
                const decryptedNames = await Promise.all(incomes.map(i => decryptData(i.encryptedName)));
                let html = '';
                incomes.reverse().forEach((inc, idx) => {
                    const decryptedName = decryptedNames[incomes.length - 1 - idx];
                    const displayName = decryptedName ? escapeHtml(decryptedName) : '(не удалось расшифровать)';
                    const cat = allCategories.find(c => c.id === inc.categoryId);
                    html += `
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; border-bottom: 1px solid #333;">
                            <div>
                                <div style="font-weight: bold;">${cat ? escapeHtml(cat.name) : "Без категории"}</div>
                                <div style="font-size: 12px; color: #888;">${displayName} • ${inc.date}</div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <div style="font-weight: bold; color: #4CAF50;">+${formatMoney(inc.amount)} ₽</div>
                                <button data-action="edit-income" data-id="${inc.id}" style="background: none; border: none; color: #888; font-size: 18px; cursor: pointer; padding: 10px;">✎</button>
                                <button data-action="delete-income" data-id="${inc.id}" style="background: none; border: none; color: #888; font-size: 20px; cursor: pointer; min-width: 44px; min-height: 44px;">&times;</button>
                            </div>
                        </div>`;
                });
                listDiv.innerHTML = html;
            };
        };
    }

    // --- 11. ОТЧЕТ ---
    async function renderReportScreen() {
        const tx = db.transaction(['expenses', 'categories'], 'readonly');
        const reqExp = tx.objectStore('expenses').getAll();
        const reqCat = tx.objectStore('categories').getAll();
        tx.oncomplete = () => {
            const expenses = reqExp.result;
            const categories = reqCat.result;
            if (expenses.length === 0) return mainContent.innerHTML = '<h2 style="text-align: center;">Отчет</h2><p style="color: #888;">Расходов пока нет.</p>';
            
            const totalsByCategory = {};
            let grandTotal = 0;
            for (const exp of expenses) {
                const catId = exp.categoryId || 0;
                totalsByCategory[catId] = (totalsByCategory[catId] || 0) + exp.amount;
                grandTotal += exp.amount;
            }
            
            const sortedData = Object.keys(totalsByCategory).map(id => {
                const cat = categories.find(c => c.id == id);
                return { name: cat ? cat.name : "Другое", amount: totalsByCategory[id] };
            }).sort((a, b) => b.amount - a.amount);
            
            const colors = ['#4f9cf9', '#7c5cff', '#3ddc84', '#ffb86b', '#ff5c6c', '#6bd0ff', '#c084fc', '#facc15'];
            let currentAngle = 0;
            let gradientParts = [];
            let legendHTML = '';
            
            sortedData.forEach((item, index) => {
                const percentage = (item.amount / grandTotal) * 100;
                const sliceAngle = (item.amount / grandTotal) * 360;
                const color = colors[index % colors.length];
                gradientParts.push(`${color} ${currentAngle}deg ${currentAngle + sliceAngle}deg`);
                currentAngle += sliceAngle;
                legendHTML += `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #333;">
                        <div style="display: flex; align-items: center;">
                            <span style="display: inline-block; width: 12px; height: 12px; background: ${color}; border-radius: 50%; margin-right: 10px;"></span>
                            <span>${escapeHtml(item.name)}</span>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-weight: bold;">${formatMoney(item.amount)} ₽</div>
                            <div style="font-size: 12px; color: #888;">${percentage.toFixed(1)}%</div>
                        </div>
                    </div>`;
            });
            
            mainContent.innerHTML = `
                <h2 style="text-align: center;">Отчет</h2>
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="font-size: 14px; color: #888; margin-bottom: 5px;">Всего потрачено</div>
                    <div style="font-size: 28px; font-weight: bold; color: #ff5252;">${formatMoney(grandTotal)} ₽</div>
                </div>
                <div style="width: 220px; height: 220px; border-radius: 50%; margin: 0 auto 30px auto; background: conic-gradient(${gradientParts.join(', ')}); box-shadow: 0 4px 15px rgba(0,0,0,0.5);">
                    <div style="width: 120px; height: 120px; background: #121212; border-radius: 50%; position: relative; top: 50px; left: 50px;"></div>
                </div>
                <div>${legendHTML}</div>
            `;
        };
    }

    // --- 12. ПЛАНЕР ---
    async function renderPlannerScreen() {
        const tx = db.transaction(['goals', 'expenses', 'incomes'], 'readonly');
        const reqGoals = tx.objectStore('goals').getAll();
        const reqExp = tx.objectStore('expenses').getAll();
        const reqInc = tx.objectStore('incomes').getAll();
        tx.oncomplete = async () => {
            const goals = reqGoals.result;
            const allExpenses = reqExp.result;
            const allIncomes = reqInc.result;
            const now = new Date();
            const threeMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 3, 1);
            
            const monthlyIncomes = {};
            const monthlyMandatoryExpenses = {};
            
            allIncomes.forEach(inc => {
                const incDate = new Date(inc.date + 'T00:00:00');
                if (incDate >= threeMonthsAgo) {
                    const monthKey = inc.date.slice(0, 7);
                    monthlyIncomes[monthKey] = (monthlyIncomes[monthKey] || 0) + inc.amount;
                }
            });
            allExpenses.forEach(exp => {
                const expDate = new Date(exp.date + 'T00:00:00');
                if (expDate >= threeMonthsAgo && exp.mandatory) {
                    const monthKey = exp.date.slice(0, 7);
                    monthlyMandatoryExpenses[monthKey] = (monthlyMandatoryExpenses[monthKey] || 0) + exp.amount;
                }
            });
            
            const medianIncome = getMedian(Object.values(monthlyIncomes));
            const medianMandatory = getMedian(Object.values(monthlyMandatoryExpenses));
            const freeFlow = Math.max(0, medianIncome - medianMandatory);
            
            const allDates = [...allExpenses, ...allIncomes].map(r => new Date(r.date + 'T00:00:00').getTime());
            const oldestDate = allDates.length > 0 ? new Date(Math.min(...allDates)) : new Date();
            const weeksOfData = Math.floor((new Date() - oldestDate) / (1000 * 60 * 60 * 24 * 7));
            
            let html = `
                <h2 style="text-align: center; margin-bottom: 20px;">Планер целей</h2>
                <div style="background: #1e1e1e; padding: 15px; border-radius: 10px; margin-bottom: 20px;">
                    <input type="text" id="goal-name" placeholder="Что хотим купить?" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <input type="text" data-money id="goal-amount" placeholder="Стоимость (руб)" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <input type="text" data-money id="goal-saved" placeholder="Уже накоплено (руб)" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <input type="text" id="goal-deadline" placeholder="Выберите дедлайн" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <button id="save-goal-btn" style="width: 100%; padding: 10px; background: #7c5cff; color: white; border: none; border-radius: 5px; font-size: 16px;">Добавить цель</button>
                </div>
                <div style="background: #1a2f3a; border: 1px solid #6bd0ff; border-radius: 10px; padding: 12px; margin-bottom: 20px;">
                    <div style="font-size: 12px; color: #6bd0ff;">Свободный поток (по медиане за 3 мес.)</div>
                    <div style="font-size: 20px; font-weight: bold;">${formatMoney(Math.round(freeFlow))} ₽ / мес.</div>
                    <div style="font-size: 11px; color: #888; margin-top: 4px;">Доход: ${formatMoney(Math.round(medianIncome))} — Обязательные: ${formatMoney(Math.round(medianMandatory))}</div>
                </div>
            `;
            
            if (goals.length === 0) {
                html += '<p style="color: #888;">Целей пока нет.</p>';
            } else {
                let goalsHtml = '';
                const dateOptions = { day: 'numeric', month: 'long', year: 'numeric' };
                for (const goal of goals) {
                    const decryptedName = await decryptData(goal.encryptedName);
                    const displayName = decryptedName ? escapeHtml(decryptedName) : '(не удалось расшифровать)';
                    const left = Math.max(0, goal.amount - goal.saved);
                    let deadlineText = 'Без дедлайна';
                    
                    if (goal.deadline) {
                        const deadline = new Date(goal.deadline + 'T00:00:00');
                        const diffMonths = Math.max(1, monthsBetween(now, deadline));
                        const requiredPerMonth = left / diffMonths;
                        deadlineText = `До: ${deadline.toLocaleDateString('ru-RU', dateOptions)} (нужно ~${formatMoney(Math.ceil(requiredPerMonth))} ₽/мес)`;
                    }
                    
                    let sliderHtml = '';
                    if (weeksOfData < 4) {
                        const weeksLeft = 4 - weeksOfData;
                        sliderHtml = `<div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #333; font-size: 13px; color: #ffb86b; text-align: center;">Пока мало данных для прогноза. Продолжай записывать — через ${weeksLeft} нед. покажем, реально ли достичь цели.</div>`;
                    } else {
                        const maxSlider = Math.max(10000, Math.ceil(freeFlow * 1.5), Math.ceil(left / 12));
                        const defaultSlider = Math.min(Math.ceil(left / 12), maxSlider);
                        sliderHtml = `
                            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #333;">
                                <div style="display: flex; justify-content: space-between; font-size: 12px; color: #888; margin-bottom: 5px;">
                                    <span>Откладывать в месяц:</span>
                                    <span id="slider-val-${goal.id}" style="color: #7c5cff; font-weight: bold;">${formatMoney(defaultSlider)} ₽</span>
                                </div>
                                <input type="range" id="goal-slider-${goal.id}" min="0" max="${maxSlider}" step="1000" value="${defaultSlider}" style="width: 100%; cursor: pointer;">
                                <div id="goal-estimate-${goal.id}" style="font-size: 12px; color: #ffb86b; margin-top: 5px; text-align: center;"></div>
                            </div>`;
                    }
                    
                    goalsHtml += `
                        <div style="background: #1e1e1e; padding: 15px; border-radius: 10px; margin-bottom: 15px; border-left: 4px solid #7c5cff;">
                            <div style="display: flex; justify-content: space-between;">
                                <div style="font-weight: bold; font-size: 18px;">${displayName}</div>
                                <button data-action="delete-goal" data-id="${goal.id}" style="background: none; border: none; color: #888; font-size: 20px; cursor: pointer; min-width: 44px; min-height: 44px;">&times;</button>
                            </div>
                            <div style="color: #888; font-size: 14px; margin-top: 5px;">Цель: ${formatMoney(goal.amount)} ₽ | Накоплено: ${formatMoney(goal.saved)} ₽</div>
                            <div style="margin-top: 5px; font-size: 13px; color: #aaa;">${deadlineText}</div>
                            ${sliderHtml}
                        </div>`;
                }
                html += `<div id="goals-list">${goalsHtml}</div>`;
            }
            
            html += `
                <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; text-align: center;">
                    <h3 style="color: #888; font-size: 16px; margin-bottom: 15px;">Безопасность данных</h3>
                    <button id="export-btn" style="width: 100%; padding: 12px; background: #333; color: white; border: none; border-radius: 5px; margin-bottom: 10px;">💾 Скачать зашифрованный бэкап</button>
                    <input type="file" id="import-file" accept=".enc" style="display: none;">
                    <button id="import-btn" style="width: 100%; padding: 12px; background: #333; color: white; border: none; border-radius: 5px;">📂 Восстановить из бэкапа</button>
                </div>`;
            
            mainContent.innerHTML = html;
            initFlatpickr("#goal-deadline", { minDate: "today" });
            
            goals.forEach(goal => {
                const slider = document.getElementById(`goal-slider-${goal.id}`);
                const valDisplay = document.getElementById(`slider-val-${goal.id}`);
                const estimateDisplay = document.getElementById(`goal-estimate-${goal.id}`);
                if (slider) {
                    const updateEstimate = () => {
                        const perMonth = parseInt(slider.value);
                        const left = Math.max(0, goal.amount - goal.saved);
                        valDisplay.textContent = formatMoney(perMonth) + ' ₽';
                        if (perMonth === 0) {
                            estimateDisplay.textContent = 'Цель не будет достигнута';
                            estimateDisplay.style.color = '#ff5252';
                        } else {
                            const monthsNeeded = Math.ceil(left / perMonth);
                            const finishDate = new Date();
                            finishDate.setMonth(finishDate.getMonth() + monthsNeeded);
                            if (perMonth > freeFlow) {
                                estimateDisplay.textContent = `⚠️ Потребует сокращения на ${formatMoney(perMonth - freeFlow)} ₽/мес`;
                                estimateDisplay.style.color = '#ff5252';
                            } else {
                                estimateDisplay.textContent = `Достигнете через ${monthsNeeded} мес. (${finishDate.toLocaleDateString('ru-RU', { month: 'short', year: 'numeric' })})`;
                                estimateDisplay.style.color = '#3ddc84';
                            }
                        }
                    };
                    slider.addEventListener('input', updateEstimate);
                    updateEstimate();
                }
            });
            
            document.getElementById('export-btn').addEventListener('click', exportBackup);
            document.getElementById('import-btn').addEventListener('click', () => {
                Swal.fire({ title: 'Вы уверены?', text: "Текущие данные будут заменены данными из бэкапа!", icon: 'warning',
                    showCancelButton: true, confirmButtonColor: '#ff5252', cancelButtonColor: '#333',
                    confirmButtonText: 'Да, восстановить', cancelButtonText: 'Отмена', background: '#1e1e1e', color: '#fff'
                }).then((result) => {
                    if (result.isConfirmed) document.getElementById('import-file').click();
                });
            });
            document.getElementById('import-file').addEventListener('change', (e) => {
                if (e.target.files.length > 0) importBackup(e.target.files[0]);
            });
            
            document.getElementById('save-goal-btn').addEventListener('click', async () => {
                const saveBtn = document.getElementById('save-goal-btn');
                saveBtn.disabled = true; // FIX 7.5
                saveBtn.textContent = 'Сохранение...';
                try {
                    const name = document.getElementById('goal-name').value.trim();
                    const amount = parseFloat(document.getElementById('goal-amount').value.replace(/\s/g, ''));
                    const saved = parseFloat(document.getElementById('goal-saved').value.replace(/\s/g, '')) || 0;
                    const deadline = document.getElementById('goal-deadline').value;
                    
                    if (!name || isNaN(amount) || amount <= 0) {
                        Swal.fire({ icon: 'error', title: 'Ошибка', text: 'Заполните название и корректную стоимость', background: '#1e1e1e', color: '#fff' });
                        return;
                    }
                    
                    const encryptedName = await encryptData(name);
                    const txAdd = db.transaction(['goals'], 'readwrite');
                    txAdd.objectStore('goals').add({ encryptedName, amount, saved, deadline: deadline || null });
                    
                    await new Promise(resolve => {
                        txAdd.oncomplete = () => {
                            renderPlannerScreen();
                            resolve();
                        };
                    });
                } finally {
                    saveBtn.disabled = false;
                    saveBtn.textContent = 'Добавить цель';
                }
            });
        };
    }

    // --- 13. КАЛЕНДАРЬ ---
    let currentCalendarDate = new Date();
    async function renderCalendarScreen() {
        const year = currentCalendarDate.getFullYear();
        const month = currentCalendarDate.getMonth();
        const todayStr = getTodayLocal();
        
        const allExpenses = await new Promise(resolve => {
            const req = db.transaction(['expenses'], 'readonly').objectStore('expenses').getAll();
            req.onsuccess = () => resolve(req.result);
        });
        const allIncomes = await new Promise(resolve => {
            const req = db.transaction(['incomes'], 'readonly').objectStore('incomes').getAll();
            req.onsuccess = () => resolve(req.result);
        });
        const allRecurring = await new Promise(resolve => {
            const req = db.transaction(['recurring'], 'readonly').objectStore('recurring').getAll();
            req.onsuccess = () => resolve(req.result);
        });
        
        const monthStr = `${year}-${String(month + 1).padStart(2, '0')}`;
        const monthExpenses = allExpenses.filter(e => e.date.startsWith(monthStr));
        const monthIncomes = allIncomes.filter(i => i.date.startsWith(monthStr));
        
        const dayData = {};
        const initDay = (day) => { if (!dayData[day]) dayData[day] = { exp: 0, inc: 0, rec: [] }; };
        
        monthExpenses.forEach(e => { const d = parseInt(e.date.split('-')[2]); initDay(d); dayData[d].exp += e.amount; });
        monthIncomes.forEach(i => { const d = parseInt(i.date.split('-')[2]); initDay(d); dayData[d].inc += i.amount; });
        allRecurring.forEach(r => {
            const d = r.dayOfMonth;
            if (d) { initDay(d); dayData[d].rec.push({ amount: r.amount, freq: r.freq }); }
        });
        
        const monthNames = ["Январь", "Февраль", "Март", "Апрель", "Май", "Июнь", "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"];
        const headerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; background: #1e1e1e; padding: 10px 15px; border-radius: 10px;">
                <button id="cal-prev" style="background: #333; border: none; color: white; font-size: 20px; width: 44px; height: 44px; border-radius: 8px; cursor: pointer;">‹</button>
                <h3 style="margin: 0; font-size: 18px; color: #fff;">${monthNames[month]} ${year}</h3>
                <button id="cal-next" style="background: #333; border: none; color: white; font-size: 20px; width: 44px; height: 44px; border-radius: 8px; cursor: pointer;">›</button>
            </div>`;
            
        const firstDay = new Date(year, month, 1);
        const daysInMonth = new Date(year, month + 1, 0).getDate();
        let startDay = firstDay.getDay() || 7;
        startDay -= 1;
        
        let gridHTML = `<div style="display: grid; grid-template-columns: repeat(7, 1fr); gap: 5px; margin-bottom: 20px;">
            ${['Пн','Вт','Ср','Чт','Пт','Сб','Вс'].map(d => `<div style="text-align: center; font-size: 12px; color: #888; font-weight: bold; padding: 5px 0;">${d}</div>`).join('')}`;
            
        for (let i = 0; i < startDay; i++) {
            gridHTML += `<div></div>`;
        }
        
        for (let d = 1; d <= daysInMonth; d++) {
            const dateStr = `${monthStr}-${String(d).padStart(2, '0')}`;
            const isToday = dateStr === todayStr;
            const data = dayData[d] || { exp: 0, inc: 0, rec: [] };
            
            let contentHTML = `<div style="font-size: 14px; color: #aaa; font-weight: bold;">${d}</div>`;
            if (data.inc > 0) contentHTML += `<div style="font-size: 10px; color: #4CAF50; font-weight: bold;">+${formatMoney(data.inc)}</div>`;
            if (data.exp > 0) contentHTML += `<div style="font-size: 10px; color: #ff5252; font-weight: bold;">-${formatMoney(data.exp)}</div>`;
            if (data.rec.length > 0) contentHTML += `<div style="font-size: 10px; color: #6bd0ff;">🔄 ${data.rec.length}</div>`;
            
            gridHTML += `<div class="cal-day" data-date="${dateStr}" style="background: #1e1e1e; border-radius: 8px; padding: 8px 4px; text-align: center; cursor: pointer; min-height: 60px; display: flex; flex-direction: column; justify-content: space-between; border: 1px solid ${isToday ? '#7c5cff' : 'transparent'};">${contentHTML}</div>`;
        }
        gridHTML += `</div>`;
        
        mainContent.innerHTML = headerHTML + gridHTML;
        
        document.getElementById('cal-prev').onclick = () => { currentCalendarDate.setMonth(currentCalendarDate.getMonth() - 1); renderCalendarScreen(); };
        document.getElementById('cal-next').onclick = () => { currentCalendarDate.setMonth(currentCalendarDate.getMonth() + 1); renderCalendarScreen(); };
        
        document.querySelectorAll('.cal-day[data-date]').forEach(el => {
            el.onclick = async () => {
                const clickedDate = el.dataset.date;
                const dayExp = allExpenses.filter(e => e.date === clickedDate);
                const dayInc = allIncomes.filter(i => i.date === clickedDate);
                const dNum = parseInt(clickedDate.split('-')[2]);
                const dayRecs = allRecurring.filter(r => r.dayOfMonth === dNum);
                
                let html = '';
                if (dayInc.length > 0) {
                    html += '<h4 style="color:#4CAF50; margin-top:0;">Доходы</h4>';
                    for (const inc of dayInc) {
                        const name = await decryptData(inc.encryptedName) || 'Без названия';
                        html += `<div style="display:flex; justify-content:space-between; padding: 5px 0; border-bottom: 1px solid #333;"><span>${escapeHtml(name)}</span><span style="color:#4CAF50;">+${formatMoney(inc.amount)} ₽</span></div>`;
                    }
                }
                if (dayExp.length > 0) {
                    html += '<h4 style="color:#ff5252; margin-top:15px;">Расходы</h4>';
                    for (const exp of dayExp) {
                        const name = await decryptData(exp.encryptedName) || 'Без названия';
                        html += `<div style="display:flex; justify-content:space-between; padding: 5px 0; border-bottom: 1px solid #333;"><span>${escapeHtml(name)}</span><span style="color:#ff5252;">-${formatMoney(exp.amount)} ₽</span></div>`;
                    }
                }
                if (dayRecs.length > 0) {
                    html += '<h4 style="color:#6bd0ff; margin-top:15px;">Повторяющиеся</h4>';
                    for (const rec of dayRecs) {
                        const name = await decryptData(rec.encryptedName) || 'Без названия';
                        const freqLabel = rec.freq === 'monthly' ? 'каждый месяц' : 'каждый год';
                        html += `<div style="display:flex; justify-content:space-between; padding: 5px 0; border-bottom: 1px solid #333; color:#888;"><span>${escapeHtml(name)} (${freqLabel})</span><span>-${formatMoney(rec.amount)} ₽</span></div>`;
                    }
                }
                if (!html) html = '<p style="color:#888;">В этот день транзакций нет.</p>';
                
                Swal.fire({ title: `События на ${clickedDate}`, html: html, background: '#1e1e1e', color: '#fff', confirmButtonText: 'Закрыть' });
            };
        });
    }

    // --- 14. АВТОМАТИЧЕСКИЕ ОПЕРАЦИИ ---
    async function checkRecurringOperations() {
        const templates = await new Promise((resolve, reject) => {
            const tx = db.transaction(['recurring'], 'readonly');
            const req = tx.objectStore('recurring').getAll();
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(tx.error);
        });

        const today = getTodayLocal();
        const currentMonth = today.slice(0, 7);
        const currentYear = currentMonth.slice(0, 4);
        const [currYearNum, currMonthNum] = currentMonth.split('-').map(Number);
        const lastDayOfMonth = new Date(currYearNum, currMonthNum, 0).getDate();
        
        const MAX_BACKFILL_MONTHS = 12; // FIX 7.6: Ограничитель догонялки

        const tx = db.transaction(['expenses', 'recurring', 'goals'], 'readwrite');
        const expStore = tx.objectStore('expenses');
        const recStore = tx.objectStore('recurring');
        const goalStore = tx.objectStore('goals');
        const goalDeltas = {};

        for (const tmpl of templates) {
            if (tmpl.freq === 'monthly') {
                let [lastYear, lastMonth] = tmpl.lastRunMonth ? tmpl.lastRunMonth.split('-').map(Number) : [currYearNum, currMonthNum];
                let monthsDiff = (currYearNum - lastYear) * 12 + (currMonthNum - lastMonth);
                
                // Ограничиваем backfill, чтобы не зависнуть при открытии после долгого простоя
                if (monthsDiff > MAX_BACKFILL_MONTHS) {
                    lastMonth = currMonthNum - MAX_BACKFILL_MONTHS;
                    if (lastMonth <= 0) {
                        lastYear -= 1;
                        lastMonth += 12;
                    }
                    monthsDiff = MAX_BACKFILL_MONTHS;
                }

                for (let i = 1; i <= monthsDiff; i++) {
                    let targetMonth = lastMonth + i;
                    let targetYear = lastYear;
                    if (targetMonth > 12) {
                        targetYear += Math.floor((targetMonth - 1) / 12);
                        targetMonth = ((targetMonth - 1) % 12) + 1;
                    }
                    const targetMonthStr = `${targetYear}-${String(targetMonth).padStart(2, '0')}`;
                    const clampedDay = Math.min(tmpl.dayOfMonth || 1, new Date(targetYear, targetMonth, 0).getDate());
                    const effectiveDate = `${targetMonthStr}-${String(clampedDay).padStart(2, '0')}`;

                    expStore.add({
                        encryptedName: tmpl.encryptedName, amount: tmpl.amount, categoryId: tmpl.categoryId,
                        mandatory: tmpl.mandatory, date: effectiveDate, goalId: tmpl.goalId || null
                    });
                    if (tmpl.goalId) goalDeltas[tmpl.goalId] = (goalDeltas[tmpl.goalId] || 0) + tmpl.amount;
                }
                tmpl.lastRunMonth = currentMonth;
                recStore.put(tmpl);
                
            } else if (tmpl.freq === 'yearly') {
                let lastYear = tmpl.lastRunYear ? parseInt(tmpl.lastRunYear) : currYearNum;
                let yearsDiff = currYearNum - lastYear;
                const MAX_BACKFILL_YEARS = Math.max(1, Math.floor(MAX_BACKFILL_MONTHS / 12));
                
                if (yearsDiff > MAX_BACKFILL_YEARS) {
                    lastYear = currYearNum - MAX_BACKFILL_YEARS;
                    yearsDiff = MAX_BACKFILL_YEARS;
                }

                for (let i = 1; i <= yearsDiff; i++) {
                    const targetYear = lastYear + i;
                    // Используем текущий месяц для прошлых лет (ограничение текущей схемы данных)
                    const targetMonthStr = `${targetYear}-${String(currMonthNum).padStart(2, '0')}`;
                    const clampedDay = Math.min(tmpl.dayOfMonth || 1, new Date(targetYear, currMonthNum, 0).getDate());
                    const effectiveDate = `${targetMonthStr}-${String(clampedDay).padStart(2, '0')}`;

                    expStore.add({
                        encryptedName: tmpl.encryptedName, amount: tmpl.amount, categoryId: tmpl.categoryId,
                        mandatory: tmpl.mandatory, date: effectiveDate, goalId: tmpl.goalId || null
                    });
                    if (tmpl.goalId) goalDeltas[tmpl.goalId] = (goalDeltas[tmpl.goalId] || 0) + tmpl.amount;
                }
                tmpl.lastRunYear = currentYear;
                recStore.put(tmpl);
            }
        }

        Object.entries(goalDeltas).forEach(([goalId, delta]) => {
            const req = goalStore.get(parseInt(goalId));
            req.onsuccess = () => {
                if (req.result) {
                    req.result.saved = (req.result.saved || 0) + delta;
                    goalStore.put(req.result);
                }
            };
        });

        return new Promise((resolve, reject) => {
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // --- 15. ЭКСПОРТ И ИМПОРТ ---
    async function exportBackup() {
        try {
            const saltRecord = await new Promise((resolve) => {
                const req = db.transaction(['settings'], 'readonly').objectStore('settings').get('salt');
                req.onsuccess = () => resolve(req.result);
            });
            if (!saltRecord) throw new Error("Соль не найдена");
            
            const stores = ['categories', 'expenses', 'incomes', 'goals', 'recurring'];
            const backupData = {};
            for (const storeName of stores) {
                backupData[storeName] = await new Promise((resolve) => {
                    const req = db.transaction([storeName], 'readonly').objectStore(storeName).getAll();
                    req.onsuccess = () => resolve(req.result);
                });
            }
            
            const jsonString = JSON.stringify(backupData);
            const encryptedData = await encryptData(jsonString);
            const fileContent = JSON.stringify({ version: 1, salt: saltRecord.value, encrypted: encryptedData });
            
            const blob = new Blob([fileContent], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `finance_backup_${getTodayLocal()}.enc`;
            a.click();
            URL.revokeObjectURL(url);
            
            Swal.fire({ icon: 'success', title: 'Бэкап создан', html: 'Файл зашифрован и скачан.<br><br><small style="color:#888;">Пароль от бэкапа = ваш текущий пароль от приложения.</small>', background: '#1e1e1e', color: '#fff' });
        } catch (error) {
            console.error(error);
            Swal.fire({ icon: 'error', title: 'Ошибка экспорта', text: error.message, background: '#1e1e1e', color: '#fff' });
        }
    }

    async function importBackup(file) {
        try {
            const fileContent = await file.text();
            let parsed;
            try { parsed = JSON.parse(fileContent); } catch (e) { throw new Error("Неверный формат файла"); }
            if (!parsed.salt || !parsed.encrypted) throw new Error("Файл не содержит соли или данных.");
            
            const { value: backupPassword } = await Swal.fire({
                title: 'Пароль от бэкапа', input: 'password',
                inputLabel: 'Введите пароль, с которым создавался бэкап',
                inputAttributes: { minlength: 8 },
                showCancelButton: true, confirmButtonText: 'Восстановить', cancelButtonText: 'Отмена',
                background: '#1e1e1e', color: '#fff',
                inputValidator: (value) => { if (!value || value.length < 8) return 'Пароль минимум 8 символов'; }
            });
            if (!backupPassword) return;
            
            const backupSalt = new Uint8Array(atob(parsed.salt).split('').map(c => c.charCodeAt(0)));
            const backupKey = await deriveKey(backupPassword, backupSalt);
            const decryptedJson = await decryptData(parsed.encrypted, backupKey);
            if (!decryptedJson) throw new Error("Неверный пароль или повреждённый файл");
            
            const backupData = JSON.parse(decryptedJson);
            const storesToClear = ['categories', 'expenses', 'incomes', 'goals', 'recurring'];
            
            await new Promise((resolve, reject) => {
                const tx = db.transaction(storesToClear, 'readwrite');
                storesToClear.forEach(s => tx.objectStore(s).clear());
                tx.oncomplete = resolve;
                tx.onerror = () => reject(tx.error);
            });
            
            for (const storeName of storesToClear) {
                if (backupData[storeName] && backupData[storeName].length > 0) {
                    await new Promise((resolve, reject) => {
                        const tx = db.transaction([storeName], 'readwrite');
                        backupData[storeName].forEach(item => tx.objectStore(storeName).put(item));
                        tx.oncomplete = resolve;
                        tx.onerror = () => reject(tx.error);
                    });
                }
            }
            
            const newMasterCheck = await encryptData("SUCCESS", backupKey);
            await new Promise((resolve, reject) => {
                const tx = db.transaction(['settings'], 'readwrite');
                tx.objectStore('settings').put({ key: 'salt', value: parsed.salt });
                tx.objectStore('settings').put({ key: 'masterCheck', value: newMasterCheck });
                tx.oncomplete = resolve;
                tx.onerror = () => reject(tx.error);
            });
            
            cryptoKey = backupKey;
            await Swal.fire({
                icon: 'success', title: 'Импорт завершен',
                html: `<p>Данные восстановлены.</p><p style="color:#ffb86b; margin-top:15px;"><b>Важно:</b> пароль от приложения теперь — пароль бэкапа.</p>`,
                background: '#1e1e1e', color: '#fff'
            });
            location.reload();
        } catch (error) {
            console.error(error);
            Swal.fire({ icon: 'error', title: 'Ошибка импорта', text: error.message, background: '#1e1e1e', color: '#fff' });
        }
    }
});