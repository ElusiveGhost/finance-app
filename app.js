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
    pinBtn.disabled = true; // Блокируем кнопку до загрузки базы
    const mainContent = document.getElementById('main-content');
    
    let cryptoKey = null; 
    let db;
    let flatpickrInstances = []; 

    function getTodayLocal() {
        return new Date().toLocaleDateString('sv-SE');
    }

    function escapeHtml(str) {
        if (!str) return '';
        return str.toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function formatMoney(amount) {
        if (amount == null || isNaN(amount)) return '0';
        return amount.toString().replace(/\B(?=(\d{3})+(?!\d))/g, " ");
    }

    function monthsBetween(from, to) {
        return (to.getFullYear() - from.getFullYear()) * 12 + (to.getMonth() - from.getMonth());
    }

    function getMedian(arr) {
        if (arr.length === 0) return 0;
        const sorted = [...arr].sort((a, b) => a - b);
        const middle = Math.floor(sorted.length / 2);
        if (sorted.length % 2 === 0) {
            return (sorted[middle - 1] + sorted[middle]) / 2;
        }
        return sorted[middle];
    }

    function initFlatpickr(selector, options = {}) {
        if (flatpickrInstances.length > 0) {
            flatpickrInstances.forEach(instance => instance.destroy());
            flatpickrInstances = [];
        }
        const elements = document.querySelectorAll(selector);
        elements.forEach(el => {
            const fp = flatpickr(el, { locale: "ru", dateFormat: "Y-m-d", disableMobile: true, ...options });
            flatpickrInstances.push(fp);
        });
    }

    // --- 2. ГЛОБАЛЬНОЕ ДЕЛЕГИРОВАНИЕ ВВОДА ---
    document.addEventListener('input', (e) => {
        if (e.target.matches('[data-money]')) {
            let value = e.target.value.replace(/\D/g, '');
            e.target.value = value.replace(/\B(?=(\d{3})+(?!\d))/g, " ");
        }
    });

    // --- 3. ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ (Версия 8) ---
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
        console.error("Ошибка БД:", event.target.error);
        pinBtn.disabled = false;
        Swal.fire({ icon: 'error', title: 'Ошибка БД', text: 'Не удалось открыть базу данных. Попробуйте перезагрузить страницу.', background: '#1e1e1e', color: '#fff' });
    };
        db = event.target.result;
         pinBtn.disabled = false; // Разблокируем кнопку
        seedCategories().then(() => checkUserStatus());
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

    async function encryptData(text) {
        const enc = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));
        const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cryptoKey, enc.encode(text));
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        return btoa(String.fromCharCode(...combined));
    }

    async function decryptData(encryptedBase64) {
        try {
            const combined = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));
            const iv = combined.slice(0, CONFIG.IV_LENGTH);
            const data = combined.slice(CONFIG.IV_LENGTH);
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, cryptoKey, data);
            return new TextDecoder().decode(decrypted);
        } catch (e) { return null; }
    }

    // --- 5. СИНХРОНИЗАЦИЯ СОЛИ ---
    async function getOrCreateSalt() {
         // Ждем, пока база данных реально откроется
        if (!db) {
            await new Promise(resolve => {
                const checkDb = setInterval(() => {
                    if (db) {
                        clearInterval(checkDb);
                        resolve();
                    }
                }, 100);
            });
        }
        const saltRecord = await new Promise((resolve) => {
            const req = db.transaction(['settings'], 'readonly').objectStore('settings').get('salt');
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
        });

        if (saltRecord) {
            localStorage.setItem('dbSalt', saltRecord.value);
            return new Uint8Array(atob(saltRecord.value).split('').map(c => c.charCodeAt(0)));
        }

        const localSalt = localStorage.getItem('dbSalt');
        if (localSalt) {
            await new Promise((resolve) => {
                const tx = db.transaction(['settings'], 'readwrite');
                tx.objectStore('settings').put({ key: 'salt', value: localSalt });
                tx.oncomplete = () => resolve();
            });
            return new Uint8Array(atob(localSalt).split('').map(c => c.charCodeAt(0)));
        }

        const newSalt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
        const newSaltBase64 = btoa(String.fromCharCode(...newSalt));
        await new Promise((resolve) => {
            const tx = db.transaction(['settings'], 'readwrite');
            tx.objectStore('settings').put({ key: 'salt', value: newSaltBase64 });
            tx.oncomplete = () => resolve();
        });
        localStorage.setItem('dbSalt', newSaltBase64);
        return newSalt;
    }

    // --- 6. АВТОРИЗАЦИЯ ---
    async function checkUserStatus() {
        const request = db.transaction(['settings'], 'readonly').objectStore('settings').get('masterCheck');
        request.onsuccess = () => {
            if (!request.result) {
                lockScreen.querySelector('h2').textContent = "Придумайте длинный пароль (мин. 8 символов)";
                pinBtn.textContent = "Создать хранилище";
            } else {
                lockScreen.querySelector('h2').textContent = "Введите пароль";
                pinBtn.textContent = "Разблокировать";
            }
        };
    }

    pinBtn.addEventListener('click', async () => {
         // Ждем готовности базы
        if (!db) {
            return Swal.fire({ icon: 'warning', title: 'Подождите', text: 'База данных еще загружается. Попробуйте через секунду.', background: '#1e1e1e', color: '#fff' });
        }
        const password = pinInput.value;
        if (password.length < CONFIG.MIN_PASSWORD_LENGTH) return Swal.fire({ icon: 'error', title: 'Ошибка', text: `Пароль должен быть минимум ${CONFIG.MIN_PASSWORD_LENGTH} символов!`, background: '#1e1e1e', color: '#fff' });

        const salt = await getOrCreateSalt();
        cryptoKey = await deriveKey(password, salt);

        const checkEncrypted = await new Promise(resolve => {
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
            unlockApp();
        } else {
            const decrypted = await decryptData(checkEncrypted);
            if (decrypted === "SUCCESS") unlockApp();
            else {
                Swal.fire({ icon: 'error', title: 'Ошибка', text: 'Неверный пароль!', background: '#1e1e1e', color: '#fff' });
                pinInput.value = '';
                cryptoKey = null;
            }
        }
    });

    pinInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') pinBtn.click(); });

    async function unlockApp() {
        lockScreen.classList.add('hidden');
        appScreen.classList.remove('hidden');
        checkRecurringOperations();
        loadTab('расходы');

        // Триггер 3: Проверяем, не созрели ли данные для прогноза
        const hasShownMaturityToast = localStorage.getItem('maturityToastShown');
        
        if (!hasShownMaturityToast) {
            const allExp = await new Promise(resolve => {
                const req = db.transaction(['expenses'], 'readonly').objectStore('expenses').getAll();
                req.onsuccess = () => resolve(req.result);
            });
            const allInc = await new Promise(resolve => {
                const req = db.transaction(['incomes'], 'readonly').objectStore('incomes').getAll();
                req.onsuccess = () => resolve(req.result);
            });
            const allGoals = await new Promise(resolve => {
                const req = db.transaction(['goals'], 'readonly').objectStore('goals').getAll();
                req.onsuccess = () => resolve(req.result);
            });

            if (allGoals.length > 0 && (allExp.length + allInc.length) > 10) {
                const allDates = [...allExp, ...allInc].map(r => new Date(r.date + 'T00:00:00').getTime());
                const oldestDate = new Date(Math.min(...allDates));
                const weeks = Math.floor((new Date() - oldestDate) / (1000 * 60 * 60 * 24 * 7));
                
                if (weeks >= 12) {
                    Swal.fire({
                        icon: 'success',
                        title: 'Данные готовы!',
                        text: 'Теперь мы можем проверить, реально ли достичь твоих целей. Загляни в Планер.',
                        toast: true, position: 'top-end', showConfirmButton: false, timer: 5000,
                        background: '#1e1e1e', color: '#fff'
                    });
                    localStorage.setItem('maturityToastShown', 'true');
                }
            }
        }
    }

    // --- 7. НАВИГАЦИЯ ---
    const navButtons = document.querySelectorAll('.top-nav button');
    navButtons.forEach(button => {
        button.addEventListener('click', () => loadTab(button.textContent.toLowerCase()));
    });

    function loadTab(tabName) {
        navButtons.forEach(btn => {
            btn.classList.remove('active');
            if (btn.textContent.toLowerCase() === tabName) btn.classList.add('active');
        });

        if (tabName === 'доходы') renderIncomesScreen();
        else if (tabName === 'расходы') renderExpensesScreen();
        else if (tabName === 'отчёт') renderReportScreen();
        else if (tabName === 'планер') renderPlannerScreen();
    }

    // --- 8. ДЕЙСТВИЯ (Удаление и Редактирование) ---
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
        }).then((result) => {
            if (result.isConfirmed) {
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

        const decryptedName = await decryptData(record.encryptedName);
        
        Swal.fire({
            title: 'Редактировать',
            html: `
                <input id="swal-name" class="swal2-input" placeholder="Комментарий" value="${decryptedName ? escapeHtml(decryptedName) : ''}">
                <input id="swal-amount" class="swal2-input" type="text" inputmode="decimal" placeholder="Сумма" value="${record.amount}">
                <input id="swal-date" class="swal2-input" type="date" value="${record.date}">
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
                    date: document.getElementById('swal-date').value
                };
            }
        }).then(async (result) => {
            if (result.isConfirmed) {
                const encryptedName = await encryptData(result.value.name);
                const tx = db.transaction([storeName], 'readwrite');
                const updatedRecord = { ...record, encryptedName, amount: result.value.amount, date: result.value.date };
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
    async function addExpenseToDB(name, amount, categoryId, mandatory, date, goalId = null) {
        if (!cryptoKey) return Swal.fire('Ошибка', 'Нет ключа', 'error');
        const encryptedName = await encryptData(name);

        const transaction = db.transaction(['expenses'], 'readwrite');
        transaction.objectStore('expenses').add({ encryptedName, amount, categoryId, mandatory, date, goalId });
        
        transaction.oncomplete = async () => {
            if (goalId) {
                const goal = await new Promise(resolve => {
                    const req = db.transaction(['goals'], 'readonly').objectStore('goals').get(goalId);
                    req.onsuccess = () => resolve(req.result);
                });
                if (goal) {
                    goal.saved = (goal.saved || 0) + amount;
                    const txGoal = db.transaction(['goals'], 'readwrite');
                    txGoal.objectStore('goals').put(goal);
                }
            }

            if (document.getElementById('exp-recurring') && document.getElementById('exp-recurring').checked) {
                const txRec = db.transaction(['recurring'], 'readwrite');
                txRec.objectStore('recurring').add({
                    type: 'expense', encryptedName, amount, categoryId, mandatory, freq: 'monthly',
                    dayOfMonth: new Date(date).getDate(),
                    lastRunMonth: getTodayLocal().slice(0, 7)
                });
                txRec.oncomplete = () => {
                    renderExpensesScreen();
                    Swal.fire({ icon: 'success', title: 'Расход добавлен', toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, background: '#1e1e1e', color: '#fff' });
                    checkFirstTriggers();
                };
            } else {
                renderExpensesScreen();
                Swal.fire({ icon: 'success', title: 'Расход добавлен', toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, background: '#1e1e1e', color: '#fff' });
                checkFirstTriggers();
            }
        };
    }

    // Триггер 1: После 5 записей
    async function checkFirstTriggers() {
        const countExp = await new Promise(resolve => {
            const req = db.transaction(['expenses'], 'readonly').objectStore('expenses').count();
            req.onsuccess = () => resolve(req.result);
        });
        const countInc = await new Promise(resolve => {
            const req = db.transaction(['incomes'], 'readonly').objectStore('incomes').count();
            req.onsuccess = () => resolve(req.result);
        });
        const total = countExp + countInc;

        if (total === 5) {
            Swal.fire({
                icon: 'info',
                title: 'Уже 5 записей!',
                text: 'Хочешь поставить первую финансовую цель? Мы будем отслеживать прогресс, а когда накопим данные — покажем прогноз.',
                toast: true, position: 'top-end', showConfirmButton: false, timer: 5000,
                background: '#1e1e1e', color: '#fff'
            });
        }
    }

    function renderExpensesScreen() {
        const tx = db.transaction(['categories', 'goals'], 'readonly');
        const reqCat = tx.objectStore('categories').getAll();
        const reqGoals = tx.objectStore('goals').getAll();

        tx.oncomplete = () => {
            const allCategories = reqCat.result;
            const allGoals = reqGoals.result;
            
            let optionsHTML = allCategories.filter(c => c.type === 'expense')
                .map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');

            mainContent.innerHTML = `
                <h2 style="text-align: center; margin-bottom: 20px;">Расходы</h2>
                <div style="background: #1e1e1e; padding: 15px; border-radius: 10px; margin-bottom: 20px;">
                    <input type="text" id="exp-name" placeholder="Комментарий" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <select id="exp-category" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">${optionsHTML}</select>
                    
                    <select id="exp-goal" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px; display: none;">
                        <option value="">Выберите цель...</option>
                        ${allGoals.map(g => `<option value="${g.id}">${escapeHtml(g.encryptedName)}</option>`).join('')}
                    </select>

                    <input type="text" data-money id="exp-amount" placeholder="Сумма (руб)" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;">
                    <input type="text" id="exp-date" placeholder="Дата" style="width: 100%; padding: 10px; margin-bottom: 10px; background: #121212; color: white; border: 1px solid #333; border-radius: 5px;" value="${getTodayLocal()}">
                    
                    <label style="display: flex; align-items: center; color: white; margin-bottom: 10px;">
                        <input type="checkbox" id="exp-mandatory" style="margin-right: 10px;"> Обязательный платеж
                    </label>
                    <label style="display: flex; align-items: center; color: white; margin-bottom: 10px;">
                        <input type="checkbox" id="exp-recurring" style="margin-right: 10px;"> Повторяющийся платеж (раз в месяц)
                    </label>
                    <button id="save-exp-btn" style="width: 100%; padding: 10px; background: #4CAF50; color: white; border: none; border-radius: 5px; font-size: 16px; margin-top: 10px;">Добавить расход</button>
                </div>
                <div id="expenses-list"><p style="color: #888;">Загрузка...</p></div>
            `;

            initFlatpickr("#exp-date", { defaultDate: getTodayLocal() });

            const expCategory = document.getElementById('exp-category');
            const expGoal = document.getElementById('exp-goal');
            expCategory.addEventListener('change', () => {
                const selectedCat = allCategories.find(c => c.id === parseInt(expCategory.value));
                if (selectedCat && selectedCat.name === 'Накопления') {
                    expGoal.style.display = 'block';
                } else {
                    expGoal.style.display = 'none';
                }
            });

            document.getElementById('save-exp-btn').addEventListener('click', () => {
                const name = document.getElementById('exp-name').value.trim() || "Без комментария";
                const amount = parseFloat(document.getElementById('exp-amount').value.replace(/\s/g, ''));
                const categoryId = parseInt(expCategory.value);
                const date = document.getElementById('exp-date').value;
                const goalId = expGoal.style.display !== 'none' && expGoal.value ? parseInt(expGoal.value) : null;

                if (isNaN(amount) || amount <= 0) return Swal.fire('Ошибка', 'Укажите сумму больше нуля!', 'error');
                addExpenseToDB(name, amount, categoryId, document.getElementById('exp-mandatory').checked, date, goalId);
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
        transaction.oncomplete = () => {
            renderIncomesScreen();
            Swal.fire({ icon: 'success', title: 'Доход добавлен', toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, background: '#1e1e1e', color: '#fff' });
            checkFirstTriggers();
        };
    }

    function renderIncomesScreen() {
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

            document.getElementById('save-inc-btn').addEventListener('click', () => {
                const name = document.getElementById('inc-name').value.trim() || "Без комментария";
                const amount = parseFloat(document.getElementById('inc-amount').value.replace(/\s/g, ''));
                const date = document.getElementById('inc-date').value;
                if (isNaN(amount) || amount <= 0) return Swal.fire('Ошибка', 'Укажите сумму!', 'error');
                addIncomeToDB(name, amount, parseInt(document.getElementById('inc-category').value), date);
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
    function renderReportScreen() {
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

            const weeklyTotals = {};
            const now = new Date();
            const currentWeekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const dayOfWeek = currentWeekStart.getDay() || 7;
            currentWeekStart.setDate(currentWeekStart.getDate() - dayOfWeek + 1);

            expenses.forEach(exp => {
                const expDate = new Date(exp.date + 'T00:00:00');
                const d = expDate.getDay() || 7;
                const monday = new Date(expDate);
                monday.setDate(expDate.getDate() - d + 1);
                const weekKey = monday.toISOString().slice(0, 10);
                
                if (!weeklyTotals[weekKey]) weeklyTotals[weekKey] = { total: 0, byCat: {} };
                weeklyTotals[weekKey].total += exp.amount;
                const catId = exp.categoryId || 0;
                weeklyTotals[weekKey].byCat[catId] = (weeklyTotals[weekKey].byCat[catId] || 0) + exp.amount;
            });

            const thisWeekKey = currentWeekStart.toISOString().slice(0, 10);
            const thisWeekData = weeklyTotals[thisWeekKey] || { total: 0, byCat: {} };
            
            const pastWeeksTotals = [];
            for (const key in weeklyTotals) {
                if (key !== thisWeekKey) pastWeeksTotals.push(weeklyTotals[key].total);
            }

            const medianWeekly = getMedian(pastWeeksTotals);
            let weeklyBlockHTML = '';
            let top3Deviated = [];

            if (pastWeeksTotals.length > 0 && medianWeekly > 0) {
                const diffPercent = ((thisWeekData.total - medianWeekly) / medianWeekly) * 100;
                let indicator = '';
                let bgColor = '#1e1e1e';
                let borderColor = '#333';
                
                if (diffPercent > 30) {
                    indicator = `<span style="color: #ffb86b;">▲ на ${Math.round(diffPercent)}%</span>`;
                    bgColor = '#3a2a1a';
                    borderColor = '#ffb86b';
                } else if (diffPercent < -30) {
                    indicator = `<span style="color: #3ddc84;">▼ на ${Math.round(Math.abs(diffPercent))}%</span>`;
                    bgColor = '#1a3a2a';
                    borderColor = '#3ddc84';
                } else {
                    indicator = `<span style="color: #888;">в норме</span>`;
                }

                for (const catId in thisWeekData.byCat) {
                    const catName = categories.find(c => c.id == catId)?.name || "Другое";
                    const catThisWeek = thisWeekData.byCat[catId];
                    
                    let sumPast = 0;
                    let weeksCount = 0;
                    for (const key in weeklyTotals) {
                        if (key !== thisWeekKey) {
                            const val = weeklyTotals[key].byCat[catId] || 0;
                            sumPast += val;
                            if (val > 0) weeksCount++;
                        }
                    }
                    const avgPast = weeksCount > 0 ? sumPast / weeksCount : 0;
                    
                    if (avgPast === 0 && catThisWeek > 0) {
                        top3Deviated.push({ name: catName, diff: catThisWeek, isNew: true });
                    } else if (avgPast > 0 && catThisWeek > avgPast * 1.5) {
                        top3Deviated.push({ name: catName, diff: catThisWeek - avgPast, isNew: false });
                    }
                }

                top3Deviated.sort((a, b) => b.diff - a.diff);
                top3Deviated = top3Deviated.slice(0, 3);

                weeklyBlockHTML = `
                    <div id="weekly-insight" style="background: ${bgColor}; border: 1px solid ${borderColor}; border-radius: 10px; padding: 12px; margin-bottom: 20px; cursor: pointer;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-size: 12px; color: #888;">Эта неделя</div>
                                <div style="font-size: 18px; font-weight: bold;">${formatMoney(thisWeekData.total)} ₽</div>
                            </div>
                            <div style="text-align: right;">
                                <div style="font-size: 12px; color: #888;">Обычно ${formatMoney(Math.round(medianWeekly))} ₽</div>
                                <div style="font-size: 14px; font-weight: bold;">${indicator}</div>
                            </div>
                        </div>
                    </div>
                `;
            }

            mainContent.innerHTML = `
                <h2 style="text-align: center;">Отчет</h2>
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="font-size: 14px; color: #888; margin-bottom: 5px;">Всего потрачено</div>
                    <div style="font-size: 28px; font-weight: bold; color: #ff5252;">${formatMoney(grandTotal)} ₽</div>
                </div>
                <div style="width: 220px; height: 220px; border-radius: 50%; margin: 0 auto 30px auto; background: conic-gradient(${gradientParts.join(', ')}); box-shadow: 0 4px 15px rgba(0,0,0,0.5);">
                    <div style="width: 120px; height: 120px; background: #121212; border-radius: 50%; position: relative; top: 50px; left: 50px;"></div>
                </div>
                ${weeklyBlockHTML}
                <div>${legendHTML}</div>
            `;

            const insightBlock = document.getElementById('weekly-insight');
            if (insightBlock) {
                insightBlock.addEventListener('click', () => {
                    if (top3Deviated.length === 0) {
                        Swal.fire({ 
                            title: 'Всё в норме!', 
                            text: 'На этой неделе нет категорий, которые сильно выбиваются из обычного ритма.', 
                            icon: 'success', 
                            background: '#1e1e1e', color: '#fff' 
                        });
                    } else {
                        let listHtml = '<div style="text-align: left; margin-top: 15px;">';
                        top3Deviated.forEach(c => {
                            const label = c.isNew ? '(новая трата)' : '';
                            listHtml += `<div style="padding: 8px 0; border-bottom: 1px solid #333; display: flex; justify-content: space-between;">
                                <span>${escapeHtml(c.name)} ${label}</span>
                                <span style="color: #ffb86b;">+${formatMoney(c.diff)} ₽</span>
                            </div>`;
                        });
                        listHtml += '</div>';
                        
                        Swal.fire({
                            title: 'Что выбилось?',
                            html: `<p style="color: #888;">Категории, где траты выше обычного:</p>${listHtml}`,
                            background: '#1e1e1e', color: '#fff', confirmButtonText: 'Понятно'
                        });
                    }
                });
            }
        };
    }

    // --- 12. ПЛАНЕР ---
    function renderPlannerScreen() {
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

            // Считаем, сколько недель данных есть в базе (от самой старой записи)
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
            `;

            html += `
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
                        sliderHtml = `
                            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #333; font-size: 13px; color: #ffb86b; text-align: center;">
                                Пока мало данных для прогноза. Продолжай записывать — через ${weeksLeft} нед. покажем, реально ли достичь цели.
                            </div>
                        `;
                    } else {
                        const maxSlider = Math.max(1000, Math.ceil(freeFlow * 1.5));
                        const defaultSlider = Math.min(Math.ceil(left / 12), maxSlider);
                        sliderHtml = `
                            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #333;">
                                <div style="display: flex; justify-content: space-between; font-size: 12px; color: #888; margin-bottom: 5px;">
                                    <span>Откладывать в месяц:</span>
                                    <span id="slider-val-${goal.id}" style="color: #7c5cff; font-weight: bold;">${formatMoney(defaultSlider)} ₽</span>
                                </div>
                                <input type="range" id="goal-slider-${goal.id}" min="0" max="${maxSlider}" step="1000" value="${defaultSlider}" style="width: 100%; cursor: pointer;">
                                <div id="goal-estimate-${goal.id}" style="font-size: 12px; color: #ffb86b; margin-top: 5px; text-align: center;"></div>
                            </div>
                        `;
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
                        </div>
                    `;
                }
                html += `<div id="goals-list">${goalsHtml}</div>`;
            }

            html += `
                <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; text-align: center;">
                    <h3 style="color: #888; font-size: 16px; margin-bottom: 15px;">Безопасность данных</h3>
                    <button id="export-btn" style="width: 100%; padding: 12px; background: #333; color: white; border: none; border-radius: 5px; margin-bottom: 10px;">💾 Скачать зашифрованный бэкап</button>
                    <input type="file" id="import-file" accept=".enc" style="display: none;">
                    <button id="import-btn" style="width: 100%; padding: 12px; background: #333; color: white; border: none; border-radius: 5px;">📂 Восстановить из бэкапа</button>
                </div>
            `;

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
                Swal.fire({
                    title: 'Вы уверены?', text: "Текущие данные будут заменены данными из бэкапа!", icon: 'warning',
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
                const name = document.getElementById('goal-name').value.trim();
                const amount = parseFloat(document.getElementById('goal-amount').value.replace(/\s/g, ''));
                const saved = parseFloat(document.getElementById('goal-saved').value.replace(/\s/g, '')) || 0;
                const deadline = document.getElementById('goal-deadline').value;

                if (!name || isNaN(amount) || amount <= 0) {
                    return Swal.fire({ icon: 'error', title: 'Ошибка', text: 'Заполните название и корректную стоимость', background: '#1e1e1e', color: '#fff' });
                }

                const encryptedName = await encryptData(name);
                const txAdd = db.transaction(['goals'], 'readwrite');
                txAdd.objectStore('goals').add({ encryptedName, amount, saved, deadline: deadline || null });
                txAdd.oncomplete = () => renderPlannerScreen();
            });
        };
    }

    // --- 13. АВТОМАТИЧЕСКИЕ ОПЕРАЦИИ ---
    async function checkRecurringOperations() {
        const templates = await new Promise((resolve, reject) => {
            const tx = db.transaction(['recurring'], 'readonly');
            const req = tx.objectStore('recurring').getAll();
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(tx.error);
        });

        const currentMonth = getTodayLocal().slice(0, 7);
        const toProcess = templates.filter(t => t.freq === 'monthly' && t.lastRunMonth !== currentMonth);
        
        if (toProcess.length === 0) return;

        const tx = db.transaction(['expenses', 'recurring'], 'readwrite');
        const expensesStore = tx.objectStore('expenses');
        const recurringStore = tx.objectStore('recurring');

        for (const tmpl of toProcess) {
            const day = String(tmpl.dayOfMonth || 1).padStart(2, '0');
            const effectiveDate = `${currentMonth}-${day}`;

            expensesStore.add({
                encryptedName: tmpl.encryptedName,
                amount: tmpl.amount,
                categoryId: tmpl.categoryId,
                mandatory: tmpl.mandatory,
                date: effectiveDate
            });

            tmpl.lastRunMonth = currentMonth;
            recurringStore.put(tmpl);
        }

        tx.oncomplete = () => console.log(`Создано повторяющихся платежей: ${toProcess.length}`);
        tx.onerror = (e) => console.error("Ошибка при создании повторяющихся платежей:", e.target.error);
    }

    // --- 14. ЭКСПОРТ И ИМПОРТ (БЭКАП) ---
    async function exportBackup() {
        try {
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

            const blob = new Blob([encryptedData], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `finance_backup_${getTodayLocal()}.enc`;
            a.click();
            URL.revokeObjectURL(url);

            Swal.fire({ icon: 'success', title: 'Бэкап создан', text: 'Файл зашифрован и скачан. Сохрани его в надежном месте.', background: '#1e1e1e', color: '#fff' });
        } catch (error) {
            console.error(error);
            Swal.fire({ icon: 'error', title: 'Ошибка экспорта', text: 'Не удалось создать бэкап.', background: '#1e1e1e', color: '#fff' });
        }
    }

    async function importBackup(file) {
        try {
            const encryptedData = await file.text();
            const decryptedJson = await decryptData(encryptedData);
            if (!decryptedJson) throw new Error("Неверный пароль или поврежденный файл");

            const backupData = JSON.parse(decryptedJson);

            const storesToClear = ['categories', 'expenses', 'incomes', 'goals', 'recurring'];
            for (const storeName of storesToClear) {
                await new Promise((resolve) => {
                    const tx = db.transaction([storeName], 'readwrite');
                    tx.objectStore(storeName).clear();
                    tx.oncomplete = () => resolve();
                });
            }

            for (const storeName of storesToClear) {
                if (backupData[storeName] && backupData[storeName].length > 0) {
                    const tx = db.transaction([storeName], 'readwrite');
                    const store = tx.objectStore(storeName);
                    backupData[storeName].forEach(item => store.put(item));
                    await new Promise(resolve => tx.oncomplete = resolve);
                }
            }

            Swal.fire({ icon: 'success', title: 'Импорт завершен', text: 'Данные успешно восстановлены.', background: '#1e1e1e', color: '#fff' })
                .then(() => renderExpensesScreen());

        } catch (error) {
            console.error(error);
            Swal.fire({ icon: 'error', title: 'Ошибка импорта', text: 'Файл поврежден или пароль не подходит.', background: '#1e1e1e', color: '#fff' });
        }
    }
});