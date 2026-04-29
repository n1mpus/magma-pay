function getCsrfToken() {
    const meta = document.querySelector("meta[name='csrf-token']");
    return meta ? String(meta.getAttribute("content") || "") : "";
}

function attachCsrfToForms() {
    const token = getCsrfToken();
    if (!token) return;
    const forms = Array.from(document.querySelectorAll("form[method='POST'], form[method='post']"));
    forms.forEach((form) => {
        if (form.querySelector("input[name='csrf_token']")) return;
        const hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "csrf_token";
        hidden.value = token;
        form.appendChild(hidden);
    });
}

function showToast(title, message, level = "info") {
    const stack = document.getElementById("toast-stack");
    if (!stack) return;
    const toast = document.createElement("article");
    toast.className = `toast ${level}`;
    toast.innerHTML = `<strong>${title}</strong><div>${message}</div>`;
    stack.prepend(toast);
    window.setTimeout(() => {
        toast.classList.add("fade-out");
        window.setTimeout(() => toast.remove(), 420);
    }, 5200);
}

function formatAmount(value) {
    const n = Number(value || 0);
    if (!Number.isFinite(n)) return "0";
    return Math.trunc(n).toLocaleString("ru-RU");
}

function hydrateDates() {
    const nodes = Array.from(document.querySelectorAll("[data-dt]"));
    nodes.forEach((node) => {
        const raw = node.getAttribute("data-dt");
        if (!raw) return;
        const parsed = new Date(raw);
        if (Number.isNaN(parsed.getTime())) return;
        const dd = String(parsed.getDate()).padStart(2, "0");
        const mm = String(parsed.getMonth() + 1).padStart(2, "0");
        const yyyy = parsed.getFullYear();
        const hh = String(parsed.getHours()).padStart(2, "0");
        const min = String(parsed.getMinutes()).padStart(2, "0");
        node.textContent = `${dd}.${mm}.${yyyy} · ${hh}:${min}`;
    });
}

function fadeFlashMessages() {
    const flashBox = document.getElementById("flash-messages");
    if (!flashBox) return;
    window.setTimeout(() => {
        flashBox.classList.add("fade-out");
        window.setTimeout(() => flashBox.remove(), 420);
    }, 5600);
}

function updateWithdrawPreview() {
    const amountInput = document.getElementById("withdraw-amount");
    const preview = document.getElementById("withdraw-preview");
    if (!amountInput || !preview) return;
    const amount = Number(amountInput.value || 0);
    const payout = Math.max(0, Math.floor(amount * 0.8));
    preview.textContent = `К выводу: ${payout} USDT`;
}

function updateTradeConfigSummary() {
    const wrap = document.querySelector(".trade-config");
    const spreadSlider = document.getElementById("spread-reduction");
    const spreadLabel = document.getElementById("spread-reduction-label");
    if (!wrap || !spreadSlider || !spreadLabel) return;

    const baseSpread = Number(wrap.dataset.spread || "0");
    const reduction = Math.max(0, Number(spreadSlider.value || 0));
    const effectiveSpread = Math.max(0, baseSpread - reduction);
    spreadLabel.textContent = `Приоритет: ${Math.round((reduction / 8) * 100)}% / снижение спреда: ${reduction.toFixed(1)}%`;
    wrap.dataset.effectiveSpread = effectiveSpread.toFixed(1);
}

function updateTradeOnlineState() {
    const checkbox = document.getElementById("exchange-enabled");
    const title = document.getElementById("online-title");
    const desc = document.getElementById("online-desc");
    const card = document.getElementById("trade-online-card");
    if (!checkbox || !title || !desc || !card) return;
    if (checkbox.checked) {
        title.textContent = "Вы онлайн";
        desc.textContent = "Вы получаете новые трейды";
        card.classList.add("is-online");
    } else {
        title.textContent = "Вы офлайн";
        desc.textContent = "Вы не получаете новых трейдов";
        card.classList.remove("is-online");
    }
}

function syncRequisiteInputMode() {
    const typeSelect = document.querySelector("[data-requisite-type]");
    const numberInput = document.querySelector("[data-requisite-number]");
    if (!typeSelect || !numberInput) return;
    const isPhone = typeSelect.value === "phone";
    numberInput.placeholder = isPhone ? "+7XXXXXXXXXX" : "0000000000000000";
    numberInput.maxLength = isPhone ? 12 : 19;
    numberInput.inputMode = "numeric";
}

function formatCountdown(targetDate) {
    const diffMs = targetDate.getTime() - Date.now();
    if (diffMs <= 0) return "00:00";
    const totalSec = Math.floor(diffMs / 1000);
    const min = Math.floor(totalSec / 60);
    const sec = totalSec % 60;
    return `${String(min).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
}

function startTradeCountdowns() {
    const nodes = Array.from(document.querySelectorAll("[data-expires-at]"));
    if (!nodes.length) return;

    function tick() {
        nodes.forEach((node) => {
            const raw = node.getAttribute("data-expires-at");
            if (!raw) return;
            const target = new Date(raw);
            if (Number.isNaN(target.getTime())) return;
            node.textContent = formatCountdown(target);
        });
    }

    tick();
    window.setInterval(tick, 1000);
}

function applyLiveState(payload) {
    if (!payload) return;
    const online = document.getElementById("online-pill");
    const spread = document.getElementById("spread-pill");
    const ratePill = document.getElementById("rate-pill");
    const rateLabel = document.getElementById("rate-label");
    const changePill = document.getElementById("change-pill");
    const mainBalance = document.getElementById("main-balance");
    const insuranceBalance = document.getElementById("insurance-balance");

    if (online) online.textContent = formatAmount(payload.online);
    if (spread) spread.textContent = `${payload.spread} %`;
    if (ratePill) ratePill.textContent = payload.rub_rate;
    if (rateLabel) rateLabel.textContent = payload.rate_label || `КУРС $ ${payload.rub_rate} ₽`;
    if (changePill) changePill.textContent = `${payload.rate_change}%`;
    if (mainBalance) mainBalance.textContent = `${formatAmount(payload.balance)} USDT`;
    if (insuranceBalance) insuranceBalance.textContent = `${formatAmount(payload.insurance_balance)} USDT`;

    if (Array.isArray(payload.notifications) && payload.notifications.length) {
        payload.notifications.forEach((item) => showToast(item.title, item.message, item.level || "info"));
        fetch("/api/notifications/read", {
            method: "POST",
            headers: {
                "X-CSRF-Token": getCsrfToken(),
            },
        }).catch(() => {});
    }
}

function startPolling() {
    const page = document.body.dataset.page;
    if (!page || page === "app") return;
    window.setInterval(() => {
        fetch("/api/live")
            .then((response) => {
                if (!response.ok) throw new Error("poll failed");
                return response.json();
            })
            .then(applyLiveState)
            .catch(() => {});
    }, 5000);
}

function appendSupportMessage(message) {
    const thread = document.getElementById("support-thread");
    if (!thread || !message) return;
    const bubble = document.createElement("article");
    bubble.className = `chat-bubble ${message.author_role}`;
    const author = message.author_role === "admin" ? "Поддержка" : "Вы";
    bubble.innerHTML = `<strong>${author}</strong><span>${message.text}</span>`;
    thread.appendChild(bubble);
}

function startSupportPolling() {
    const thread = document.getElementById("support-thread");
    if (!thread) return;
    window.setInterval(() => {
        const since = thread.dataset.lastId || "";
        fetch(`/api/support/messages?since=${encodeURIComponent(since)}`)
            .then((response) => {
                if (!response.ok) throw new Error("support poll failed");
                return response.json();
            })
            .then((payload) => {
                if (!payload || !Array.isArray(payload.messages)) return;
                payload.messages.forEach(appendSupportMessage);
                if (payload.last_id) {
                    thread.dataset.lastId = payload.last_id;
                }
                if (payload.messages.length) {
                    thread.scrollTop = thread.scrollHeight;
                }
            })
            .catch(() => {});
    }, 3000);
}

function escapeHtml(value) {
    return String(value || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function formatDateTime(raw) {
    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) return "";
    const dd = String(parsed.getDate()).padStart(2, "0");
    const mm = String(parsed.getMonth() + 1).padStart(2, "0");
    const yyyy = parsed.getFullYear();
    const hh = String(parsed.getHours()).padStart(2, "0");
    const min = String(parsed.getMinutes()).padStart(2, "0");
    return `${dd}.${mm}.${yyyy} · ${hh}:${min}`;
}

function startTradeLivePolling() {
    const list = document.getElementById("trade-active-list");
    if (!list) return;
    let prevSignature = "";
    function render(items) {
        if (!Array.isArray(items) || !items.length) {
            list.innerHTML = `<article class="empty-notice pulse-in"><strong>Нет активных трейдов</strong><span>Новые трейды появятся автоматически после распределения.</span></article>`;
            return;
        }
        list.innerHTML = items
            .map((item) => {
                const status = escapeHtml(item.status || "active");
                return `<article class="trade-entry pulse-in">
                    <div class="trade-left">
                        <div class="trade-amount">${formatAmount(item.amount_usdt)} <span>USDT</span></div>
                        <div class="trade-lines">
                            <span>${escapeHtml(item.bank)}</span>
                            <span>${escapeHtml(item.holder)}</span>
                            <span>${escapeHtml(item.number)}</span>
                            <span>Получаете в рублях: ${formatAmount(item.rub_amount_fixed)} ₽</span>
                        </div>
                    </div>
                    <div class="trade-right">
                        <div class="status-badge ${status}">${escapeHtml(status)}</div>
                        <div class="trade-timer" data-expires-at="${escapeHtml(item.expires_at)}">10:00</div>
                        <form action="/trade/${escapeHtml(item.id)}/confirm" method="POST">
                            <button type="submit">Подтвердить оплату вручную</button>
                        </form>
                    </div>
                </article>`;
            })
            .join("");
        attachCsrfToForms();
        startTradeCountdowns();
    }

    window.setInterval(() => {
        fetch("/api/trade/active")
            .then((r) => (r.ok ? r.json() : null))
            .then((payload) => {
                if (!payload || !Array.isArray(payload.active_trades)) return;
                const signature = payload.active_trades.map((x) => `${x.id}:${x.status}:${x.amount_usdt}`).join("|");
                if (signature !== prevSignature) {
                    prevSignature = signature;
                    render(payload.active_trades);
                }
            })
            .catch(() => {});
    }, 4000);
}

function startAdminLivePolling() {
    const requestsList = document.getElementById("admin-requests-list");
    const tradesList = document.getElementById("admin-active-trades-list");
    if (!requestsList || !tradesList) return;
    let prevReqSig = "";
    let prevTradeSig = "";

    function renderRequests(items) {
        if (!items.length) {
            requestsList.innerHTML = `<article class="empty-notice pulse-in"><strong>Новых заявок нет</strong><span>Очередь обновляется автоматически.</span></article>`;
            return;
        }
        requestsList.innerHTML = items
            .map((item) => {
                const status = escapeHtml(item.status || "");
                const isTradeActivation = String(item.type || "") === "trade_activation";
                const actions = isTradeActivation
                    ? `<form action="/admin/trade/create" method="POST" class="inline-form">
                            <input type="hidden" name="request_id" value="${escapeHtml(item.id)}">
                            <input type="number" name="amount_usdt" min="1" value="${Math.max(1, Number(item.amount_usdt || 0))}" required>
                            <button type="submit">Добавить трейд</button>
                       </form>
                       <form action="/admin/request/${escapeHtml(item.id)}/reject" method="POST">
                            <button type="submit" class="btn-danger">Отклонить</button>
                       </form>`
                    : `<form action="/admin/request/${escapeHtml(item.id)}/approve" method="POST">
                            <button type="submit">Одобрить</button>
                       </form>
                       <form action="/admin/request/${escapeHtml(item.id)}/reject" method="POST">
                            <button type="submit" class="btn-danger">Отклонить</button>
                       </form>`;
                return `<article class="admin-request pulse-in">
                    <div class="request-main"><strong>${escapeHtml(item.user)} / ${escapeHtml(item.type)}</strong><span>${formatDateTime(item.created_at)}</span></div>
                    <div class="status-badge ${status}">${status}</div>
                    <div>${formatAmount(item.amount_usdt)} USDT</div>
                    <div class="request-actions">${actions}</div>
                </article>`;
            })
            .join("");
        attachCsrfToForms();
    }

    function renderTrades(items) {
        if (!items.length) {
            tradesList.innerHTML = `<article class="empty-notice pulse-in"><strong>Нет активных трейдов</strong><span>После создания трейды появятся в этом блоке.</span></article>`;
            return;
        }
        tradesList.innerHTML = items
            .map((trade) => {
                const status = escapeHtml(trade.status || "active");
                return `<article class="trade-entry pulse-in">
                    <div class="trade-left">
                        <div class="trade-amount">${formatAmount(trade.amount_usdt)} <span>USDT</span></div>
                        <div class="trade-lines">
                            <span>${escapeHtml(trade.user)}</span>
                            <span>${escapeHtml(trade.bank)} / ${escapeHtml(trade.holder)}</span>
                            <span>${escapeHtml(trade.number)}</span>
                            <span>${formatDateTime(trade.created_at)}</span>
                        </div>
                    </div>
                    <div class="trade-right"><div class="status-badge ${status}">${status}</div></div>
                </article>`;
            })
            .join("");
    }

    window.setInterval(() => {
        fetch("/api/admin/live")
            .then((r) => (r.ok ? r.json() : null))
            .then((payload) => {
                if (!payload) return;
                const req = Array.isArray(payload.pending_requests) ? payload.pending_requests : [];
                const tr = Array.isArray(payload.active_trades) ? payload.active_trades : [];
                const reqSig = req.map((x) => `${x.id}:${x.status}`).join("|");
                const trSig = tr.map((x) => `${x.id}:${x.status}:${x.amount_usdt}`).join("|");
                if (reqSig !== prevReqSig) {
                    prevReqSig = reqSig;
                    renderRequests(req);
                }
                if (trSig !== prevTradeSig) {
                    prevTradeSig = trSig;
                    renderTrades(tr);
                }
            })
            .catch(() => {});
    }, 4000);
}

function initAdminUserSearch() {
    const input = document.getElementById("admin-user-search");
    const list = document.getElementById("admin-users-list");
    if (!input || !list) return;
    const cards = Array.from(list.querySelectorAll(".admin-user[data-email]"));
    input.addEventListener("input", () => {
        const query = String(input.value || "").trim().toLowerCase();
        cards.forEach((card) => {
            const email = String(card.getAttribute("data-email") || "").toLowerCase();
            card.style.display = query === "" || email.includes(query) ? "" : "none";
        });
    });
}

function initManualTradePreview() {
    const form = document.getElementById("admin-manual-trade-form");
    const userSelect = document.getElementById("manual-trade-email");
    const amountInput = document.getElementById("manual-trade-amount");
    const usdtNode = document.getElementById("manual-preview-usdt");
    const rubNode = document.getElementById("manual-preview-rub");
    const balanceNode = document.getElementById("manual-preview-balance");
    if (!form || !userSelect || !amountInput || !usdtNode || !rubNode || !balanceNode) return;

    const rate = Number(form.dataset.rate || "0");
    const spread = Number(form.dataset.spread || "0");

    function update() {
        const amount = Math.max(0, Number(amountInput.value || "0"));
        const selected = userSelect.options[userSelect.selectedIndex];
        const balance = Number(selected ? selected.getAttribute("data-balance") : 0);
        const rub = Math.round(amount * rate * (1 + spread / 100));
        usdtNode.textContent = `${formatAmount(amount)} USDT`;
        rubNode.textContent = `${formatAmount(rub)} ₽`;
        balanceNode.textContent = `${formatAmount(balance)} USDT`;
    }

    amountInput.addEventListener("input", update);
    userSelect.addEventListener("change", update);
    update();
}

function initPasswordToggles() {
    const buttons = Array.from(document.querySelectorAll("[data-password-toggle-btn]"));
    buttons.forEach((btn) => {
        const wrap = btn.closest(".password-wrap");
        const input = wrap ? wrap.querySelector("[data-password-toggle]") : null;
        if (!input) return;
        function syncVisibility() {
            const hasValue = String(input.value || "").length > 0;
            wrap.classList.toggle("has-value", hasValue);
            if (!hasValue) {
                input.type = "password";
                btn.textContent = "Показать";
            }
        }
        input.addEventListener("input", syncVisibility);
        input.addEventListener("blur", syncVisibility);
        btn.addEventListener("click", () => {
            const isHidden = input.type === "password";
            input.type = isHidden ? "text" : "password";
            btn.textContent = isHidden ? "Скрыть" : "Показать";
        });
        syncVisibility();
    });
}

document.addEventListener("DOMContentLoaded", () => {
    attachCsrfToForms();

    const withdrawInput = document.getElementById("withdraw-amount");
    if (withdrawInput) {
        withdrawInput.addEventListener("input", updateWithdrawPreview);
        updateWithdrawPreview();
    }

    const spreadReduction = document.getElementById("spread-reduction");
    if (spreadReduction) {
        spreadReduction.addEventListener("input", updateTradeConfigSummary);
        updateTradeConfigSummary();
    }

    const tradeEnabled = document.getElementById("exchange-enabled");
    if (tradeEnabled) {
        tradeEnabled.addEventListener("change", updateTradeOnlineState);
        updateTradeOnlineState();
    }

    const reqType = document.querySelector("[data-requisite-type]");
    if (reqType) {
        reqType.addEventListener("change", syncRequisiteInputMode);
        syncRequisiteInputMode();
    }

    startTradeCountdowns();
    hydrateDates();
    fadeFlashMessages();
    startPolling();
    startSupportPolling();
    startTradeLivePolling();
    startAdminLivePolling();
    initAdminUserSearch();
    initManualTradePreview();
    initPasswordToggles();
});
