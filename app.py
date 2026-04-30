import copy
import datetime as dt
import json
import os
import random
import re
import secrets
import time
import uuid
from functools import wraps
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data.json"

NETWORKS = ["TRC20", "TON"]
NETWORK_LABELS = {"TRC20": "USDT TRC-20", "TON": "USDT TON"}
DEPOSIT_ADDRESSES = {
    "TRC20": "TXp7J9magmaUsdtTrc20DemoAddr381",
    "TON": "UQDNmagmaUsdtTonDemoAddress291x",
}
WITHDRAW_FEE = 0.20
COINGECKO_SIMPLE_PRICE_URL = "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=rub"
BANK_OPTIONS = [
    "Сбербанк",
    "ВТБ",
    "Газпромбанк",
    "Альфа-Банк",
    "Промсвязьбанк",
    "Россельхозбанк",
    "Московский кредитный банк",
    "Совкомбанк",
    "Т-Банк",
    "Банк ДОМ.РФ",
    "Почта Банк",
    "МТС Банк",
    "Открытие",
    "Росбанк",
    "УБРиР",
    "Ренессанс Банк",
    "Хоум Банк",
    "Банк Санкт-Петербург",
    "Ак Барс Банк",
    "ТрансКапиталБанк",
    "БКС Банк",
    "Экспобанк",
    "Кредит Европа Банк",
    "Русский Стандарт",
    "Ингосстрах Банк",
    "Локо-Банк",
    "Металлинвестбанк",
    "Новикомбанк",
    "Абсолют Банк",
    "Зенит",
    "Синара Банк",
    "Азиатско-Тихоокеанский Банк",
    "Примсоцбанк",
    "Дальневосточный банк",
    "Солидарность",
    "Центр-инвест",
    "Банк Россия",
    "Кубань Кредит",
    "Челиндбанк",
    "Банк Хлынов",
    "Таврический",
    "Форштадт",
    "БЖФ Банк",
    "СДМ-Банк",
    "Генбанк",
    "Севергазбанк",
    "Инвестторгбанк",
    "Еврофинанс Моснарбанк",
    "РНКБ",
    "Киви Банк",
    "ЮниКредит Банк",
    "Райффайзен Банк",
    "Ситибанк",
]

REQUEST_TYPE_LABELS = {
    "deposit": "Пополнение",
    "insurance": "Пополнение страхового баланса",
    "insurance_payment": "Оплата страхового баланса",
    "sell_usdt": "Обмен USDT to Fiat",
    "withdraw_usdt": "Вывод USDT",
    "withdraw": "Вывод USDT",
}

REQUEST_STATUS_LABELS = {
    "pending_payment": "Ожидает оплаты",
    "pending_review": "В обработке",
    "approved": "Одобрено",
    "completed": "Выполнено",
    "rejected": "Отклонено",
    "open": "Открыт",
    "blocked": "Заблокирован",
    "active": "Активен",
}


ONLINE_THRESHOLD_SECONDS = 120
AUTH_RATE_LIMIT_WINDOW_SEC = 900
AUTH_RATE_LIMIT_LOGIN_MAX = 8
AUTH_RATE_LIMIT_REGISTER_MAX = 5
AUTH_RATE_BUCKETS = {"login": {}, "register": {}}

# Override labels with clean Russian texts.
REQUEST_TYPE_LABELS = {
    "deposit": "Пополнение",
    "insurance": "Пополнение страхового баланса",
    "insurance_payment": "Оплата страхового баланса",
    "sell_usdt": "Обмен USDT to RUB",
    "withdraw_usdt": "Вывод USDT",
    "withdraw": "Вывод USDT",
    "trade_activation": "Запрос трейдинга",
    "trade_manual": "Ручной трейд",
}

REQUEST_STATUS_LABELS = {
    "pending_payment": "Ожидает оплаты",
    "pending_review": "В обработке",
    "approved": "Одобрено",
    "completed": "Выполнено",
    "rejected": "Отклонено",
    "open": "Открыт",
    "blocked": "Заблокирован",
    "active": "Активен",
    "user_confirmed": "Подтверждено пользователем",
    "expired": "Истек",
}


MSK_TZ = dt.timezone(dt.timedelta(hours=3), name="MSK")


def now_utc():
    return dt.datetime.now(MSK_TZ)


def now_iso():
    return now_utc().isoformat()


def is_user_online(user):
    last_seen = user.get("last_seen_at")
    if not last_seen:
        return False
    try:
        seen_at = dt.datetime.fromisoformat(last_seen)
    except ValueError:
        return False
    return (now_utc() - seen_at).total_seconds() <= ONLINE_THRESHOLD_SECONDS


def safe_int(value, default=0):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def client_ip():
    forwarded = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.remote_addr or "unknown").strip()


def is_rate_limited(scope, key, limit, window_sec):
    bucket = AUTH_RATE_BUCKETS.setdefault(scope, {})
    now_ts = time.time()
    attempts = bucket.get(key, [])
    attempts = [ts for ts in attempts if now_ts - ts <= window_sec]
    bucket[key] = attempts
    return len(attempts) >= limit


def mark_rate_limit(scope, key):
    bucket = AUTH_RATE_BUCKETS.setdefault(scope, {})
    now_ts = time.time()
    attempts = bucket.get(key, [])
    attempts = [ts for ts in attempts if now_ts - ts <= AUTH_RATE_LIMIT_WINDOW_SEC]
    attempts.append(now_ts)
    bucket[key] = attempts


def clear_rate_limit(scope, key):
    bucket = AUTH_RATE_BUCKETS.setdefault(scope, {})
    bucket.pop(key, None)


def get_deposit_address(network, state=None):
    # During startup `STATE` may not be initialized yet, so read from explicit state first.
    source_state = state if isinstance(state, dict) else globals().get("STATE", {})
    dynamic = source_state.get("settings", {}).get("deposit_addresses", {})
    address = (dynamic.get(network) or "").strip()
    if address:
        return address
    return DEPOSIT_ADDRESSES.get(network, "")


def fetch_usdt_rub_from_coingecko():
    req = Request(COINGECKO_SIMPLE_PRICE_URL, headers={"User-Agent": "MagmaPay/1.0"})
    try:
        with urlopen(req, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return None

    value = safe_float(payload.get("tether", {}).get("rub"), 0.0)
    if value <= 0:
        return None
    return round(value, 2)


def insurance_required_for_user(user):
    global_minimum = max(safe_int(STATE["settings"].get("insurance_minimum"), 0), 0)
    override = user.get("insurance_minimum_override")
    if override in (None, ""):
        return global_minimum
    return max(safe_int(override, global_minimum), 0)


def insurance_is_paid(user):
    required = insurance_required_for_user(user)
    if required <= 0:
        return True
    paid_value = max(safe_int(user.get("insurance_paid_value"), 0), 0)
    return paid_value >= required


def normalize_runtime_settings(settings):
    settings["online"] = max(0, safe_int(settings.get("online"), 0))
    settings["online_variation"] = max(0, min(5000, safe_int(settings.get("online_variation"), 7)))
    settings["spread_percent"] = round(max(0.1, min(25, safe_float(settings.get("spread_percent"), 3.6))), 2)
    settings["insurance_default"] = max(safe_int(settings.get("insurance_default"), 100), 0)
    settings["insurance_minimum"] = max(safe_int(settings.get("insurance_minimum"), settings["insurance_default"]), 0)
    settings["rub_rate"] = round(max(40, min(300, safe_float(settings.get("rub_rate"), 92.4))), 2)
    settings["rate_change"] = round(max(-3.0, min(3.0, safe_float(settings.get("rate_change"), 0.0))), 2)
    if not isinstance(settings.get("deposit_addresses"), dict):
        settings["deposit_addresses"] = {}
    settings["deposit_addresses"]["TRC20"] = (settings["deposit_addresses"].get("TRC20") or DEPOSIT_ADDRESSES["TRC20"]).strip()
    settings["deposit_addresses"]["TON"] = (settings["deposit_addresses"].get("TON") or DEPOSIT_ADDRESSES["TON"]).strip()


def sync_market_rate_if_needed(settings, min_interval_sec=30):
    now_stamp = now_utc().timestamp()
    last_sync = safe_float(settings.get("rate_synced_at"), 0.0)
    if now_stamp - last_sync < min_interval_sec:
        return False

    market_rate = fetch_usdt_rub_from_coingecko()
    if market_rate is None:
        return False

    current_rate = safe_float(settings.get("rub_rate"), market_rate)
    next_rate = current_rate + (market_rate - current_rate) * 0.65
    settings["rub_rate"] = round(max(40, min(300, next_rate)), 2)
    if current_rate > 0:
        settings["rate_change"] = round(((settings["rub_rate"] - current_rate) / current_rate) * 100, 2)
    settings["rate_synced_at"] = now_stamp
    normalize_runtime_settings(settings)
    return True


DEFAULT_STATE = {
    "users": {
        "admin@magma.com": {
            "password_hash": generate_password_hash("admin"),
            "role": "admin",
            "status": "active",
            "balance": 0,
            "insurance_balance": 25000,
            "insurance_paid": True,
            "insurance_paid_value": 25000,
            "spread_profit": 0,
            "theme": "cyber",
            "trade_online": False,
            "trade_minimum_rub": 300,
            "trade_spread_reduction": 0.0,
            "trade_requisite_id": "",
            "created_at": "2026-04-22T00:00:00+00:00",
            "last_seen_at": None,
        },
        "test@magma.com": {
            "password_hash": generate_password_hash("123456"),
            "role": "user",
            "status": "active",
            "balance": 24680,
            "insurance_balance": 12000,
            "insurance_paid": True,
            "insurance_paid_value": 12000,
            "spread_profit": 3260,
            "theme": "cyber",
            "trade_online": False,
            "trade_minimum_rub": 300,
            "trade_spread_reduction": 0.0,
            "trade_requisite_id": "reqdemo001",
            "created_at": "2026-04-22T00:00:00+00:00",
            "last_seen_at": None,
        },
        "fresh@magma.com": {
            "password_hash": generate_password_hash("123456"),
            "role": "user",
            "status": "active",
            "balance": 0,
            "insurance_balance": 0,
            "insurance_paid": False,
            "insurance_paid_value": 0,
            "spread_profit": 0,
            "theme": "cyber",
            "trade_online": False,
            "trade_minimum_rub": 300,
            "trade_spread_reduction": 0.0,
            "trade_requisite_id": "",
            "created_at": "2026-04-22T00:00:00+00:00",
            "last_seen_at": None,
        },
    },
    "requisites": [],
    "requests": [],
    "notifications": [],
    "support_threads": [],
    "disputes": [],
    "trades": [],
    "admin_logs": [],
        "settings": {
        "online": 1284,
        "online_variation": 7,
        "spread_percent": 3.6,
        "rub_rate": 92.4,
        "rate_change": 1.18,
        "deposit_min": 100,
        "deposit_max": 500000,
        "withdraw_min": 50,
        "withdraw_max": 100000,
        "fiat_min": 300,
        "fiat_max": 300000,
        "insurance_default": 100,
        "insurance_minimum": 100,
        "rate_synced_at": None,
        "deposit_addresses": {
            "TRC20": DEPOSIT_ADDRESSES["TRC20"],
            "TON": DEPOSIT_ADDRESSES["TON"],
        },
    },
}


def save_state(state):
    DATA_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def append_notification(state, email, title, message, level="info"):
    item = {
        "id": uuid.uuid4().hex[:12],
        "user": email,
        "title": title,
        "message": message,
        "level": level,
        "created_at": now_iso(),
        "read": False,
    }
    state["notifications"].insert(0, item)
    state["notifications"] = state["notifications"][:400]
    return item


def append_admin_log(state, admin_email, action, target=None, meta=None):
    item = {
        "id": uuid.uuid4().hex[:12],
        "admin": admin_email,
        "action": action,
        "target": target,
        "meta": meta or {},
        "created_at": now_iso(),
    }
    state["admin_logs"].insert(0, item)
    state["admin_logs"] = state["admin_logs"][:400]
    return item


def append_request(state, email, request_type, amount_usdt, status, meta=None):
    item = {
        "id": uuid.uuid4().hex[:12],
        "user": email,
        "type": request_type,
        "amount_usdt": amount_usdt,
        "status": status,
        "created_at": now_iso(),
        "meta": meta or {},
    }
    state["requests"].insert(0, item)
    state["requests"] = state["requests"][:600]
    return item


def calculate_trade_rub(amount_usdt, spread_percent, rub_rate):
    base = safe_float(amount_usdt, 0.0) * safe_float(rub_rate, 0.0) * (1 + safe_float(spread_percent, 0.0) / 100.0)
    fixed = int(round(base))
    return max(0, fixed + random.randint(1, 9))


def append_support_message(state, email, author_role, text):
    thread = next((x for x in state["support_threads"] if x["user"] == email), None)
    if not thread:
        thread = {
            "id": uuid.uuid4().hex[:12],
            "user": email,
            "status": "open",
            "created_at": now_iso(),
            "messages": [],
        }
        state["support_threads"].insert(0, thread)

    message = {
        "id": uuid.uuid4().hex[:12],
        "author_role": author_role,
        "text": text[:500],
        "created_at": now_iso(),
    }
    thread["messages"].append(message)
    return thread, message


def normalize_user(raw_user):
    password_hash = raw_user.get("password_hash")
    if not password_hash and raw_user.get("password"):
        password_hash = generate_password_hash(str(raw_user["password"]))
    insurance_balance = safe_int(raw_user.get("insurance_balance"), 0)
    insurance_paid_value = safe_int(raw_user.get("insurance_paid_value"), 0)
    insurance_paid = raw_user.get("insurance_paid")
    if insurance_paid_value <= 0 and insurance_paid:
        insurance_paid_value = insurance_balance
    if insurance_paid_value <= 0:
        insurance_balance = 0
    else:
        insurance_balance = insurance_paid_value
    return {
        "password_hash": password_hash or generate_password_hash("123456"),
        "role": raw_user.get("role", "user"),
        "status": raw_user.get("status", "active"),
        "balance": safe_int(raw_user.get("balance"), 0),
        "insurance_balance": insurance_balance,
        "insurance_paid": bool(insurance_paid_value > 0),
        "insurance_paid_value": insurance_paid_value,
        "insurance_minimum_override": (
            None if raw_user.get("insurance_minimum_override") in (None, "") else max(0, safe_int(raw_user.get("insurance_minimum_override"), 0))
        ),
        "spread_profit": safe_int(raw_user.get("spread_profit"), 0),
        "theme": raw_user.get("theme", "cyber"),
        "trade_online": bool(raw_user.get("trade_online", False)),
        "trade_minimum_rub": max(1, safe_int(raw_user.get("trade_minimum_rub", raw_user.get("trade_minimum", 300)))),
        "trade_spread_reduction": round(min(8.0, max(0.0, safe_float(raw_user.get("trade_spread_reduction"), 0.0))), 1),
        "trade_requisite_id": (raw_user.get("trade_requisite_id") or ""),
        "last_ip": raw_user.get("last_ip"),
        "last_user_agent": raw_user.get("last_user_agent"),
        "created_at": raw_user.get("created_at") or now_iso(),
        "last_seen_at": raw_user.get("last_seen_at"),
    }


def seed_demo_data(state):
    if not state["requisites"]:
        state["requisites"] = [
            {
                "id": "reqdemo001",
                "user": "test@magma.com",
                "label": "Основная карта",
                "bank": "T-Bank",
                "holder": "A. Client",
                "number": "22007001****1842",
                "limit_rub": 60000,
                "status": "active",
                "created_at": "2026-04-22T08:12:00+00:00",
            }
        ]

    if not state["requests"]:
        append_request(
            state,
            "test@magma.com",
            "deposit",
            350,
            "completed",
            {"network": "TRC20", "wallet_address": get_deposit_address("TRC20")},
        )
        append_request(
            state,
            "test@magma.com",
            "sell_usdt",
            220,
            "pending_review",
            {
                "requisite_id": "reqdemo001",
                "bank": "T-Bank",
                "holder": "A. Client",
                "rub_amount": 19685,
            },
        )
        append_request(
            state,
            "test@magma.com",
            "withdraw_usdt",
            85,
            "approved",
            {
                "network": "TON",
                "wallet": "UQBy-demo-withdraw-wallet-001",
                "fee_usdt": 1,
            },
        )

    if not state["notifications"]:
        append_notification(
            state,
            "test@magma.com",
            "Новая заявка",
            "Администратор получил вашу заявку на продажу USDT за RUB.",
            "info",
        )

    if not state["support_threads"]:
        thread, _ = append_support_message(
            state,
            "test@magma.com",
            "user",
            "Здравствуйте, подскажите по сроку одобрения заявки USDT to Fiat.",
        )
        thread["messages"].append(
            {
                "id": uuid.uuid4().hex[:12],
                "author_role": "admin",
                "text": "Проверяем заявку, ответим в течение нескольких минут.",
                "created_at": now_iso(),
            }
        )

    if not state["disputes"]:
        state["disputes"] = [
            {
                "id": "dispdemo001",
                "user": "test@magma.com",
                "request_id": "manual-demo-request",
                "status": "open",
                "reason": "Задержка подтверждения сделки",
                "created_at": now_iso(),
            }
        ]


def load_state():
    state = copy.deepcopy(DEFAULT_STATE)

    if DATA_FILE.exists():
        try:
            # `utf-8-sig` safely handles files saved with BOM (common on Windows/PowerShell).
            raw = json.loads(DATA_FILE.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            raw = {}
    else:
        raw = {}

    if isinstance(raw.get("users"), dict):
        for email, user in raw["users"].items():
            if isinstance(user, dict):
                state["users"][email.strip().lower()] = normalize_user(user)

    for key in ("requisites", "requests", "notifications", "support_threads", "disputes", "trades", "admin_logs"):
        if isinstance(raw.get(key), list):
            state[key] = raw[key]

    if isinstance(raw.get("settings"), dict):
        state["settings"].update(raw["settings"])
    normalize_runtime_settings(state["settings"])

    seed_demo_data(state)
    save_state(state)
    return state


STATE = load_state()

app = Flask(__name__)
app.secret_key = os.getenv("MAGMA_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("MAGMA_SECURE_COOKIE") == "1"
app.config["SESSION_COOKIE_NAME"] = "magma_sid"
app.config["PERMANENT_SESSION_LIFETIME"] = dt.timedelta(hours=12)


@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    if request.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.before_request
def csrf_guard():
    if request.method != "POST":
        return None
    if request.endpoint in {"static"}:
        return None
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("csrf_token")
    if not expected or not sent or sent != expected:
        return ("CSRF validation failed", 400)
    return None


def current_user_email():
    return session.get("user")


def current_user():
    email = current_user_email()
    if not email:
        return None
    return STATE["users"].get(email)


def update_presence(email):
    user = STATE["users"].get(email)
    if user:
        user["last_seen_at"] = now_iso()
        user["last_ip"] = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        user["last_user_agent"] = request.headers.get("User-Agent", "")[:220]
        save_state(STATE)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth_required"}), 401
            flash("Авторизуйтесь, чтобы продолжить.", "error")
            return redirect(url_for("login"))
        if user.get("status") == "blocked":
            session.clear()
            flash("Аккаунт заблокирован администратором.", "error")
            return redirect(url_for("login"))
        update_presence(current_user_email())
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_user().get("role") != "admin":
            flash("Доступ только для администратора.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


def user_requests(email, limit=50):
    return [x for x in STATE["requests"] if x["user"] == email][:limit]


def user_requisites(email):
    return [x for x in STATE["requisites"] if x["user"] == email]


def unread_notifications(email):
    return [x for x in STATE["notifications"] if x["user"] == email and not x["read"]]


def user_support_thread(email):
    return next((x for x in STATE["support_threads"] if x["user"] == email), None)


def analytics_snapshot():
    requests = STATE["requests"]
    platform_income = 0
    for item in requests:
        if item.get("type") == "withdraw_usdt" and item.get("status") in {"approved", "completed"}:
            platform_income += max(0, safe_int(item.get("meta", {}).get("fee_usdt"), 0))
        if item.get("type") == "trade_manual" and item.get("status") == "completed":
            platform_income += max(0, safe_int(item.get("meta", {}).get("platform_income_usdt"), 0))
    return {
        "deposit_volume": sum(x["amount_usdt"] for x in requests if x["type"] == "deposit"),
        "withdraw_volume": sum(x["amount_usdt"] for x in requests if x["type"] == "withdraw_usdt"),
        "fiat_volume": sum(x["amount_usdt"] for x in requests if x["type"] in {"sell_usdt", "trade_manual"}),
        "platform_income": platform_income,
        "pending_requests": len([x for x in requests if x["status"] in {"pending_payment", "pending_review"}]),
        "open_support": len([x for x in STATE["support_threads"] if x["status"] == "open"]),
        "open_disputes": len([x for x in STATE["disputes"] if x["status"] == "open"]),
        "series": [
            {"day": (dt.date.today() - dt.timedelta(days=offset)).isoformat(), "volume": random.randint(25, 96)}
            for offset in range(6, -1, -1)
        ],
    }


@app.context_processor
def inject_globals():
    normalize_runtime_settings(STATE["settings"])
    if sync_market_rate_if_needed(STATE["settings"], min_interval_sec=60):
        save_state(STATE)
    user = current_user()
    return {
        "brand_name": "MAGMA PAY",
        "current_user": user,
        "active_theme": (user.get("theme", "cyber") if user else "cyber"),
        "csrf_token": get_csrf_token(),
        "settings": STATE["settings"],
        "network_labels": NETWORK_LABELS,
        "bank_options": BANK_OPTIONS,
    }


@app.template_filter("req_type_label")
def req_type_label(value):
    return REQUEST_TYPE_LABELS.get(value, value)


@app.template_filter("req_status_label")
def req_status_label(value):
    return REQUEST_STATUS_LABELS.get(value, value)


@app.template_filter("amount_fmt")
def amount_fmt(value):
    number = safe_int(value, 0)
    return f"{number:,}".replace(",", " ")


@app.template_filter("dt_fmt")
def dt_fmt(value):
    if not value:
        return "—"
    text = str(value)
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=MSK_TZ)
    else:
        parsed = parsed.astimezone(MSK_TZ)
    return parsed.strftime("%d.%m.%Y · %H:%M")
    return parsed.strftime("%d.%m.%Y · %H:%M")


@app.route("/")
def root():
    return redirect(url_for("dashboard" if current_user() else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        register_key = f"{client_ip()}|{email}"
        if is_rate_limited("register", register_key, AUTH_RATE_LIMIT_REGISTER_MAX, AUTH_RATE_LIMIT_WINDOW_SEC):
            flash("Слишком много попыток регистрации. Повторите позже.", "error")
            return render_template("login.html", register_mode=True)
        if not email or "@" not in email:
            mark_rate_limit("register", register_key)
            flash("Укажите корректный email.", "error")
        elif len(password) < 6:
            mark_rate_limit("register", register_key)
            flash("Пароль должен быть не короче 6 символов.", "error")
        elif password != confirm:
            mark_rate_limit("register", register_key)
            flash("Пароли не совпадают.", "error")
        elif email in STATE["users"]:
            mark_rate_limit("register", register_key)
            flash("Такой пользователь уже существует.", "error")
        else:
            STATE["users"][email] = {
                "password_hash": generate_password_hash(password),
                "role": "user",
                "status": "active",
                "balance": 0,
                "insurance_balance": 0,
                "insurance_paid": False,
                "insurance_paid_value": 0,
                "insurance_minimum_override": None,
                "spread_profit": 0,
                "theme": "cyber",
                "trade_online": False,
                "trade_minimum_rub": max(1, safe_int(STATE["settings"].get("fiat_min"), 300)),
                "trade_spread_reduction": 0.0,
                "trade_requisite_id": "",
                "last_ip": None,
                "last_user_agent": None,
                "created_at": now_iso(),
                "last_seen_at": None,
            }
            append_notification(STATE, email, "Аккаунт создан", "Добро пожаловать в MAGMA PAY.", "success")
            save_state(STATE)
            clear_rate_limit("register", register_key)
            flash("Регистрация завершена.", "success")
            return redirect(url_for("login"))
    return render_template("login.html", register_mode=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        login_key = f"{client_ip()}|{email}"
        if is_rate_limited("login", login_key, AUTH_RATE_LIMIT_LOGIN_MAX, AUTH_RATE_LIMIT_WINDOW_SEC):
            flash("Слишком много попыток входа. Повторите позже.", "error")
            return render_template("login.html", register_mode=False)
        user = STATE["users"].get(email)
        if not user or not check_password_hash(user["password_hash"], password):
            mark_rate_limit("login", login_key)
            append_admin_log(STATE, "system", "auth_failed_password", email, {"ip": client_ip()})
            save_state(STATE)
            flash("Неверный email или пароль.", "error")
        else:
            session.clear()
            session["user"] = email
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            session["counted_online"] = True
            update_presence(email)
            normalize_runtime_settings(STATE["settings"])
            STATE["settings"]["online"] = max(0, safe_int(STATE["settings"].get("online"), 0) + 1)
            clear_rate_limit("login", login_key)
            append_admin_log(STATE, "system", "auth_success", email, {"ip": client_ip()})
            save_state(STATE)
            flash("Вход выполнен.", "success")
            return redirect(url_for("dashboard"))
    return render_template("login.html", register_mode=False)


@app.route("/dashboard")
@login_required
def dashboard():
    email = current_user_email()
    return render_template(
        "dashboard.html",
        active_nav="dashboard",
        user=current_user(),
        requests=user_requests(email, limit=4),
        notifications=unread_notifications(email)[:4],
        analytics=analytics_snapshot(),
    )


@app.route("/requisites")
@login_required
def requisites_page():
    return render_template(
        "requisites.html",
        active_nav="requisites",
        requisites=user_requisites(current_user_email()),
    )


@app.route("/requisites/create", methods=["POST"])
@login_required
def requisites_create():
    label = request.form.get("label", "").strip()
    bank = request.form.get("bank", "").strip()
    holder = request.form.get("holder", "").strip()
    number_type = request.form.get("number_type", "card").strip()
    number = request.form.get("number", "").strip()
    raw_limit = request.form.get("limit_rub", "").strip()
    limit_rub = None if raw_limit == "" else safe_int(raw_limit)
    if not label or not bank or not holder:
        flash("Заполните все поля реквизита.", "error")
    elif bank not in BANK_OPTIONS:
        flash("Выберите банк из списка.", "error")
    elif not re.match(r"^[A-Za-zА-Яа-яЁё]+ [A-Za-zА-Яа-яЁё]\.$", holder):
        flash("Получатель должен быть в формате Имя Ф.", "error")
    elif number_type not in {"card", "phone"}:
        flash("Выберите тип реквизита.", "error")
    elif number_type == "card" and (not number.isdigit() or len(number) < 16):
        flash("Введите корректный номер карты.", "error")
    elif number_type == "phone" and (not number.startswith("+7") or len(number) != 12 or not number[1:].isdigit()):
        flash("Телефон должен быть в формате +7XXXXXXXXXX.", "error")
    elif limit_rub is not None and limit_rub <= 0:
        flash("Лимит должен быть больше нуля или пустым.", "error")
    else:
        STATE["requisites"].insert(
            0,
            {
                "id": uuid.uuid4().hex[:12],
                "user": current_user_email(),
                "label": label,
                "bank": bank,
                "holder": holder,
                "number_type": number_type,
                "number": number,
                "limit_rub": limit_rub,
                "status": "active",
                "created_at": now_iso(),
            },
        )
        save_state(STATE)
        flash("Реквизит добавлен.", "success")
    return redirect(url_for("requisites_page"))


@app.route("/deposit/new")
@login_required
def deposit_new():
    return render_template("deposit.html", active_nav="deposit", networks=NETWORKS)


@app.route("/deposit/create", methods=["POST"])
@login_required
def deposit_create():
    network = request.form.get("network", "")
    amount = safe_int(request.form.get("amount"))
    if network not in NETWORKS:
        flash("Выберите поддерживаемую сеть.", "error")
        return redirect(url_for("deposit_new"))
    if amount < safe_int(STATE["settings"]["deposit_min"]) or amount > safe_int(STATE["settings"]["deposit_max"]):
        flash("Сумма вне допустимого диапазона.", "error")
        return redirect(url_for("deposit_new"))

    item = append_request(
        STATE,
        current_user_email(),
        "deposit",
        amount,
        "pending_payment",
        {"network": network, "wallet_address": get_deposit_address(network)},
    )
    append_notification(STATE, "admin@magma.com", "Новая заявка", f"Поступила заявка на пополнение {amount} USDT.", "warning")
    save_state(STATE)
    return redirect(url_for("payment_page", request_id=item["id"]))


@app.route("/payment/<request_id>")
@login_required
def payment_page(request_id):
    item = next((x for x in STATE["requests"] if x["id"] == request_id and x["user"] == current_user_email()), None)
    if not item:
        flash("Заявка не найдена.", "error")
        return redirect(url_for("dashboard"))
    return render_template(
        "payment.html",
        active_nav="deposit",
        payment=item,
        network=item["meta"]["network"],
        wallet_address=item["meta"]["wallet_address"],
        network_label=NETWORK_LABELS[item["meta"]["network"]],
    )


@app.route("/payment/<request_id>/confirm", methods=["POST"])
@login_required
def payment_confirm(request_id):
    item = next((x for x in STATE["requests"] if x["id"] == request_id and x["user"] == current_user_email()), None)
    if not item:
        flash("Заявка не найдена.", "error")
        return redirect(url_for("dashboard"))
    if item["status"] == "pending_payment":
        item["status"] = "pending_review"
        item["meta"]["paid_clicked_at"] = now_iso()
        append_notification(STATE, "admin@magma.com", "Платеж отмечен", f"Пользователь отметил оплату по заявке {item['id']}.", "info")
        save_state(STATE)
        flash("Платеж отмечен. Заявка принята в обработку.", "success")
    return redirect(url_for("history_page"))


@app.route("/withdraw/new")
@login_required
def withdraw_new():
    return render_template("withdraw.html", active_nav="withdraw", fee_percent=round(WITHDRAW_FEE * 100, 1))


@app.route("/withdraw/create", methods=["POST"])
@login_required
def withdraw_create():
    amount = safe_int(request.form.get("amount"))
    network = request.form.get("network", "")
    wallet = request.form.get("wallet", "").strip()
    user = current_user()
    if network not in NETWORKS:
        flash("Выберите сеть вывода.", "error")
        return redirect(url_for("withdraw_new"))
    if amount < safe_int(STATE["settings"]["withdraw_min"]) or amount > safe_int(STATE["settings"]["withdraw_max"]):
        flash("Сумма вне допустимого диапазона.", "error")
        return redirect(url_for("withdraw_new"))
    if amount > user["balance"]:
        flash("Недостаточно средств.", "error")
        return redirect(url_for("withdraw_new"))
    if len(wallet) < 10:
        flash("Укажите корректный адрес кошелька.", "error")
        return redirect(url_for("withdraw_new"))

    fee = max(1, int(amount * WITHDRAW_FEE))
    payout = amount - fee
    user["balance"] -= amount
    append_request(
        STATE,
        current_user_email(),
        "withdraw_usdt",
        payout,
        "pending_review",
        {"network": network, "wallet": wallet, "fee_usdt": fee, "charged_amount": amount},
    )
    append_notification(STATE, "admin@magma.com", "Новый вывод", f"Поступила заявка на вывод {payout} USDT.", "warning")
    save_state(STATE)
    flash("Заявка на вывод создана и принята в обработку.", "success")
    return redirect(url_for("history_page"))


@app.route("/usdt-to-fiat")
@login_required
def usdt_to_fiat():
    user = current_user()
    insurance_required = insurance_required_for_user(user)
    insurance_paid = insurance_is_paid(user)
    user["insurance_paid"] = insurance_paid
    user.setdefault("trade_online", False)
    user.setdefault("trade_minimum_rub", max(1, safe_int(STATE["settings"].get("fiat_min"), 300)))
    user.setdefault("trade_spread_reduction", 0.0)
    user.setdefault("trade_requisite_id", "")
    if bool(user.get("trade_online")) and (not insurance_paid or safe_int(user.get("balance"), 0) <= 0):
        user["trade_online"] = False
        save_state(STATE)

    now_value = now_utc()
    active_trades = []
    changed = False
    for trade in STATE["trades"]:
        if trade.get("user") != current_user_email():
            continue
        if trade.get("status") == "active":
            expires_at = dt.datetime.fromisoformat(trade["expires_at"])
            if now_value >= expires_at:
                trade["status"] = "expired"
                reserved = max(0, safe_int(trade.get("reserved_usdt"), 0))
                if reserved > 0:
                    owner = STATE["users"].get(trade.get("user"))
                    if owner:
                        owner["balance"] += reserved
                    trade["reserved_usdt"] = 0
                for item in STATE["requests"]:
                    if item.get("type") == "trade_manual" and item.get("meta", {}).get("trade_id") == trade.get("id"):
                        item["status"] = "rejected"
                        item.setdefault("meta", {})["expired_at"] = now_iso()
                        break
                changed = True
        if trade.get("status") == "active":
            active_trades.append(trade)
    if changed:
        save_state(STATE)
    return render_template(
        "trade.html",
        active_nav="trade",
        user=user,
        requisites=user_requisites(current_user_email()),
        active_trades=active_trades,
        insurance_required=insurance_required,
        insurance_paid=insurance_paid,
        trade_minimum_rub=max(1, safe_int(user.get("trade_minimum_rub"), safe_int(STATE["settings"].get("fiat_min"), 300))),
        trade_online=bool(user.get("trade_online", False)),
        trade_spread_reduction=round(min(8.0, max(0.0, safe_float(user.get("trade_spread_reduction"), 0.0))), 1),
        selected_requisite_id=user.get("trade_requisite_id", ""),
        available_rub=max(0, int(safe_int(user.get("balance"), 0) * safe_float(STATE["settings"].get("rub_rate"), 0) * (1 + safe_float(STATE["settings"].get("spread_percent"), 0) / 100))),
        can_enable_trade=bool(insurance_paid and safe_int(user.get("balance"), 0) > 0),
    )


@app.route("/trade/settings", methods=["POST"])
@login_required
def trade_settings():
    user = current_user()
    requisites = user_requisites(current_user_email())
    requisite_id = request.form.get("requisite_id", "").strip()
    spread_reduction = round(min(8.0, max(0.0, safe_float(request.form.get("spread_reduction"), 0.0))), 1)
    trade_minimum_rub = max(1, safe_int(request.form.get("trade_minimum_rub"), safe_int(STATE["settings"].get("fiat_min"), 300)))
    enabled = request.form.get("exchange_enabled", "") == "on"
    available_rub = max(
        0,
        int(
            safe_int(user.get("balance"), 0)
            * safe_float(STATE["settings"].get("rub_rate"), 0)
            * (1 + safe_float(STATE["settings"].get("spread_percent"), 0) / 100)
        ),
    )

    if not requisites:
        flash("Сначала добавьте реквизиты.", "error")
        return redirect(url_for("usdt_to_fiat"))

    if not any(x["id"] == requisite_id for x in requisites):
        requisite_id = requisites[0]["id"]

    if trade_minimum_rub > max(1, available_rub):
        flash("Минимальная сумма трейда не может быть больше доступного лимита в рублях.", "error")
        return redirect(url_for("usdt_to_fiat"))

    insurance_paid = insurance_is_paid(user)
    has_positive_balance = safe_int(user.get("balance"), 0) > 0
    if enabled and not insurance_paid:
        enabled = False
        flash("Для режима «Вы онлайн» сначала пополните страховой депозит.", "error")
    if enabled and not has_positive_balance:
        enabled = False
        flash("Для режима «Вы онлайн» нужен положительный баланс USDT.", "error")

    user["trade_online"] = enabled
    user["trade_minimum_rub"] = trade_minimum_rub
    user["trade_spread_reduction"] = spread_reduction
    user["trade_requisite_id"] = requisite_id
    save_state(STATE)
    flash("Параметры трейдинга сохранены.", "success")
    return redirect(url_for("usdt_to_fiat"))


@app.route("/disputes")
@login_required
def disputes_page():
    return render_template(
        "disputes.html",
        active_nav="disputes",
        disputes=[x for x in STATE["disputes"] if x["user"] == current_user_email()],
    )


@app.route("/insurance/pay", methods=["POST"])
@login_required
def insurance_pay():
    user = current_user()
    insurance_required = insurance_required_for_user(user)
    if insurance_required <= 0:
        flash("Для вашего аккаунта страховой баланс не требуется.", "info")
        return redirect(url_for("usdt_to_fiat"))
    if insurance_is_paid(user):
        flash("Страховой баланс уже оплачен.", "info")
        return redirect(url_for("usdt_to_fiat"))
    if safe_int(user.get("balance")) < insurance_required:
        flash("Недостаточно средств для оплаты страхового баланса.", "error")
        return redirect(url_for("usdt_to_fiat"))

    user["balance"] -= insurance_required
    user["insurance_paid"] = True
    user["insurance_paid_value"] = insurance_required
    user["insurance_balance"] = user["insurance_paid_value"]
    append_request(
        STATE,
        current_user_email(),
        "insurance_payment",
        insurance_required,
        "completed",
        {"source": "main_balance"},
    )
    append_admin_log(
        STATE,
        "system",
        "insurance_paid",
        current_user_email(),
        {"amount_usdt": insurance_required},
    )
    save_state(STATE)
    flash("Страховой баланс успешно оплачен.", "success")
    return redirect(url_for("usdt_to_fiat"))


@app.route("/fiat/create", methods=["POST"])
@login_required
def fiat_create():
    enabled = request.form.get("exchange_enabled", "") == "on"
    spread_reduction = round(min(8.0, max(0.0, safe_float(request.form.get("spread_reduction"), 0.0))), 1)
    requisite_id = request.form.get("requisite_id", "").strip()
    user = current_user()
    req = next((x for x in STATE["requisites"] if x["id"] == requisite_id and x["user"] == current_user_email()), None)
    available = safe_int(user.get("balance"))
    min_trade = max(1, safe_int(STATE["settings"].get("fiat_min"), 300))
    amount = min(min_trade, available, safe_int(STATE["settings"]["fiat_max"]))
    if not enabled:
        flash("Переведите статус в режим «Вы онлайн», чтобы получать трейды.", "error")
    elif available <= 0:
        flash("Недостаточно USDT для запуска обмена.", "error")
    elif available < min_trade:
        flash(f"Минимальная сумма трейда: {min_trade} USDT.", "error")
    elif not req:
        flash("Сначала добавьте реквизит для получения RUB.", "error")
    elif not insurance_is_paid(user):
        flash("Сначала пополните страховой баланс.", "error")
    else:
        append_request(
            STATE,
            current_user_email(),
            "trade_activation",
            amount,
            "pending_review",
            {
                "requisite_id": req["id"],
                "bank": req["bank"],
                "holder": req["holder"],
                "number": req["number"],
                "number_type": req.get("number_type", "card"),
                "spread_reduction": spread_reduction,
                "requested_amount_usdt": min_trade,
            },
        )
        append_notification(
            STATE,
            "admin@magma.com",
            "Новый запрос на трейдинг",
            f"Пользователь {current_user_email()} активировал обмен USDT to RUB: минимум {min_trade} USDT, снижение спреда {spread_reduction}%.",
            "warning",
        )
        flash("Обмен активирован. Ожидайте появление трейда в разделе активных.", "success")
        save_state(STATE)
    return redirect(url_for("usdt_to_fiat"))


@app.route("/trade/<trade_id>/confirm", methods=["POST"])
@login_required
def trade_confirm(trade_id):
    trade = next((x for x in STATE["trades"] if x["id"] == trade_id and x["user"] == current_user_email()), None)
    if not trade:
        flash("Трейд не найден.", "error")
        return redirect(url_for("usdt_to_fiat"))

    if trade["status"] != "active":
        flash("Этот трейд уже недоступен для подтверждения.", "info")
        return redirect(url_for("usdt_to_fiat"))

    trade["status"] = "completed"
    trade["confirmed_at"] = now_iso()
    trade["completed_at"] = now_iso()
    trade["reserved_usdt"] = 0
    for item in STATE["requests"]:
        if item.get("type") == "trade_manual" and item.get("meta", {}).get("trade_id") == trade_id:
            item["status"] = "completed"
            item.setdefault("meta", {})["completed_at"] = now_iso()
            break
    append_admin_log(STATE, "system", "trade_completed_by_user", current_user_email(), {"trade_id": trade_id})
    append_notification(STATE, current_user_email(), "Трейд завершен", f"Трейд {trade_id} успешно завершен.", "success")
    save_state(STATE)
    flash("Оплата подтверждена. Трейд завершен автоматически.", "success")
    return redirect(url_for("usdt_to_fiat"))


@app.route("/rate")
@login_required
def rate_page():
    return redirect(url_for("dashboard"))


@app.route("/support")
@login_required
def support_page():
    thread = user_support_thread(current_user_email())
    last_id = ""
    if thread and thread.get("messages"):
        last_id = thread["messages"][-1]["id"]
    return render_template("support.html", active_nav="support", thread=thread, support_last_id=last_id)


@app.route("/support/send", methods=["POST"])
@login_required
def support_send():
    text = request.form.get("text", "").strip()
    if not text:
        flash("Введите сообщение.", "error")
    else:
        append_support_message(STATE, current_user_email(), "user", text)
        append_notification(STATE, "admin@magma.com", "Новое сообщение в поддержке", f"Пользователь {current_user_email()} написал в чат.", "info")
        save_state(STATE)
        flash("Сообщение отправлено в поддержку.", "success")
    return redirect(url_for("support_page"))


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html", active_nav="settings", user=current_user())


@app.route("/settings/theme", methods=["POST"])
@login_required
def settings_theme():
    theme = request.form.get("theme", "cyber").strip()
    if theme not in {"cyber", "light"}:
        flash("Выберите корректную тему.", "error")
    else:
        current_user()["theme"] = theme
        save_state(STATE)
        flash("Тема обновлена.", "success")
    return redirect(url_for("settings_page"))


@app.route("/settings/password", methods=["POST"])
@login_required
def settings_password():
    user = current_user()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not check_password_hash(user["password_hash"], current_password):
        flash("Текущий пароль введен неверно.", "error")
    elif len(new_password) < 6:
        flash("Новый пароль должен быть не короче 6 символов.", "error")
    elif new_password != confirm_password:
        flash("Новые пароли не совпадают.", "error")
    else:
        user["password_hash"] = generate_password_hash(new_password)
        save_state(STATE)
        flash("Пароль успешно обновлен.", "success")
    return redirect(url_for("settings_page"))


@app.route("/api/support/messages")
@login_required
def api_support_messages():
    since_id = request.args.get("since", "").strip()
    thread = user_support_thread(current_user_email())
    if not thread:
        return jsonify({"messages": [], "last_id": ""})

    messages = thread.get("messages", [])
    if not since_id:
        return jsonify({"messages": messages, "last_id": (messages[-1]["id"] if messages else "")})

    index = next((idx for idx, msg in enumerate(messages) if msg["id"] == since_id), None)
    if index is None:
        return jsonify({"messages": messages, "last_id": (messages[-1]["id"] if messages else "")})

    new_messages = messages[index + 1 :]
    return jsonify({"messages": new_messages, "last_id": (messages[-1]["id"] if messages else since_id)})


@app.route("/history")
@login_required
def history_page():
    return render_template("history.html", active_nav="history", requests=user_requests(current_user_email(), limit=80))


@app.route("/admin")
@admin_required
def admin():
    for user in STATE["users"].values():
        user["insurance_paid"] = insurance_is_paid(user)
        user["online"] = is_user_online(user)
    pending_requests = [x for x in STATE["requests"] if x.get("status") in {"pending_review", "pending_payment"}][:80]
    return render_template(
        "admin.html",
        active_nav="admin",
        users=STATE["users"],
        requests=pending_requests,
        trades=STATE["trades"][:80],
        disputes=STATE["disputes"][:40],
        threads=STATE["support_threads"][:20],
        analytics=analytics_snapshot(),
    )


@app.route("/admin/request/<request_id>/<decision>", methods=["POST"])
@admin_required
def admin_decide_request(request_id, decision):
    item = next((x for x in STATE["requests"] if x["id"] == request_id), None)
    if not item:
        flash("Заявка не найдена.", "error")
        return redirect(url_for("admin"))

    if decision == "approve":
        item["status"] = "approved"
        if item["type"] in {"deposit", "insurance"}:
            user = STATE["users"][item["user"]]
            if item["type"] == "deposit":
                user["balance"] += item["amount_usdt"]
            else:
                user["insurance_balance"] += item["amount_usdt"]
        append_notification(STATE, item["user"], "Операция подтверждена", f"Заявка {item['id']} успешно подтверждена.", "success")
    elif decision == "reject":
        item["status"] = "rejected"
        if item["type"] == "sell_usdt":
            STATE["users"][item["user"]]["balance"] += item["amount_usdt"]
        if item["type"] == "withdraw_usdt":
            charged_amount = safe_int(item.get("meta", {}).get("charged_amount"), item["amount_usdt"])
            STATE["users"][item["user"]]["balance"] += charged_amount
        append_notification(STATE, item["user"], "Операция отклонена", f"Заявка {item['id']} была отклонена.", "warning")
    else:
        flash("Неизвестное действие.", "error")
        return redirect(url_for("admin"))

    append_admin_log(STATE, current_user_email(), f"{decision}_request", item["user"], {"request_id": request_id})
    save_state(STATE)
    flash("Статус заявки обновлен.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/trade/create", methods=["POST"])
@admin_required
def admin_create_trade():
    request_id = request.form.get("request_id", "").strip()
    amount_usdt = safe_int(request.form.get("amount_usdt"))

    request_item = next(
        (
            x
            for x in STATE["requests"]
            if x.get("id") == request_id and x.get("type") == "trade_activation" and x.get("status") == "pending_review"
        ),
        None,
    )
    if not request_item:
        flash("Запрос на трейд не найден или уже обработан.", "error")
        return redirect(url_for("admin"))

    user_email = request_item["user"]
    user = STATE["users"].get(user_email)
    if not user:
        flash("Пользователь не найден.", "error")
        return redirect(url_for("admin"))

    if amount_usdt <= 0:
        flash("Сумма трейда должна быть больше нуля.", "error")
        return redirect(url_for("admin"))

    max_trade = max(0, safe_int(user.get("balance")))
    if amount_usdt > max_trade:
        flash("Сумма трейда не может быть выше доступного баланса пользователя.", "error")
        return redirect(url_for("admin"))
    if amount_usdt > safe_int(STATE["settings"].get("fiat_max"), 300000):
        flash("Сумма трейда превышает лимит платформы.", "error")
        return redirect(url_for("admin"))

    expires_at = now_utc() + dt.timedelta(minutes=10)
    meta = request_item.get("meta", {})
    spread_snapshot = safe_float(STATE["settings"].get("spread_percent"), 0.0)
    rate_snapshot = safe_float(STATE["settings"].get("rub_rate"), 0.0)
    rub_amount_fixed = calculate_trade_rub(amount_usdt, spread_snapshot, rate_snapshot)
    platform_income_usdt = max(0, int(round(amount_usdt * (spread_snapshot / 100.0))))
    user["balance"] -= amount_usdt
    trade_id = uuid.uuid4().hex[:12]
    STATE["trades"].insert(
        0,
        {
            "id": trade_id,
            "request_id": request_id,
            "user": user_email,
            "amount_usdt": amount_usdt,
            "bank": meta.get("bank", ""),
            "holder": meta.get("holder", ""),
            "number": meta.get("number", ""),
            "number_type": meta.get("number_type", "card"),
            "status": "active",
            "reserved_usdt": amount_usdt,
            "rub_amount_fixed": rub_amount_fixed,
            "spread_percent_snapshot": spread_snapshot,
            "rub_rate_snapshot": rate_snapshot,
            "created_at": now_iso(),
            "expires_at": expires_at.isoformat(),
        },
    )

    request_item["status"] = "approved"
    request_item["meta"] = {
        **meta,
        "assigned_trade_id": trade_id,
        "assigned_amount_usdt": amount_usdt,
    }

    append_request(
        STATE,
        user_email,
        "trade_manual",
        amount_usdt,
        "active",
        {
            "trade_id": trade_id,
            "bank": meta.get("bank", ""),
            "holder": meta.get("holder", ""),
            "number": meta.get("number", ""),
            "rub_amount_fixed": rub_amount_fixed,
            "platform_income_usdt": platform_income_usdt,
        },
    )
    append_notification(
        STATE,
        user_email,
        "Активный трейд добавлен",
        f"Трейд на {amount_usdt} USDT запущен. Откройте вкладку USDT to RUB для подтверждения оплаты.",
        "success",
    )
    append_admin_log(STATE, current_user_email(), "create_trade", user_email, {"request_id": request_id, "amount": amount_usdt})
    save_state(STATE)
    flash("Трейд успешно добавлен пользователю.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/trade/manual", methods=["POST"])
@admin_required
def admin_create_trade_manual():
    email = request.form.get("email", "").strip().lower()
    amount_usdt = safe_int(request.form.get("amount_usdt"))
    user = STATE["users"].get(email)
    if not user or user.get("role") == "admin":
        flash("Выберите корректного пользователя.", "error")
        return redirect(url_for("admin"))
    if amount_usdt <= 0:
        flash("Сумма трейда должна быть больше нуля.", "error")
        return redirect(url_for("admin"))

    max_trade = max(0, safe_int(user.get("balance")))
    if amount_usdt > max_trade:
        flash("Сумма трейда не может быть выше доступного баланса пользователя.", "error")
        return redirect(url_for("admin"))
    if amount_usdt > safe_int(STATE["settings"].get("fiat_max"), 300000):
        flash("Сумма трейда превышает лимит платформы.", "error")
        return redirect(url_for("admin"))

    user_reqs = [x for x in STATE["requisites"] if x.get("user") == email]
    preferred_id = user.get("trade_requisite_id", "")
    req = next((x for x in user_reqs if x.get("id") == preferred_id), None)
    if not req and user_reqs:
        req = user_reqs[0]
    if not req:
        flash("У пользователя нет реквизитов.", "error")
        return redirect(url_for("admin"))

    spread_snapshot = safe_float(STATE["settings"].get("spread_percent"), 0.0)
    rate_snapshot = safe_float(STATE["settings"].get("rub_rate"), 0.0)
    rub_amount_fixed = calculate_trade_rub(amount_usdt, spread_snapshot, rate_snapshot)
    platform_income_usdt = max(0, int(round(amount_usdt * (spread_snapshot / 100.0))))
    user["balance"] -= amount_usdt
    trade_id = uuid.uuid4().hex[:12]
    STATE["trades"].insert(
        0,
        {
            "id": trade_id,
            "request_id": "",
            "user": email,
            "amount_usdt": amount_usdt,
            "bank": req.get("bank", ""),
            "holder": req.get("holder", ""),
            "number": req.get("number", ""),
            "number_type": req.get("number_type", "card"),
            "status": "active",
            "reserved_usdt": amount_usdt,
            "rub_amount_fixed": rub_amount_fixed,
            "spread_percent_snapshot": spread_snapshot,
            "rub_rate_snapshot": rate_snapshot,
            "created_at": now_iso(),
            "expires_at": (now_utc() + dt.timedelta(minutes=10)).isoformat(),
        },
    )
    append_request(
        STATE,
        email,
        "trade_manual",
        amount_usdt,
        "active",
        {
            "trade_id": trade_id,
            "bank": req.get("bank", ""),
            "holder": req.get("holder", ""),
            "number": req.get("number", ""),
            "rub_amount_fixed": rub_amount_fixed,
            "platform_income_usdt": platform_income_usdt,
        },
    )
    append_notification(
        STATE,
        email,
        "Новый активный трейд",
        f"Добавлен трейд на {amount_usdt} USDT. Откройте раздел USDT to RUB.",
        "success",
    )
    append_admin_log(STATE, current_user_email(), "manual_trade_create", email, {"amount": amount_usdt, "trade_id": trade_id})
    save_state(STATE)
    flash("Трейд добавлен вручную.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/set-balance", methods=["POST"])
@admin_required
def admin_set_balance():
    email = request.form.get("email", "").strip().lower()
    amount = safe_int(request.form.get("balance"))
    user = STATE["users"].get(email)
    if not user:
        flash("Пользователь не найден.", "error")
    elif amount < 0:
        flash("Баланс не может быть отрицательным.", "error")
    else:
        user["balance"] = amount
        append_admin_log(STATE, current_user_email(), "set_balance", email, {"to": amount})
        save_state(STATE)
        flash("Баланс обновлен.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/balance-adjust", methods=["POST"])
@admin_required
def admin_adjust_balance():
    email = request.form.get("email", "").strip().lower()
    amount = safe_int(request.form.get("amount"))
    action = request.form.get("action", "").strip().lower()
    user = STATE["users"].get(email)
    if not user:
        flash("Пользователь не найден.", "error")
        return redirect(url_for("admin"))
    if amount <= 0:
        flash("Укажите сумму больше нуля.", "error")
        return redirect(url_for("admin"))
    if action not in {"add", "subtract"}:
        flash("Некорректная операция.", "error")
        return redirect(url_for("admin"))
    if action == "subtract" and safe_int(user.get("balance"), 0) < amount:
        flash("Недостаточно средств для списания.", "error")
        return redirect(url_for("admin"))

    delta = amount if action == "add" else -amount
    user["balance"] = safe_int(user.get("balance"), 0) + delta
    append_admin_log(STATE, current_user_email(), "adjust_balance", email, {"delta": delta, "after": user["balance"]})
    save_state(STATE)
    flash("Баланс пользователя обновлен.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/set-insurance", methods=["POST"])
@admin_required
def admin_set_insurance():
    email = request.form.get("email", "").strip().lower()
    amount = safe_int(request.form.get("insurance_balance"))
    if email != "all":
        user = STATE["users"].get(email)
        if not user or user.get("role") == "admin":
            flash("Пользователь не найден.", "error")
            return redirect(url_for("admin"))
        if amount < 0:
            flash("Страховой депозит не может быть отрицательным.", "error")
            return redirect(url_for("admin"))
        user["insurance_paid_value"] = amount
        user["insurance_balance"] = amount
        user["insurance_paid"] = bool(amount > 0)
        append_admin_log(STATE, current_user_email(), "set_user_insurance_balance", email, {"to": amount})
        save_state(STATE)
        flash("Страховой депозит пользователя обновлен.", "success")
        return redirect(url_for("admin"))
    if amount < 0:
        flash("Страховой баланс не может быть отрицательным.", "error")
    elif email == "all":
        STATE["settings"]["insurance_minimum"] = amount
        STATE["settings"]["insurance_default"] = amount
        append_admin_log(STATE, current_user_email(), "set_insurance_minimum", "system", {"to": amount})
        save_state(STATE)
        flash("Минимальный страховой баланс обновлен.", "success")
    else:
        flash("Индивидуальная установка страхового баланса отключена. Используйте минимальный страховой платформы.", "error")
    return redirect(url_for("admin"))


@app.route("/admin/set-user-insurance-minimum", methods=["POST"])
@admin_required
def admin_set_user_insurance_minimum():
    email = request.form.get("email", "").strip().lower()
    raw_value = (request.form.get("insurance_minimum_override") or "").strip()
    user = STATE["users"].get(email)
    if not user or user.get("role") == "admin":
        flash("Пользователь не найден.", "error")
        return redirect(url_for("admin"))

    if raw_value == "":
        user["insurance_minimum_override"] = None
        append_admin_log(STATE, current_user_email(), "clear_user_insurance_minimum", email, {})
        save_state(STATE)
        flash("Для пользователя включен общий минимум страхового депозита платформы.", "success")
        return redirect(url_for("admin"))

    amount = safe_int(raw_value, -1)
    if amount < 0:
        flash("Минимальный страховой депозит должен быть числом от 0.", "error")
        return redirect(url_for("admin"))

    user["insurance_minimum_override"] = amount
    append_admin_log(STATE, current_user_email(), "set_user_insurance_minimum", email, {"to": amount})
    save_state(STATE)
    flash("Индивидуальный минимум страхового депозита обновлен.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/settings/deposit-addresses", methods=["POST"])
@admin_required
def admin_set_deposit_addresses():
    trc20 = request.form.get("trc20_address", "").strip()
    ton = request.form.get("ton_address", "").strip()
    if len(trc20) < 10 or len(ton) < 10:
        flash("Укажите корректные адреса пополнения для TRC20 и TON.", "error")
        return redirect(url_for("admin"))
    normalize_runtime_settings(STATE["settings"])
    STATE["settings"]["deposit_addresses"]["TRC20"] = trc20
    STATE["settings"]["deposit_addresses"]["TON"] = ton
    append_admin_log(STATE, current_user_email(), "set_deposit_addresses", "system", {"TRC20": trc20, "TON": ton})
    save_state(STATE)
    flash("Адреса пополнения обновлены.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/set-spread", methods=["POST"])
@admin_required
def admin_set_spread():
    spread = round(safe_float(request.form.get("spread")), 2)
    if spread <= 0 or spread > 25:
        flash("Спред должен быть в диапазоне 0.1–25%.", "error")
    else:
        STATE["settings"]["spread_percent"] = spread
        append_admin_log(STATE, current_user_email(), "set_spread", "system", {"to": spread})
        save_state(STATE)
        flash("Спред обновлен.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/set-online", methods=["POST"])
@admin_required
def admin_set_online():
    online_value = safe_int(request.form.get("online"))
    variation_value = safe_int(request.form.get("online_variation"))
    if online_value < 0:
        flash("Онлайн не может быть отрицательным.", "error")
        return redirect(url_for("admin"))
    if variation_value < 0 or variation_value > 5000:
        flash("Диапазон онлайна должен быть в пределах 0-5000.", "error")
        return redirect(url_for("admin"))
    normalize_runtime_settings(STATE["settings"])
    STATE["settings"]["online"] = online_value
    STATE["settings"]["online_variation"] = variation_value
    append_admin_log(
        STATE,
        current_user_email(),
        "set_online_settings",
        "system",
        {"online": online_value, "online_variation": variation_value},
    )
    save_state(STATE)
    flash("Параметры онлайна обновлены.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/toggle-user", methods=["POST"])
@admin_required
def admin_toggle_user():
    email = request.form.get("email", "").strip().lower()
    user = STATE["users"].get(email)
    if not user or user["role"] == "admin":
        flash("Нельзя изменить этот аккаунт.", "error")
    else:
        user["status"] = "blocked" if user["status"] == "active" else "active"
        append_admin_log(STATE, current_user_email(), "toggle_user", email, {"status": user["status"]})
        save_state(STATE)
        flash("Статус пользователя изменен.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/send-notification", methods=["POST"])
@admin_required
def admin_send_notification():
    email = request.form.get("email", "").strip().lower()
    title = request.form.get("title", "").strip()
    message = request.form.get("message", "").strip()
    level = request.form.get("level", "info")
    if email not in STATE["users"]:
        flash("Пользователь не найден.", "error")
    elif not title or not message:
        flash("Заполните заголовок и сообщение.", "error")
    else:
        append_notification(STATE, email, title, message, level)
        append_admin_log(STATE, current_user_email(), "send_notification", email)
        save_state(STATE)
        flash("Уведомление отправлено.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/open-dispute", methods=["POST"])
@admin_required
def admin_open_dispute():
    email = request.form.get("email", "").strip().lower()
    request_id = request.form.get("request_id", "").strip()
    reason = request.form.get("reason", "").strip()
    if email not in STATE["users"] or not reason:
        flash("Укажите пользователя и причину.", "error")
    else:
        STATE["disputes"].insert(
            0,
            {
                "id": uuid.uuid4().hex[:12],
                "user": email,
                "request_id": request_id,
                "status": "open",
                "reason": reason,
                "created_at": now_iso(),
            },
        )
        append_notification(STATE, email, "Открыт спор", reason, "warning")
        append_admin_log(STATE, current_user_email(), "open_dispute", email, {"request_id": request_id})
        save_state(STATE)
        flash("Спор открыт.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/support/reply", methods=["POST"])
@admin_required
def admin_support_reply():
    email = request.form.get("email", "").strip().lower()
    text = request.form.get("text", "").strip()
    if email not in STATE["users"] or not text:
        flash("Укажите пользователя и сообщение.", "error")
    else:
        append_support_message(STATE, email, "admin", text)
        append_notification(STATE, email, "Ответ поддержки", "Поддержка ответила в вашем чате.", "success")
        append_admin_log(STATE, current_user_email(), "support_reply", email)
        save_state(STATE)
        flash("Ответ отправлен.", "success")
    return redirect(url_for("admin"))


@app.route("/api/trade/active")
@login_required
def api_trade_active():
    now_value = now_utc()
    changed = False
    active_trades = []
    for trade in STATE["trades"]:
        if trade.get("user") != current_user_email():
            continue
        if trade.get("status") == "active":
            try:
                expires_at = dt.datetime.fromisoformat(trade["expires_at"])
            except Exception:
                expires_at = now_value
            if now_value >= expires_at:
                trade["status"] = "expired"
                reserved = max(0, safe_int(trade.get("reserved_usdt"), 0))
                if reserved > 0:
                    owner = STATE["users"].get(trade.get("user"))
                    if owner:
                        owner["balance"] += reserved
                    trade["reserved_usdt"] = 0
                changed = True
            else:
                active_trades.append(
                    {
                        "id": trade.get("id", ""),
                        "amount_usdt": safe_int(trade.get("amount_usdt"), 0),
                        "bank": trade.get("bank", ""),
                        "holder": trade.get("holder", ""),
                        "number": trade.get("number", ""),
                        "rub_amount_fixed": safe_int(trade.get("rub_amount_fixed"), 0),
                        "status": trade.get("status", "active"),
                        "expires_at": trade.get("expires_at", ""),
                    }
                )
    if changed:
        save_state(STATE)
    return jsonify({"active_trades": active_trades})


@app.route("/api/admin/live")
@admin_required
def api_admin_live():
    pending_requests = [x for x in STATE["requests"] if x.get("status") in {"pending_review", "pending_payment"}][:80]
    active_trades = [x for x in STATE["trades"] if x.get("status") == "active"][:80]
    return jsonify(
        {
            "pending_requests": [
                {
                    "id": item.get("id", ""),
                    "user": item.get("user", ""),
                    "type": item.get("type", ""),
                    "amount_usdt": safe_int(item.get("amount_usdt"), safe_int(item.get("amount"), 0)),
                    "status": item.get("status", ""),
                    "created_at": item.get("created_at", ""),
                }
                for item in pending_requests
            ],
            "active_trades": [
                {
                    "id": trade.get("id", ""),
                    "user": trade.get("user", ""),
                    "bank": trade.get("bank", ""),
                    "holder": trade.get("holder", ""),
                    "number": trade.get("number", ""),
                    "status": trade.get("status", ""),
                    "amount_usdt": safe_int(trade.get("amount_usdt"), 0),
                    "created_at": trade.get("created_at", ""),
                }
                for trade in active_trades
            ],
        }
    )


@app.route("/api/live")
@login_required
def api_live():
    normalize_runtime_settings(STATE["settings"])
    base_online = max(0, safe_int(STATE["settings"].get("online"), 0))
    variation = max(0, safe_int(STATE["settings"].get("online_variation"), 7))
    jitter = random.randint(-variation, variation) if variation > 0 else 0
    online_view = max(0, base_online + jitter)
    current_rate = safe_float(STATE["settings"]["rub_rate"], 92.4)
    synced = sync_market_rate_if_needed(STATE["settings"], min_interval_sec=20)
    synced_rate = safe_float(STATE["settings"]["rub_rate"], current_rate)
    noise = 0.0 if synced else random.uniform(-0.01, 0.01)
    next_rate = current_rate + (synced_rate - current_rate) * 0.55 + noise
    next_rate = round(max(40, min(300, next_rate)), 2)
    STATE["settings"]["rub_rate"] = next_rate
    if current_rate > 0:
        STATE["settings"]["rate_change"] = round(((next_rate - current_rate) / current_rate) * 100, 2)
    spread = round(max(0.1, min(25, safe_float(STATE["settings"]["spread_percent"]))), 2)
    normalize_runtime_settings(STATE["settings"])
    save_state(STATE)
    return jsonify(
        {
            "online": online_view,
            "rub_rate": STATE["settings"]["rub_rate"],
            "rate_label": f"КУРС $ {STATE['settings']['rub_rate']} ₽",
            "rate_change": STATE["settings"]["rate_change"],
            "spread": spread,
            "balance": current_user()["balance"],
            "insurance_balance": current_user()["insurance_balance"],
            "notifications": unread_notifications(current_user_email())[:3],
        }
    )


@app.route("/api/notifications/read", methods=["POST"])
@login_required
def api_notifications_read():
    email = current_user_email()
    for item in STATE["notifications"]:
        if item["user"] == email:
            item["read"] = True
    save_state(STATE)
    return jsonify({"ok": True})


@app.route("/logout")
def logout():
    if session.get("counted_online"):
        normalize_runtime_settings(STATE["settings"])
        STATE["settings"]["online"] = max(0, safe_int(STATE["settings"].get("online"), 0) - 1)
        save_state(STATE)
    session.clear()
    flash("Сессия завершена.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
