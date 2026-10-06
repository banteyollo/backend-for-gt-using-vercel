# app.py - GTAG private-server backend (single Flask app for Vercel + Supabase)
#
# ============================================================================
# REWRITE NOTES (read me before editing)
# ============================================================================
# This file is a full rewrite of the backend. Every route's request/response
# shape was rebuilt from captured official-server traffic in
# "atrium revamp  mothership_dump_2026-09-06_01-41-27/ai_summary/ai_database.json"
# (93 endpoints, 51 captured responses). Where the dump captures an exact
# response, the route below reproduces it field-for-field.
#
# AUTH (do not "fix" this - it is intentional, see "full customID METHOD.md"):
# - The game's SteamAuthenticator is patched to hand out a DEVICE ID
#   (SystemInfo.deviceUniqueIdentifier, hashed, 32 hex chars) instead of a
#   Steam ticket. The ticket field everywhere IS the device key.
# - POST /v2/player/client/auth/complete/STEAM receives that device key in the
#   SteamTicket/nonce fields, and locks ONE PlayFab account + ONE MothershipID
#   to it forever (device_players table). The MothershipID is PERMANENT: it is
#   assigned when the device key first logs in and never rotates afterwards.
# - This is a private game (friends-only, deployed on Vercel, data in
#   Supabase), so device-key auth replaces real Steam/PlayFab auth on purpose.
#   No Steam ticket validation exists anywhere by design.
#
# SECRETS: supply SUPABASE_URL / SUPABASE_KEY / PLAYFAB_* via Vercel env vars.
# Never commit real keys here.
# ============================================================================

import os
import json
import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
import jwt
import requests

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

# ============================================================================
# CONFIGURATION - all values hardcoded; NO environment variables needed.
# Everything below can still be overridden with env vars if you ever want to,
# but the defaults in this file are the deployment values.
# ============================================================================

CONFIG = {
    # Supabase (service-role key - keep in env vars in production)
    "supabase_url": os.environ.get("SUPABASE_URL", "ursupabase.supabase.co"),
    "supabase_key": os.environ.get(
        "SUPABASE_KEY",
        "ur supabase key"),

    # PlayFab (cosmetics inventory / DLC catalog / display names)
    "playfab_title_id": os.environ.get("PLAYFAB_TITLE_ID", "ur title id"),
    "playfab_secret_key": os.environ.get(
        "PLAYFAB_SECRET_KEY", "playfab secret key"),

    # Mothership identifiers - these are baked into the ES256 player tokens.
    # The client echoes them back in every request body (MothershipEnvId /
    # MothershipDeploymentId) and validates the "did"/"env"/"tid" claims.
    "mothership_title_id": os.environ.get("MOTHERSHIP_TITLE_ID", "f3e9fb19"),
    "mothership_env_id": os.environ.get("MOTHERSHIP_ENV_ID", "7f3a99dd-5598-4725-98cf-6538d28feb9f"),
    "mothership_deployment_id": os.environ.get("MOTHERSHIP_DEPLOYMENT_ID", "c2f9177d-23d3-45db-9699-0f72103a6888"),

    # Mod.io (cosmetic mod browsing). The game also calls these directly with
    # its own api key when configured; we mirror a public-shaped fallback.
    "modio_api_key": os.environ.get("MODIO_API_KEY", ""),
    "modio_game_id": os.environ.get("MODIO_GAME_ID", "6657"),

    # Kid-safety session (GetPlayerData) - overridable for regional testing
    "kid_dob": os.environ.get("KID_DATE_OF_BIRTH", "2000-01-01T00:00:00"),
    "kid_jurisdiction": os.environ.get("KID_JURISDICTION", "US"),

    # Server
    "host": os.environ.get("HOST", "0.0.0.0"),
    "port": int(os.environ.get("PORT", 5000)),

    # Agreement versions the client must accept (official capture: 2026.03.11)
    "agreement_version": os.environ.get("AGREEMENT_VERSION", "2026.03.11"),

    # Allowed client game version (ReturnCurrentVersionV2)
    "game_version": os.environ.get("GAME_VERSION", "99999"),

    # Admin identity used for the friend-presence bypass (see GetFriendsV2)
    "admin_playfab_id": os.environ.get("ADMIN_PLAYFAB_ID", ""),
}

# Fallback convenience: if SUPABASE_KEY is unset, SUPABASE_SERVICE_KEY is
# accepted as an alias (env vars always win over the hardcoded default).
if not CONFIG["supabase_key"]:
    CONFIG["supabase_key"] = os.environ.get("SUPABASE_SERVICE_KEY", "")

# ============================================================================
# JWT keys (ES256) - HARDCODED so every Vercel instance signs/verifies player
# tokens with the same pair, with ZERO environment variables required.
#
# The private key ships inside this source file: treat the source as the
# secret. To revoke every outstanding player token, regenerate both PEM
# strings (any ES256/P-256 generator) and redeploy.
# ============================================================================

JWT_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6n3FTGcb0r6LZkSS
lP/nsbTWVYCS4GuyOzBotVxPZoyhRANCAAReaIpimi70vb7RJ9D0vEOjT1SJWPs9
t4ZGaVzRBuGIEhWRHuuq2Z5P9dhhkuoXj3bCNrmZx0TIf0kTSN5u6VsS
-----END PRIVATE KEY-----"""

JWT_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXmiKYpou9L2+0SfQ9LxDo09UiVj7
PbeGRmlc0QbhiBIVkR7rqtmeT/XYYZLqF492wja5mcdEyH9JE0jebulbEg==
-----END PUBLIC KEY-----"""

# ============================================================================
# Supabase
# ============================================================================

supabase: Client = None

def init_supabase():
    global supabase
    if CONFIG["supabase_url"] and CONFIG["supabase_key"]:
        try:
            supabase = create_client(CONFIG["supabase_url"], CONFIG["supabase_key"])
            print("[supabase] Initialized")
            return True
        except Exception as e:
            print(f"[supabase] init failed: {e}")
            supabase = None
            return False
    print("[supabase] WARNING: not configured (SUPABASE_URL / SUPABASE_KEY)")
    return False

# ============================================================================
# Flask app
# ============================================================================

app = Flask(__name__)
CORS(app)

init_supabase()

# ============================================================================
# Presence store (in-process; per-instance on serverless)
# ============================================================================

player_sockets = {}  # mothershipid/playfabid -> last_seen epoch seconds

PRESENCE_WINDOW_SECONDS = 60

def update_player_presence(player_id):
    if player_id:
        player_sockets[player_id] = time.time()

def get_ccu():
    now = time.time()
    stale = [pid for pid, ts in player_sockets.items() if now - ts > PRESENCE_WINDOW_SECONDS]
    for pid in stale:
        player_sockets.pop(pid, None)
    return len(player_sockets)

# ============================================================================
# Database helpers (Supabase)
# ============================================================================

def db_get(table, match=None, select="*", order_by=None, limit=None):
    if not supabase:
        return []
    try:
        query = supabase.table(table).select(select)
        if match:
            for key, value in match.items():
                query = query.eq(key, value)
        if order_by:
            query = query.order(order_by[0], desc=bool(order_by[1]) if len(order_by) > 1 else True)
        if limit:
            query = query.limit(limit)
        result = query.execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"[db_get error] {table}: {e}")
        return []

def db_get_one(table, match=None, select="*", order_by=None):
    results = db_get(table, match, select, order_by, 1)
    return results[0] if results else None

def db_insert(table, data):
    if not supabase:
        return None
    try:
        result = supabase.table(table).insert(data).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"[db_insert error] {table}: {e}")
        return None

def db_update(table, match, data):
    if not supabase:
        return None
    try:
        query = supabase.table(table).update(data)
        for key, value in match.items():
            query = query.eq(key, value)
        result = query.execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"[db_update error] {table}: {e}")
        return None

def db_upsert(table, data, on_conflict=None):
    """Upsert; on_conflict accepts a string or list of columns."""
    if not supabase:
        return None
    try:
        if on_conflict and not isinstance(on_conflict, str):
            on_conflict = ','.join(on_conflict)
        if on_conflict:
            result = supabase.table(table).upsert(data, on_conflict=on_conflict).execute()
        else:
            result = supabase.table(table).upsert(data).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"[db_upsert error] {table}: {e}")
        return None

def db_delete(table, match):
    if not supabase:
        return None
    try:
        query = supabase.table(table).delete()
        for key, value in match.items():
            query = query.eq(key, value)
        return query.execute().data
    except Exception as e:
        print(f"[db_delete error] {table}: {e}")
        return None

def db_count(table, match=None):
    if not supabase:
        return 0
    try:
        query = supabase.table(table).select("*", count="exact")
        if match:
            for key, value in match.items():
                query = query.eq(key, value)
        result = query.execute()
        return result.count if getattr(result, 'count', None) is not None else len(result.data or [])
    except Exception as e:
        print(f"[db_count error] {table}: {e}")
        return 0

# ============================================================================
# Small helpers
# ============================================================================

def utc_now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def now_ms():
    return int(time.time() * 1000)

def generate_uuid():
    import uuid
    return str(uuid.uuid4())

def generate_code(length=8):
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_map_id(length=8):
    chars = "CFGHKMNPRTWXZ256789"
    return ''.join(secrets.choice(chars) for _ in range(length))

def safe_json_loads(raw, default=None):
    if raw is None:
        return default
    if isinstance(raw, (dict, list, int, float, bool)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default

def week_number_key(dt=None):
    """ISO week number as a string - official weeklyPoints key ('37')."""
    dt = dt or datetime.now(timezone.utc)
    return str(dt.isocalendar()[1])

def date_key(dt=None):
    """Official dailyPoints key - MM/DD/YYYY ('09/04/2026')."""
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime('%m/%d/%Y')

# ============================================================================
# Title data - fetched from PLAYFAB (Server/GetTitleData), exactly like the
# pre-rewrite backend. NO hardcoded fallback: if PlayFab serves a key, the
# client gets PlayFab's value. The mothershiptitledata Supabase table is an
# OPTIONAL override layer (rows there win over PlayFab).
# ============================================================================

# PlayFab title-data cache (title data is effectively static; a failed fetch
# is NOT cached so the next request retries)
_pf_title_cache = {'data': None, 'ts': 0.0}
_PF_TITLE_TTL = 300.0

# Title Data Objects (PlayFab "object data files" referenced by schedule keys
# like RotatingFlashback / TimedStore via TitleDataObjectID). These are served
# by PlayFab from a separate CDN the SDK resolves as
# https://titledata.playfabapi.com/<titleId>/obj/<name>; we mirror them here so
# the client can resolve SetA/SetB (rotating flashback cosmetic sets) against
# our backend. Override/extend via mothershiptitledata rows keyed
# 'TitleDataObject_<Name>' (value = the raw object JSON).
_pf_object_cache = {'data': None, 'ts': 0.0}
_PF_OBJECT_TTL = 900.0


def _pf_object_names():
    """Collect every TitleDataObjectID referenced by PlayFab schedule keys."""
    data = _pf_title_data()
    names = set()
    for key, value in data.items():
        if key in ('RotatingFlashback', 'TimedStore', 'CityObjectSchedule',
                   'EventWarnings', 'EventCountdown'):
            parsed = safe_json_loads(value, {}) if isinstance(value, str) else value
            if isinstance(parsed, dict):
                for entry in parsed.get('Data', []) or []:
                    obj_id = entry.get('TitleDataObjectID') if isinstance(entry, dict) else None
                    if obj_id:
                        names.add(obj_id)
    return names


def _pf_fetch_object(name):
    """Fetch one PlayFab Title Data Object from the object CDN."""
    if not CONFIG['playfab_title_id']:
        return None
    url = f"https://titledata.playfabapi.com/{CONFIG['playfab_title_id']}/obj/{name}"
    try:
        resp = requests.get(url, timeout=15, headers={'Accept': '*/*',
                                                     'User-Agent': 'GTAG-Backend/3.0'})
        if resp.status_code == 200:
            try:
                return resp.json()
            except Exception:
                return {'value': resp.text}
        print(f"[title objects] {name} -> HTTP {resp.status_code}")
    except Exception as e:
        print(f"[title objects] {name} fetch failed: {e}")
    return None


def _pf_title_objects():
    """Map of {objectName: payload} for all referenced Title Data Objects,
    overlaid by Supabase overrides (TitleDataObject_<Name> rows)."""
    now = time.time()
    if _pf_object_cache['data'] is None or now - _pf_object_cache['ts'] > _PF_OBJECT_TTL:
        objects = {}
        for name in _pf_object_names():
            payload = _pf_fetch_object(name)
            if payload is not None:
                objects[name] = payload
        try:
            for row in db_get('mothershiptitledata'):
                key = row.get('datakey', '')
                if key.startswith('TitleDataObject_'):
                    objects[key[len('TitleDataObject_'):]] = safe_json_loads(
                        row.get('datavalue'), {'value': row.get('datavalue', '')})
        except Exception as e:
            print(f"[title objects] override load failed: {e}")
        _pf_object_cache['data'] = objects
        _pf_object_cache['ts'] = now
        if objects:
            print(f"[title objects] resolved {len(objects)}: {sorted(objects)}")
    return _pf_object_cache['data'] or {}


def _pf_title_data():
    """Fetch title data from PlayFab once per TTL window."""
    if not CONFIG['playfab_secret_key']:
        return {}
    now = time.time()
    if _pf_title_cache['data'] is not None and now - _pf_title_cache['ts'] < _PF_TITLE_TTL:
        return _pf_title_cache['data']
    try:
        result = playfab_request('POST', '/Server/GetTitleData', {})
        if result.get('status') == 200:
            data = (result.get('data', {}).get('data', {}) or {}).get('Data', {}) or {}
            _pf_title_cache['data'] = data
            _pf_title_cache['ts'] = now
            print(f"[title data] PlayFab: {len(data)} keys")
            return data
        print(f"[title data] PlayFab GetTitleData failed: {result.get('status')}")
    except Exception as e:
        print(f"[title data] PlayFab fetch failed: {e}")
    return {}


def get_title_data(keys=None):
    """Title data from PlayFab, overlaid by optional Supabase overrides.

    keys: comma-separated string; when given, returns only those keys.
    """
    data = _pf_title_data()
    try:
        rows = db_get('mothershiptitledata')
        for row in rows:
            data[row.get('datakey')] = row.get('datavalue', '')
    except Exception as e:
        print(f"[title_data error] {e}")

    _ensure_totd_rotation(data)

    if keys:
        keys_list = [k.strip() for k in keys.split(',') if k.strip()]
        return {k: data.get(k, '') for k in keys_list}
    return data


# ----------------------------------------------------------------------------
# TOTD (store pedestal rotation / rotating flashback cosmetics)
#
# The store's rotating pedestals are driven by the TOTD title-data key - a
# StoreUpdateEvent list of {PedestalID, ItemName, StartTimeUTC, EndTimeUTC}
# (see decompiled StoreUpdater.GetEventsFromTitleData). The live PlayFab title
# data has no TOTD key, and the old backend served one from the (now wiped)
# Supabase table - so the pedestals went empty.
#
# When PlayFab doesn't provide TOTD, we generate a deterministic weekly
# rotation server-side using REAL cosmetic item ids harvested from PlayFab's
# own title data (PropHuntProps / CustomMapCosmeticData lines like 'LBAFG.').
# A Supabase TOTD row always wins (it's part of the override layer).
# ----------------------------------------------------------------------------

_TOTD_PEDESTALS = ['CosmeticStand1', 'CosmeticStand2', 'CosmeticStand3']


def _harvest_cosmetic_item_ids(title_data):
    """Collect real cosmetic item ids from PlayFab title-data payloads."""
    ids = []

    def _add(candidate):
        candidate = str(candidate).strip().rstrip('\\n').strip()
        if re.fullmatch(r'[A-Z]{2,4}[A-Z0-9]{1,3}\.', candidate) and candidate not in ids:
            ids.append(candidate)

    for key in ('PropHuntProps', 'PropHuntProps_BetaJook', 'PropHauntProps'):
        raw = title_data.get(key)
        if isinstance(raw, str):
            for line in raw.replace('\r', '').split('\n'):
                _add(line)

    raw = title_data.get('CustomMapCosmeticData')
    if isinstance(raw, str):
        for m in re.finditer(r'"playFabID"\s*:\s*"([^"]+)"', raw):
            _add(m.group(1))

    return ids


def _ensure_totd_rotation(data):
    """Inject rotating-store/flashback title data when PlayFab has none.

    Two mechanisms are fed here (both resolved by the client against its
    title-data dictionary):
    - TOTD: StoreUpdateEvent list driving the store pedestals.
    - SetA/SetB: TitleDataObjectID targets of the RotatingFlashback schedule
      (rotating flashback cosmetic sets). Shape mirrors BundleData's
      {'Items': [{playFabItemName, shinyRocks, isActive, displayName}]}.
    A Supabase override row with the same key always wins.
    """
    if not isinstance(data, dict):
        return data
    try:
        items = _harvest_cosmetic_item_ids(data)
        if not items:
            return data

        now = datetime.now(timezone.utc)
        week_start = (now - timedelta(days=now.weekday())).replace(
            hour=22, minute=0, second=0, microsecond=0)
        iso_year, iso_week, _ = now.isocalendar()
        week_seed = iso_year * 53 + iso_week

        # ---- TOTD (store pedestals) ----
        existing_totd = data.get('TOTD')
        if not existing_totd or str(existing_totd).strip() in ('', '[]'):
            events = []
            for pedestal_idx, pedestal in enumerate(_TOTD_PEDESTALS):
                for week_offset in (-1, 0, 1):
                    start = week_start + timedelta(weeks=week_offset)
                    end = start + timedelta(weeks=1)
                    idx = ((week_seed + week_offset) * len(_TOTD_PEDESTALS)
                           + pedestal_idx)
                    events.append({
                        'PedestalID': pedestal,
                        'ItemName': items[idx % len(items)],
                        'StartTimeUTC': start.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                        'EndTimeUTC': end.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                    })
            data['TOTD'] = json.dumps(events)
            print(f"[TOTD] generated {len(events)} events from "
                  f"{len(items)} harvested cosmetic ids")

        # ---- RotatingFlashback sets (SetA/SetB) ----
        def _fmt_window(dt):
            """Official window format: '9/25/2026 5:00:00 PM' (portable)."""
            hour12 = dt.hour % 12 or 12
            ampm = 'AM' if dt.hour < 12 else 'PM'
            return (f"{dt.month}/{dt.day}/{dt.year} "
                    f"{hour12}:{dt.minute:02d}:{dt.second:02d} {ampm}")

        for set_name in ('SetA', 'SetB'):
            existing = data.get(set_name)
            if existing and str(existing).strip() not in ('', '{}'):
                continue
            # SetA = current window, SetB = previous 2-week window.
            offset_weeks = 0 if set_name == 'SetA' else -2
            window_start = week_start + timedelta(weeks=offset_weeks)
            window_end = window_start + timedelta(weeks=2)
            window_seed = (window_start.isocalendar()[0] * 53
                           + window_start.isocalendar()[1])

            def _price(n):
                return (100, 200, 250, 300, 400, 500, 750, 1000)[n % 8]

            set_items = []
            for i in range(15):
                item_id = items[(window_seed * 7 + i * 3) % len(items)]
                set_items.append({
                    'playFabItemName': item_id,
                    'shinyRocks': _price(window_seed + i),
                    'isActive': True,
                    'displayName': '',
                })
            data[set_name] = json.dumps({
                'Items': set_items,
                'StartDateTime': _fmt_window(window_start),
                'EndDateTime': _fmt_window(window_end),
            })
        print("[flashback] SetA/SetB rotation injected")
    except Exception as e:
        print(f"[TOTD/flashback] generation failed: {e}")
    return data


def _title_data_full():
    """Full title-data map (PlayFab + Supabase overrides). Kept as an alias
    for the route layer."""
    return get_title_data()

def title_data_results(keys_param=''):
    """Official /v1/title-data/client shape: {'Results': [{'key','data'}]}."""
    if keys_param:
        data = get_title_data(keys_param)
    else:
        data = get_title_data()
    return {'Results': [{'key': k, 'data': v} for k, v in data.items()]}

# ============================================================================
# Custom title-data files (HEATWAVE / Summer23 / Science24 hash-diff protocol)
# Just ADD A NEW ONE IF U WANT SO ENDPOINT NAME IS FIRST THEN FILE NAME AS U SEE BELOW
# ============================================================================

TITLE_DATA_FILES = {
    'HEATWAVE': 'HEATWAVE TITLE DATA.json',
    'Summer23': 'Summer23 TITLE DATA.json',
    'Science24': 'SCIENCE24 TITLE DATA.json',
}

# Keys the client expects as parsed JSON objects rather than strings
JSON_OBJECT_KEYS = {
    "DeployFeatureFlags", "KIDData", "AnnouncementData", "AllActiveQuests",
    "BundleData", "CreditsData", "AllowedClientVersions", "AutoMuteCheckedHours",
    "AutoName_Adverbs", "AutoName_Nouns", "MuteThresholds", "QueuePopulations",
    "QueueStats", "SharedBlocksTopMapConfig", "SharedBlocksStartingMapConfig",
    "SuperInfection", "ProgressionData", "GhostReactorProgression", "TOTD",
    "BannedNames", "StoreEvents", "CustomMapCosmeticData", "PropHuntProps",
    "PropHuntProps_BetaJook", "PrivateCrittersGrabSettings",
    "PublicCrittersGrabSettings",
}

def load_custom_title_data(filename):
    """Load one of the bundled custom title-data JSON files."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, 'data', filename),
        os.path.join(base_dir, os.path.basename(filename)),
        os.path.join(os.getcwd(), 'api', 'data', os.path.basename(filename)),
        os.path.join(os.getcwd(), os.path.basename(filename)),
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[title_data file] failed to load {path}: {e}")
                return None
    print(f"[title_data file] not found: {filename}")
    return None

def build_changed_title_data(title_data, client_hashes):
    """Return only keys the client is missing or whose hash changed."""
    changed = {}
    for key_name, value in (title_data or {}).items():
        if key_name not in client_hashes or client_hashes[key_name] is None:
            changed[key_name] = _parse_title_value(key_name, value)
        else:
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value, sort_keys=True)
            else:
                value_str = str(value)
            if hashlib.md5(value_str.encode()).hexdigest() != client_hashes[key_name]:
                changed[key_name] = _parse_title_value(key_name, value)
    return changed

def _parse_title_value(key, value):
    if key in JSON_OBJECT_KEYS and isinstance(value, str):
        parsed = safe_json_loads(value)
        if parsed is not None:
            return parsed
    if isinstance(value, str):
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        value = value.replace('\\n', '\n').replace('\\"', '"').replace('\\t', '\t')
    return value

# ============================================================================
# PlayFab server API helpers (optional cosmetics/DLC backing)
# ============================================================================

def playfab_request(method, path, body=None, timeout=20):
    if not CONFIG['playfab_title_id'] or not CONFIG['playfab_secret_key']:
        return {'error': 'PlayFab not configured', 'status': 400}
    path = path.lstrip('/')
    url = f"https://{CONFIG['playfab_title_id']}.playfabapi.com/{path}"
    headers = {
        'X-SecretKey': CONFIG['playfab_secret_key'],
        'Content-Type': 'application/json',
    }
    try:
        if method.upper() == 'GET':
            resp = requests.get(url, headers=headers, timeout=timeout)
        else:
            resp = requests.post(url, headers=headers, json=body or {}, timeout=timeout)
        try:
            data = resp.json()
        except Exception:
            data = {'raw': resp.text}
        return {'status': resp.status_code, 'data': data}
    except Exception as e:
        print(f"[PlayFab error] {path}: {e}")
        return {'error': str(e), 'status': 500}

def playfab_server_login(custom_id, create_account=True):
    return playfab_request('POST', '/Server/LoginWithServerCustomId', {
        'ServerCustomId': custom_id,
        'CreateAccount': create_account,
    })

def playfab_get_user_inventory(playfabid):
    return playfab_request('POST', '/Server/GetUserInventory', {'PlayFabId': playfabid})

def playfab_get_player_profile(playfabid):
    return playfab_request('POST', '/Server/GetPlayerProfile', {
        'PlayFabId': playfabid,
        'ProfileConstraints': {'ShowDisplayName': True, 'ShowAvatarUrl': True},
    })

def playfab_grant_items_to_user(playfabid, item_ids, catalog_version='DLC'):
    return playfab_request('POST', '/Server/GrantItemsToUser', {
        'PlayFabId': playfabid,
        'ItemIds': item_ids,
        'CatalogVersion': catalog_version,
    })

def playfab_update_display_name(playfabid, display_name):
    return playfab_request('POST', '/Admin/UpdateUserTitleDisplayName', {
        'PlayFabId': playfabid,
        'DisplayName': display_name,
    })

def playfab_ban_users(playfabids, reason, duration_hours=0):
    bans = [{'PlayFabId': p, 'Reason': reason, 'DurationInHours': duration_hours}
            for p in playfabids]
    return playfab_request('POST', '/Server/BanUsers', {'Bans': bans})

def playfab_pfid_from_session_ticket(ticket):
    """Session tickets look like '<PlayFabId>-...'."""
    if not ticket:
        return ''
    return ticket.split('-')[0]

# ============================================================================
# Mothership player tokens (ES256 JWT, 2h - mirrors official expiry)
# ============================================================================

def issue_token(playerid, userid, platform='STEAM'):
    now = int(time.time())
    exp = now + 7200
    payload = {
        'sub': playerid,
        'did': CONFIG['mothership_deployment_id'],
        'env': CONFIG['mothership_env_id'],
        'externalService': platform,
        'externalServiceId': userid,
        'tid': CONFIG['mothership_title_id'],
        'tags': None,
        'orgScopedExternalServiceId': userid,
        'nbf': now,
        'exp': exp,
        'iat': now,
    }
    if not JWT_PRIVATE_KEY:
        return {'token': '', 'exp': exp * 1000}
    token = jwt.encode(payload, JWT_PRIVATE_KEY, algorithm='ES256')
    return {'token': token, 'exp': exp * 1000}

def verify_token(token):
    """Returns the decoded claims dict, or None."""
    if not token or not JWT_PUBLIC_KEY:
        return None
    try:
        return jwt.decode(token, JWT_PUBLIC_KEY, algorithms=['ES256'])
    except Exception:
        return None

def mothership_from_headers():
    """Resolve the caller from the x-mothership-token header."""
    token = request.headers.get('x-mothership-token', '')
    decoded = verify_token(token)
    if not decoded:
        return ''
    return decoded.get('sub', '')

def mothership_auth_error():
    """Official-shaped 401 body for Mothership routes."""
    return jsonify({
        'message': json.dumps({
            'MothershipErrorCode': 10013,
            'ClientMessage': 'Client Authentication Failed',
            'TraceId': generate_uuid(),
        }),
        'statusCode': 401,
    }), 401

# ============================================================================
# Identity resolution / persistence helpers
# ============================================================================

def resolve_player(identifier):
    """Resolve a player by PlayFab ID, Mothership ID, device key or name."""
    clean = (identifier or '').strip()

    mention = re.match(r'<@!?(\d{17,20})>', clean)
    if mention:
        dl = db_get_one('discord_links', {'discord_id': mention.group(1)})
        if dl:
            return db_get_one('players', {'playfabid': dl.get('playfabid')})
        return None

    player = db_get_one('players', {'playfabid': clean})
    if player:
        return player

    ms = db_get_one('mothershipplayers', {'mothershipid': clean})
    if ms and ms.get('userid'):
        player = db_get_one('players', {'playfabid': ms['userid']})
        if player:
            return player

    device = db_get_one('device_players', {'device_key': clean})
    if device and device.get('playfabid'):
        return db_get_one('players', {'playfabid': device['playfabid']})

    return db_get_one('players', {'displayname': clean})

def ensure_player(playfabid):
    if not playfabid:
        return
    if not db_get_one('players', {'playfabid': playfabid}, 'playfabid'):
        db_insert('players', {'playfabid': playfabid, 'platform': 'Steam'})

def ensure_ranked_data(playfabid, platform):
    if not playfabid or not platform:
        return
    if not db_get_one('rankeddata', {'playfabid': playfabid, 'platform': platform}, 'playfabid'):
        db_insert('rankeddata', {'playfabid': playfabid, 'platform': platform,
                                 'elo': 1000, 'majortier': 2, 'minortier': 0,
                                 'rankprogress': 0})

def ensure_shift_credits(mothershipid):
    if not mothershipid:
        return
    if not db_get_one('shiftcredits', {'mothershipid': mothershipid}, 'mothershipid'):
        db_insert('shiftcredits', {'mothershipid': mothershipid,
                                   'currentcredits': 100,
                                   'capincreases': 0,
                                   'capincreasesmax': SHIFT_CREDIT_CAP_INCREASES_MAX})

def ensure_juicer_status(mothershipid):
    if not mothershipid:
        return
    if not db_get_one('juicerstatus', {'mothershipid': mothershipid}, 'mothershipid'):
        db_insert('juicerstatus', {'mothershipid': mothershipid,
                                   'corecount': 0, 'processingpercent': 0,
                                   'overdrivesupply': 0, 'overdrivecap': 5,
                                   'coresbyoverdrive': 0, 'refreshjuice': 0})

def ensure_dock_wrist(mothershipid):
    if not mothershipid:
        return
    if not db_get_one('dockwrist', {'mothershipid': mothershipid}, 'mothershipid'):
        db_insert('dockwrist', {'mothershipid': mothershipid,
                                'upgrade1level': 0, 'upgrade2level': 0,
                                'upgrade3level': 0, 'upgrade1max': 10,
                                'upgrade2max': 10, 'upgrade3max': 10})

def ensure_reactor_stats(mothershipid):
    if not mothershipid:
        return
    if not db_get_one('reactorstats', {'mothershipid': mothershipid}, 'mothershipid'):
        db_insert('reactorstats', {'mothershipid': mothershipid,
                                   'maxdepthreached': 0})

def ensure_reactor_inventory(mothershipid):
    if not mothershipid:
        return
    if not db_get_one('reactorinventory', {'mothershipid': mothershipid}, 'mothershipid'):
        db_insert('reactorinventory', {'mothershipid': mothershipid,
                                       'inventoryjson': '{}'})

def get_playfabid_from_request(body):
    """Extract the caller PlayFabId from a PlayFab-envelope request."""
    entity = body.get('Entity') or {}
    if entity.get('Id'):
        return entity['Id']
    params = body.get('FunctionParameter')
    if isinstance(params, dict) and params.get('PlayFabId'):
        return params['PlayFabId']
    profile = body.get('CallerEntityProfile') or {}
    lineage = profile.get('Lineage') or {}
    if lineage.get('MasterPlayerAccountId'):
        return lineage['MasterPlayerAccountId']
    if body.get('PlayFabId'):
        return body['PlayFabId']
    if body.get('PlayFabTicket'):
        return playfab_pfid_from_session_ticket(body['PlayFabTicket'])
    return None

# ============================================================================
# Super Infection (SI) - constants, storage and official-shaped helpers
# ============================================================================

SI_RESOURCE_COLUMNS = {
    'TechPoints': 'tech_points',
    'StrangeWood': 'strange_wood',
    'WeirdGear': 'weird_gear',
    'VibratingSpring': 'vibrating_spring',
    'BouncySand': 'bouncy_sand',
    'FloppyMetal': 'floppy_metal',
}

# Official /v1/inventory/client plain-key inventory shape
SI_INVENTORY_KEYS = [
    ('tech_points', 'TechPoints'),
    ('strange_wood', 'StrangeWood'),
    ('weird_gear', 'WeirdGear'),
    ('vibrating_spring', 'VibratingSpring'),
    ('bouncy_sand', 'BouncySand'),
    ('floppy_metal', 'FloppyMetal'),
]

# Entitlement ids captured from the official server - the client resolves
# progression-tree costs against these exact ids.
SI_ENTITLEMENT_IDS = {
    'SI_TechPoints': 'd4a0fad9-4602-435d-b379-cd5f69fb4321',
    'SI_StrangeWood': '078b85fb-c0d9-44d5-a3ca-e325819b13cd',
    'SI_WeirdGear': '427839b6-58a4-4e8b-9cb4-3d48cb1fb513',
    'SI_VibratingSpring': '5150d276-db1a-4263-bff4-edbe7b55f841',
    'SI_BouncySand': '8040ba58-afaa-44d3-bc0a-4d7864abf45d',
    'SI_FloppyMetal': '11844689-b2d0-4f02-923f-3bf49ba3aac6',
}

GR_ACCESS_ENTITLEMENTS = [
    {'entitlement_id': '3a71781f-b654-4df1-9c5f-f42705c1824d', 'in_game_id': 'InternAccess', 'name': 'InternAccess'},
    {'entitlement_id': '6e3a601f-949b-4cc0-ae9c-5eb7a934b4e8', 'in_game_id': 'PartTimeAccess', 'name': 'PartTimeAccess'},
    {'entitlement_id': '538ed093-e5bd-4cc7-86c6-861981b69241', 'in_game_id': 'FullTimeAccess', 'name': 'FullTimeAccess'},
    {'entitlement_id': '71def09d-cabd-428d-9118-a276c6e3c557', 'in_game_id': 'grServerUnlockDropPodBasic', 'name': 'grServerUnlockDropPodBasic'},
]

def _si_quest(qid, name, qtype, filt, count, zones=('none',), disable=False, category='NONE'):
    return {
        'disable': disable,
        'questID': qid,
        'weight': 1,
        'category': category,
        'questName': name,
        'questType': qtype,
        'questOccurenceFilter': filt,
        'requiredOccurenceCount': count,
        'requiredZones': list(zones),
    }

# Embedded official quest list (version "4") - fallback when title data
# has no AllActiveQuests entry.
SI_QUEST_DEFINITIONS_FALLBACK = [
    _si_quest(35, 'COLLECT WEIRD GEARS', 'misc', 'SISWeirdGearCollect', 5),
    _si_quest(1, 'COLLECT VIBRATING SPRINGS', 'misc', 'SIVibratingSpringCollect', 5),
    _si_quest(2, 'COLLECT CLUMPS OF BOUNCY SAND', 'misc', 'SIBouncySandCollect', 5),
    _si_quest(3, 'COLLECT PIECES OF FLOPPY METAL', 'misc', 'SIFloppyMetalCollect', 5),
    _si_quest(4, 'COLLECT PIECES OF STRANGE WOOD', 'misc', 'SIStrangeWoodCollect', 5),
    _si_quest(5, 'CLIMB THE TALLEST TREE', 'enterLocation', 'TallestTree', 1, zones=('forest',)),
    _si_quest(6, 'SWIM UNDER A WATERFALL', 'enterLocation', 'UnderWaterfall', 1),
    _si_quest(7, "CLIMB INTO THE CROW'S NEST", 'enterLocation', 'CrowsNest', 1),
    _si_quest(8, 'RIDE THE UPPER SLIDE', 'enterLocation', 'UpperSlide', 1),
    _si_quest(9, 'GET BLOWN BACK TO THE TOP OF THE MOUNTAIN', 'enterLocation', 'ReturnBlower', 1),
    _si_quest(10, 'FIND A SKULL OF YOUR ANCESTORS', 'enterLocation', 'CaveSkull', 1),
    _si_quest(11, 'PAY YOUR RESPECTS TO THE CHAMP', 'enterLocation', 'BoxerMonke', 1),
    _si_quest(12, 'TRAVEL 1KM', 'moveDistance', '', 1000),
    _si_quest(13, 'STAY OFF THE GROUND FOR 60 SECONDS IN A ROW', 'misc', 'remainInAirContinuous', 60, disable=True),
    _si_quest(14, 'HIT A MAX SPEED OF 30 METERS PER SECOND', 'moveDistance', 'maxSpeed', 30),
    _si_quest(15, 'CREATE A CHAIN OF 4 OR MORE PLAYERS', 'misc', 'playerHandholdChain', 4, disable=True),
    _si_quest(16, 'HELP ANOTHER MONKE COLLECT PIECES OF STRANGE WOOD', 'misc', 'SIHelpOtherCollectStrangeWood', 3),
    _si_quest(17, 'HELP ANOTHER MONKE COLLECT WEIRD GEARS', 'misc', 'SIHelpOtherCollectWeirdGears', 3),
    _si_quest(18, 'HELP ANOTHER MONKE COLLECT CLUMPS OF BOUNCY SAND', 'misc', 'SIHelpOtherCollectBouncySand', 3),
    _si_quest(19, 'HELP ANOTHER MONKE COLLECT PIECES OF FLOPPY METAL', 'misc', 'SIHelpOtherCollectFloppyMetal', 3),
    _si_quest(20, 'HELP ANOTHER MONKE COLLECT VIBRATING SPRINGS', 'misc', 'SIHelpOtherCollectVibratingSpring', 3),
    _si_quest(21, 'GET TAGS WHILE USING A STILT GADGET', 'misc', 'SIStiltTag', 10, disable=True, category='Tag'),
    _si_quest(22, 'GET TAGS WHILE USING A THRUSTER GADGET', 'misc', 'SIThrusterTag', 10, disable=True, category='Tag'),
    _si_quest(23, 'GET TAGS WHILE USING A DASH GADGET', 'misc', 'SIDashTag', 10, disable=True, category='Tag'),
    _si_quest(24, 'GET TAGS WHILE USING A PLATFORM GADGET', 'misc', 'SIPlatformTag', 10, disable=True, category='Tag'),
    _si_quest(25, 'GET TAGS WHILE USING A BORROWED GADGET', 'misc', 'SIBorrowedGadgetTag', 10, disable=True, category='Tag'),
    _si_quest(26, 'PLAY 3 ROUNDS', 'gameModeRound', 'SUPER INFEC', 3, zones=('forest',), category='GameRound'),
    _si_quest(27, 'PLAY 3 ROUNDS', 'gameModeRound', 'SUPER INFEC', 3, zones=('mountain',), category='GameRound'),
    _si_quest(28, 'PLAY 3 ROUNDS', 'gameModeRound', 'SUPER INFEC', 3, zones=('cave',), category='GameRound'),
    _si_quest(29, 'PLAY 3 ROUNDS', 'gameModeRound', 'SUPER INFEC', 3, zones=('beach',), category='GameRound'),
    _si_quest(30, 'PLAY 3 ROUNDS', 'gameModeRound', 'SUPER INFEC', 3, zones=('skyJungle',), category='GameRound'),
    _si_quest(31, 'PLAY 3 ROUNDS', 'gameModeRound', 'SUPER INFEC', 3, zones=('canyon',), category='GameRound'),
    _si_quest(32, 'PLAY 3 ROUNDS', 'gameModeRound', 'SUPER INFEC', 3, zones=('Metropolis',), category='GameRound'),
    _si_quest(33, 'GET TAGS', 'misc', 'SIGameModeTag', 10, category='Tag'),
    _si_quest(34, 'PLAY 5 ROUNDS', 'gameModeRound', 'SUPER INFEC', 5, category='GameRound'),
]

# Official fresh-day claim quotas. Captured on the official server
# 2026-10-03 09:12: {"todayClaimableQuests":9,"todayClaimableBonus":3,
# "todayClaimableIdol":1}, decrementing 9 -> 8 -> 7 with every
# SetSIQuestComplete. The client shows these as the day's claimable rewards.
SI_DAILY_CLAIMABLE_QUESTS = 9
SI_DAILY_CLAIMABLE_BONUS = 3


def si_ensure_player_exists(mothershipid):
    """Ensure the player has SI resource + quest-status rows. Accepts the
    legacy 2-arg call style (playfabid, mothershipid) silently."""
    if not mothershipid:
        return
    if not db_get_one('si_player_resources', {'mothershipid': mothershipid}, 'mothershipid'):
        db_insert('si_player_resources', {
            'mothershipid': mothershipid,
            'tech_points': 0, 'strange_wood': 0, 'weird_gear': 0,
            'vibrating_spring': 0, 'bouncy_sand': 0, 'floppy_metal': 0,
        })
    if not db_get_one('si_player_quest_status', {'mothershipid': mothershipid}, 'mothershipid'):
        db_insert('si_player_quest_status', {
            'mothershipid': mothershipid,
            'stashed_quests': SI_DAILY_CLAIMABLE_QUESTS,
            'stashed_bonus_points': SI_DAILY_CLAIMABLE_BONUS,
            'bonus_progress': 0,
            'daily_limited_turned_in': False,
        })

def si_get_inventory(mothershipid):
    """Official plain-key inventory dict: {TechPoints, StrangeWood, ...}."""
    row = db_get_one('si_player_resources', {'mothershipid': mothershipid})
    if not row:
        si_ensure_player_exists(mothershipid)
        row = db_get_one('si_player_resources', {'mothershipid': mothershipid})
    row = row or {}
    return {key: int(row.get(col, 0) or 0) for col, key in SI_INVENTORY_KEYS}

def si_update_resources(mothershipid, updates):
    if updates:
        db_update('si_player_resources', {'mothershipid': mothershipid}, updates)

def si_quest_status_response(status):
    return {
        'result': {
            'todayClaimableQuests': max(0, int(status.get('stashed_quests', 0) or 0)),
            'todayClaimableBonus': max(0, int(status.get('stashed_bonus_points', 0) or 0)),
            'todayClaimableIdol': 0 if status.get('daily_limited_turned_in', False) else 1,
        },
        'statusCode': 200,
        'error': None,
    }

def si_get_quest_status(mothershipid):
    row = db_get_one('si_player_quest_status', {'mothershipid': mothershipid})
    if not row:
        si_ensure_player_exists(mothershipid)
        row = db_get_one('si_player_quest_status', {'mothershipid': mothershipid})
    return row or {
        'stashed_quests': SI_DAILY_CLAIMABLE_QUESTS,
        'stashed_bonus_points': SI_DAILY_CLAIMABLE_BONUS,
        'bonus_progress': 0,
        'daily_limited_turned_in': False, 'last_reset_date': None,
    }

def si_roll_daily_reset(mothershipid):
    """Grant a new UTC day's claimables (capped at the official fresh-day
    amounts: quests<=9, bonus<=3, idol re-armed). Leftovers do NOT accumulate
    beyond the official caps, so a stale row self-heals on the next day."""
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    status = si_get_quest_status(mothershipid)
    last_reset = str(status.get('last_reset_date') or '')[:10]

    if last_reset == today:
        return status

    fresh = {
        'stashed_quests': min(SI_DAILY_CLAIMABLE_QUESTS,
                              max(0, int(status.get('stashed_quests', 0) or 0))
                              + SI_DAILY_CLAIMABLE_QUESTS),
        'stashed_bonus_points': min(SI_DAILY_CLAIMABLE_BONUS,
                                    max(0, int(status.get('stashed_bonus_points', 0) or 0))
                                    + SI_DAILY_CLAIMABLE_BONUS),
        'bonus_progress': 0,
        'daily_limited_turned_in': False,
        'last_reset_date': today,
        'updated_at': utc_now_iso(),
    }
    db_update('si_player_quest_status', {'mothershipid': mothershipid}, fresh)
    status.update(fresh)
    return status

def si_load_quest_definitions():
    """Official SI quest board.

    IMPORTANT: the Super Infection board is NOT PlayFab's AllActiveQuests -
    that key holds the BASE-GAME board ('PLAY INFECTION', 'TAG PLAYERS',
    'SMASH BREAKABLES IN GHOST REACTOR'...). Serving it on /api/GetActiveSIQuests
    replaces the SI board with normal quests. The SI board is the dedicated
    list captured on the official revamp server (embedded below), optionally
    overridden by a Supabase mothershiptitledata row keyed 'SIQuests' (or the
    legacy 'AllActiveQuests' row stored in SUPABASE only).
    """
    quests = []
    # Supabase-only override rows (never PlayFab's AllActiveQuests)
    try:
        rows = db_get('mothershiptitledata', {'datakey': 'SIQuests'})
        if not rows:
            rows = db_get('mothershiptitledata', {'datakey': 'AllActiveQuests'})
        raw = rows[0].get('datavalue') if rows else None
        if raw:
            data = safe_json_loads(raw, {}) if isinstance(raw, str) else raw
            for group in (data or {}).get('DailyQuests', []) + (data or {}).get('WeeklyQuests', []):
                for quest in group.get('quests', []):
                    if isinstance(quest, dict) and quest.get('questID') is not None:
                        quests.append(quest)
    except Exception as e:
        print(f"[SI quests] override load failed: {e}")

    if not quests:
        quests = SI_QUEST_DEFINITIONS_FALLBACK

    return {'result': {'quests': quests, 'version': '4'},
            'statusCode': 200, 'error': None}

def si_request_identity(body, require_token=True):
    """Resolve+validate MothershipId/MothershipToken. Returns (id, error)."""
    mothershipid = body.get('MothershipId', '')
    token = body.get('MothershipToken', '')
    if not mothershipid and token:
        decoded = verify_token(token)
        if decoded:
            mothershipid = decoded.get('sub', '')
    if not token:
        if require_token:
            return None, (jsonify({'result': None, 'statusCode': 401,
                                   'error': 'Missing MothershipToken'}), 401)
        return mothershipid, None
    decoded = verify_token(token)
    if not decoded:
        return None, (jsonify({'result': None, 'statusCode': 401,
                               'error': 'Invalid MothershipToken'}), 401)
    if mothershipid and str(decoded.get('sub', '')) != str(mothershipid):
        return None, (jsonify({'result': None, 'statusCode': 401,
                               'error': 'MothershipToken does not match MothershipId'}), 401)
    return mothershipid or decoded.get('sub', ''), None

# ============================================================================
# Name filtering (CheckForBadName / room / troop names)
# ============================================================================

BAD_NAME_PATTERNS = [
    r'n[i1!|]gg', r'f[a4@]g{1,2}', r'k[i1!|]ke', r'sp[i1!|]c', r'ch[i1!|]nk',
    r'g[o0]{2}k', r'tr[a4@]nn[yi]', r'c[u\*]nt', r'wh[o0]r[e3]', r'sl[u\*]t',
    r'b[i1!|]tch', r'd[i1!|]ck', r'c[o0]ck', r'p[u\*]ss[yi]', r'c[u\*]m',
    r'f[u\*]ck', r'sh[i1!|]t', r'p[o0]rn', r'h[i1!|]tl[e3]r', r'p[e3]n[i1!|]s',
    r'v[a4@]g[i1!|]n[a4@]', r'm[o0]nk[e3]ysl[a4@]v[e3]', r'k[yi]s',
]

def name_check_result(name):
    """0 = OK, 2 = blocked (matches the official result codes)."""
    if not name or not str(name).strip():
        return 0, ''
    lower = str(name).lower()
    for pattern in BAD_NAME_PATTERNS:
        if re.search(pattern, lower):
            return 2, f'Contains blacklisted word matching "{pattern}"'
    return 0, ''

# ============================================================================
# Rate limiting (best-effort, per-instance)
# ============================================================================

rate_limit_storage = {}

def rate_limit(limit=60, window=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr or 'unknown'
            key = f"{request.path}:{ip}"
            now = time.time()
            for k in list(rate_limit_storage.keys()):
                if now - rate_limit_storage[k]['reset'] > 0:
                    del rate_limit_storage[k]
            entry = rate_limit_storage.get(key)
            if entry is None:
                rate_limit_storage[key] = {'count': 1, 'reset': now + window}
            elif entry['count'] >= limit:
                return {'error': 'Too many requests, try again later.'}, 429
            else:
                entry['count'] += 1
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============================================================================
# Routes - basics
# ============================================================================

@app.route('/', methods=['GET'])
def index():
    return 'OK', 200

@app.route('/health', methods=['GET'])
@app.route('/healthz', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'ccu': get_ccu()})

# ============================================================================
# Routes - auth (device-key method - DO NOT REPLACE WITH REAL STEAM AUTH)
# ============================================================================

def _auth_payload_for(mothershipid, external_id, external_username='', platform='STEAM'):
    """Build the official auth response; reuses a cached unexpired token.

    NOTE: token claims include the deployment/env/title ids baked into CONFIG
    below; the client echoes those ids back. If you change the Mothership
    identifiers, already-issued cached tokens keep working until they expire
    (2h)."""
    if not mothershipid:
        return None
    player = db_get_one('mothershipplayers', {'mothershipid': mothershipid})
    if player and player.get('token') and \
            int(player.get('expirationtime', 0) or 0) > now_ms() + 1800000:
        update_player_presence(mothershipid)
        return {
            'ExternalProviderId': external_id,
            'ExternalProviderUsername': external_username,
            'IsPrimaryId': True,
            'PlayerId': mothershipid,
            'Tags': None,
            'Token': player['token'],
            'ServerTime': now_ms(),
            'ExpirationTime': player['expirationtime'],
        }
    token_data = issue_token(mothershipid, external_id, platform)
    db_upsert('mothershipplayers', {
        'mothershipid': mothershipid,
        'userid': external_id,
        'platform': platform,
        'token': token_data['token'],
        'expirationtime': token_data['exp'],
        'lastlogin': utc_now_iso(),
    }, 'mothershipid')
    update_player_presence(mothershipid)
    return {
        'ExternalProviderId': external_id,
        'ExternalProviderUsername': external_username,
        'IsPrimaryId': True,
        'PlayerId': mothershipid,
        'Tags': None,
        'Token': token_data['token'],
        'ServerTime': now_ms(),
        'ExpirationTime': token_data['exp'],
    }


def _device_login_or_create(device_key, platform='Steam'):
    """Return (playfabid, mothershipid, is_new) for a device key.

    The device_players row is the single source of truth: the PlayFab account
    AND the MothershipID are bound to the device key on first login and are
    PERMANENT - they never rotate or get re-issued.
    """
    device = db_get_one('device_players', {'device_key': device_key})
    if device:
        playfabid = device.get('playfabid')
        mothershipid = device.get('mothershipid')
        if not mothershipid:  # legacy rows created before the permanent binding
            mothershipid = generate_uuid()
            db_update('device_players', {'device_key': device_key},
                      {'mothershipid': mothershipid})
        db_update('device_players', {'device_key': device_key},
                  {'last_login': utc_now_iso()})
        ensure_player(playfabid)
        si_ensure_player_exists(mothershipid)
        return playfabid, mothershipid, False

    # New device: create its PlayFab account (cosmetics wallet)
    playfabid = ''
    if CONFIG['playfab_secret_key']:
        custom_id = f"DEVICE_{device_key[:20]}"
        result = playfab_server_login(custom_id, True)
        if result.get('status') != 200:
            result = playfab_server_login(f"DEV_{device_key[:16]}", True)
        if result.get('status') == 200:
            playfabid = result.get('data', {}).get('data', {}).get('PlayFabId', '')
    if not playfabid:
        # PlayFab unavailable/unconfigured: derive a stable offline id so the
        # private server still works end-to-end.
        playfabid = hashlib.sha256(f"DEVICE_{device_key}".encode()).hexdigest()[:16].upper()

    mothershipid = generate_uuid()
    db_insert('device_players', {
        'device_key': device_key,
        'playfabid': playfabid,
        'mothershipid': mothershipid,
        'platform': platform,
        'created_at': utc_now_iso(),
        'last_login': utc_now_iso(),
    })
    ensure_player(playfabid)
    si_ensure_player_exists(mothershipid)
    print(f"[auth] new device {device_key[:8]}... -> PlayFab={playfabid} Mothership={mothershipid}")
    return playfabid, mothershipid, True


@app.route('/v2/player/client/auth/begin/STEAM', methods=['GET', 'POST'])
def steam_auth_begin_v2():
    """Official shape: {'Nonce': '<24-char base62>'} (captured example)."""
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    nonce = ''.join(secrets.choice(alphabet) for _ in range(24))
    return jsonify({'Nonce': nonce}), 200


@app.route('/v2/player/client/auth/complete/STEAM', methods=['POST', 'GET'])
@rate_limit(limit=30, window=60)
def steam_auth_complete_v2():
    """Complete device-key auth. The 'ticket' IS the device key (custom-ID
    method). Issues/refreshes the permanent MothershipID binding."""
    try:
        nonce = request.args.get('nonce') or request.form.get('nonce')
        ticket = request.args.get('ticket') or request.form.get('ticket')
        userid = request.args.get('userId') or request.form.get('userId')
        if not nonce or not ticket:
            body = request.get_json(silent=True) or {}
            nonce = nonce or body.get('nonce') or body.get('Nonce')
            ticket = ticket or body.get('ticket') or body.get('Ticket') or body.get('SteamTicket')
            userid = userid or body.get('userId') or body.get('UserId') or body.get('userid')

        if not ticket:
            return jsonify({'message': 'Missing ticket', 'statusCode': 400}), 400

        # Nonce check is best-effort: begin/complete can hit different
        # serverless instances, so a miss must not lock players out.
        if nonce:
            print(f"[auth] complete nonce={str(nonce)[:24]}")

        device_key = (userid or ticket).strip()
        if not re.match(r'^[A-Za-z0-9_\-]{8,128}$', device_key):
            return jsonify({'message': 'Invalid device key', 'statusCode': 400}), 400

        playfabid, mothershipid, _is_new = _device_login_or_create(device_key, 'Steam')
        payload = _auth_payload_for(mothershipid, playfabid, '', 'STEAM')
        if not payload:
            return jsonify({'message': 'Could not create player', 'statusCode': 401}), 401
        return jsonify(payload), 201

    except Exception as e:
        print(f"[auth] complete error: {e}")
        return mothership_auth_error()


@app.route('/v1/client/player/auth/STEAM', methods=['POST'])
@rate_limit(limit=30, window=60)
def steam_auth_v1():
    """Single-step V1 device auth: UserId (or ticket) is the device key."""
    try:
        body = request.get_json(silent=True) or {}
        device_key = (body.get('UserId') or body.get('Ticket') or body.get('DeviceKey') or '').strip()
        if not device_key:
            return mothership_auth_error()
        playfabid, mothershipid, _ = _device_login_or_create(device_key, 'STEAM')
        payload = _auth_payload_for(mothershipid, playfabid, '', 'STEAM')
        if not payload:
            return mothership_auth_error()
        return jsonify(payload), 201
    except Exception as e:
        print(f"[auth] v1 error: {e}")
        return mothership_auth_error()


@app.route('/api/DeviceLogin', methods=['POST'])
@rate_limit(limit=30, window=60)
def device_login():
    """Device-locked login with a permanent PlayFab account + MothershipID."""
    try:
        body = request.get_json(silent=True) or {}
        device_key = (body.get('DeviceKey') or '').strip()
        platform = body.get('Platform', 'Steam')

        if not device_key:
            return jsonify({'code': 400, 'status': 'BadRequest', 'error': 'Missing DeviceKey',
                            'errorCode': 1007, 'errorMessage': 'DeviceKey is required'}), 400
        if not re.match(r'^[A-Za-z0-9_\-]{8,128}$', device_key):
            return jsonify({'code': 400, 'status': 'BadRequest', 'error': 'Invalid DeviceKey format',
                            'errorCode': 1008,
                            'errorMessage': 'DeviceKey must be 8-128 alphanumeric characters'}), 400

        playfabid, mothershipid, is_new = _device_login_or_create(device_key, platform)
        token_data = issue_token(mothershipid, playfabid, platform)
        db_upsert('mothershipplayers', {
            'mothershipid': mothershipid,
            'userid': playfabid,
            'platform': platform,
            'token': token_data['token'],
            'expirationtime': token_data['exp'],
            'lastlogin': utc_now_iso(),
        }, 'mothershipid')
        update_player_presence(mothershipid)

        device = db_get_one('device_players', {'device_key': device_key}) or {}
        session_ticket = ''
        entity_token = entity_id = entity_type = ''
        if CONFIG['playfab_secret_key']:
            result = playfab_server_login(f"DEVICE_{device_key[:20]}", False)
            if result.get('status') == 200:
                d = result.get('data', {}).get('data', {})
                session_ticket = d.get('SessionTicket', '')
                entity_token = d.get('EntityToken', {}).get('EntityToken', '')
                entity_id = d.get('EntityToken', {}).get('Entity', {}).get('Id', '')
                entity_type = d.get('EntityToken', {}).get('Entity', {}).get('Type', '')

        return jsonify({
            'PlayFabId': playfabid,
            'SessionTicket': session_ticket,
            'EntityToken': entity_token,
            'EntityId': entity_id,
            'EntityType': entity_type,
            'MothershipId': mothershipid,
            'MothershipToken': token_data['token'],
            'TokenExpiration': token_data['exp'],
            'AccountCreationIsoTimestamp': device.get('created_at', utc_now_iso()),
            'IsNewPlayer': is_new,
            'AuthMethod': 'device',
            'Permanent': True,
        })
    except Exception as e:
        print(f"[DeviceLogin error] {e}")
        return jsonify({'code': 500, 'status': 'InternalServerError', 'error': 'Internal server error',
                        'errorCode': 1127, 'errorMessage': str(e)}), 500


@app.route('/api/DeviceAuthStatus', methods=['POST'])
def device_auth_status():
    body = request.get_json(silent=True) or {}
    device_key = (body.get('DeviceKey') or '').strip()
    if not device_key:
        return jsonify({'exists': False, 'error': 'Missing DeviceKey'}), 400
    device = db_get_one('device_players', {'device_key': device_key})
    if device:
        return jsonify({
            'exists': True,
            'playfabid': device.get('playfabid'),
            'mothershipid': device.get('mothershipid'),
            'created_at': device.get('created_at'),
            'last_login': device.get('last_login'),
            'platform': device.get('platform'),
        })
    return jsonify({'exists': False, 'playfabid': None, 'mothershipid': None,
                    'created_at': None, 'last_login': None, 'platform': None})


# ---------------------------------------------------------------------------
# PlayFab facade - the client's PlayFab SDK calls hit our backend directly.
# The LoginWithSteam ticket is the DEVICE KEY (custom-ID method).
# ---------------------------------------------------------------------------

PF_CODE_OK = {'code': 200, 'status': 'OK'}

def _pf_ok(data):
    out = dict(PF_CODE_OK)
    out['data'] = data
    return out

@app.route('/Client/LoginWithSteam', methods=['POST'])
@app.route('/Client/LoginWithCustomID', methods=['POST'])
@rate_limit(limit=30, window=60)
def client_login_with_steam():
    """LoginWithSteam / LoginWithCustomID facade. The SteamTicket field
    carries the device key; one PlayFab account is bound to it forever.
    Official response shape (captured)."""
    try:
        body = request.get_json(silent=True) or {}
        ticket = body.get('SteamTicket') or body.get('CustomId') or ''
        if not ticket:
            return jsonify({'code': 400, 'status': 'BadRequest', 'error': 'Missing ticket',
                            'errorCode': 1007, 'errorMessage': 'SteamTicket is required'}), 400

        device_key = ticket.strip()
        playfabid, mothershipid, is_new = _device_login_or_create(device_key, 'Steam')

        session_ticket = f"{playfabid}-GTAGPRIV-0000000000000000-63FDD-0000000000000000-PRIVATE"
        entity_token = ''
        entity_id = ''
        last_login = utc_now_iso()

        if CONFIG['playfab_secret_key']:
            custom_id = f"DEVICE_{device_key[:20]}"
            result = playfab_server_login(custom_id, False)
            if result.get('status') != 200:
                result = playfab_server_login(custom_id, True)
            if result.get('status') == 200:
                d = result.get('data', {}).get('data', {})
                session_ticket = d.get('SessionTicket', session_ticket)
                et = d.get('EntityToken', {}) or {}
                entity_token = et.get('EntityToken', '')
                entity_id = et.get('Entity', {}).get('Id', '')
                last_login = d.get('LastLoginTime', last_login)

        update_player_presence(mothershipid)
        return jsonify(_pf_ok({
            'SessionTicket': session_ticket,
            'PlayFabId': playfabid,
            'NewlyCreated': is_new,
            'SettingsForUser': {'NeedsAttribution': False, 'GatherDeviceInfo': True,
                                'GatherFocusInfo': False},
            'LastLoginTime': last_login,
            'EntityToken': {
                'EntityToken': entity_token,
                'TokenExpiration': (datetime.now(timezone.utc) + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'Entity': {'Id': entity_id or playfabid, 'Type': 'title_player_account',
                           'TypeString': 'title_player_account'},
            },
            'TreatmentAssignment': {'Variants': [], 'Variables': []},
        }))
    except Exception as e:
        print(f"[LoginWithSteam error] {e}")
        return jsonify({'code': 500, 'status': 'InternalServerError', 'error': 'LoginFailed',
                        'errorCode': 1124, 'errorMessage': str(e)}), 500


@app.route('/api/PlayFabAuthentication', methods=['POST'])
@rate_limit(limit=30, window=60)
def playfab_auth():
    """Oculus/legacy path - kept as-is (custom-ID auth against PlayFab)."""
    try:
        body = request.get_json(silent=True) or {}
        oculusid = (body.get('OculusId') or '').replace('OCULUS', '').strip()
        platform = body.get('Platform', 'Quest')
        mothershipid = body.get('MothershipId', '')
        if not oculusid:
            return jsonify({'Message': 'Missing OculusId'}), 400

        result = playfab_server_login(f"OCULUS{oculusid}", True)
        if result.get('status') == 200 and result.get('data', {}).get('data'):
            d = result['data']['data']
            sessionticket = d.get('SessionTicket', '')
            entitytoken = d.get('EntityToken', {}).get('EntityToken', '')
            playfabid = d.get('PlayFabId', '')
            entityid = d.get('EntityToken', {}).get('Entity', {}).get('Id', '')
            entitytype = d.get('EntityToken', {}).get('Entity', {}).get('Type', '')

            ensure_player(playfabid)
            db_upsert('players', {
                'playfabid': playfabid,
                'oculusid': oculusid,
                'platform': platform,
                'sessionticket': sessionticket,
                'entitytoken': entitytoken,
                'entityid': entityid,
                'entitytype': entitytype,
                'lastlogin': utc_now_iso(),
            }, 'playfabid')

            if mothershipid:
                update_player_presence(mothershipid)

            player = db_get_one('players', {'playfabid': playfabid}, 'createdat')
            creationiso = (player or {}).get('createdat', utc_now_iso())
            return jsonify({
                'SessionTicket': sessionticket,
                'EntityToken': entitytoken,
                'PlayFabId': playfabid,
                'EntityId': entityid,
                'EntityType': entitytype,
                'AccountCreationIsoTimestamp': creationiso,
            })

        if result.get('data', {}).get('errorCode') == 1002:
            errmsg = result['data'].get('errorMessage', 'Banned')
            errdetails = result['data'].get('errorDetails', {}) or {}
            bankey = list(errdetails.keys())[0] if errdetails else errmsg
            banlist = errdetails.get(bankey, [])
            banexpiry = banlist[0] if banlist else 'Indefinite'
            return jsonify({'BanMessage': bankey, 'BanExpirationTime': banexpiry}), 403

        return jsonify({'Message': 'Authentication failed'}), 500
    except Exception as e:
        print(f"[auth error] {e}")
        return jsonify({'Message': 'Internal server error'}), 500


@app.route('/api/CachePlayFabId', methods=['POST'])
@rate_limit(limit=30, window=60)
def cache_playfab_id():
    """Official shape (captured): PlayFabId, SteamAuthIdForPhoton,
    AccountCreationIsoTimestamp, FriendCode."""
    try:
        body = request.get_json(silent=True) or {}
        sessionticket = body.get('SessionTicket', '')
        playfabid = (body.get('PlayFabId') or
                     playfab_pfid_from_session_ticket(sessionticket)).strip()
        platform = body.get('Platform', 'Steam')
        mothershipid = body.get('MothershipId', '')

        if not playfabid:
            return jsonify({'Message': 'Try Again Later.'}), 404

        ensure_player(playfabid)
        db_upsert('players', {
            'playfabid': playfabid,
            'sessionticket': sessionticket,
            'platform': platform,
            'lastlogin': utc_now_iso(),
        }, 'playfabid')

        if mothershipid:
            update_player_presence(mothershipid)

        player = db_get_one('players', {'playfabid': playfabid}, 'createdat')
        creationiso = (player or {}).get('createdat', utc_now_iso())
        return jsonify({
            'PlayFabId': playfabid,
            'SteamAuthIdForPhoton': generate_code(24),
            'AccountCreationIsoTimestamp': creationiso,
            'FriendCode': None,
            'Message': None,
        })
    except Exception as e:
        print(f"[cache error] {e}")
        return jsonify({'Message': 'Internal server error'}), 500

# ============================================================================
# Routes - PlayFab facade (read-only data the client fetches through the SDK)
# ============================================================================

@app.route('/Client/GetCatalogItems', methods=['GET', 'POST'])
def get_catalog_items():
    """DLC catalog. /Client/* uses the PlayFab envelope; /api/GetCatalogItems
    (legacy route the cosmetics system reads) returns the PLAIN shape:
    {'Catalog': [...], 'CatalogVersion': 'DLC'}."""
    try:
        body = request.get_json(silent=True) or {}
        catalog_version = 'DLC'
        param = body.get('FunctionParameter')
        if isinstance(param, dict) and param.get('CatalogVersion'):
            catalog_version = param['CatalogVersion']
        elif body.get('CatalogVersion'):
            catalog_version = body['CatalogVersion']

        catalog = []
        if CONFIG['playfab_secret_key']:
            result = playfab_request('POST', '/Server/GetCatalogItems',
                                     {'CatalogVersion': catalog_version})
            if result.get('status') == 200:
                catalog_data = result.get('data', {}).get('data', {}) or {}
                catalog = catalog_data.get('Catalog', []) or []

        plain = {'Catalog': catalog, 'CatalogVersion': catalog_version}
        if request.path.startswith('/Client/'):
            return jsonify(_pf_ok(plain))
        return jsonify(plain)
    except Exception as e:
        print(f"[catalog error] {e}")
        plain = {'Catalog': [], 'CatalogVersion': 'DLC'}
        if request.path.startswith('/Client/'):
            return jsonify(_pf_ok(plain))
        return jsonify(plain)


@app.route('/api/GetCatalogItems', methods=['GET', 'POST'])
def api_get_catalog_items():
    """Legacy PLAIN catalog shape (cosmetics/DLC store reads this)."""
    return get_catalog_items() if request.path.startswith('/api/') else None


@app.route('/Client/GetUserInventory', methods=['GET', 'POST'])
def client_get_user_inventory():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = get_playfabid_from_request(body)
        if playfabid and CONFIG['playfab_secret_key']:
            result = playfab_get_user_inventory(playfabid)
            if result.get('status') == 200:
                return jsonify(result['data'])
        return jsonify(_pf_ok({'Inventory': [], 'VirtualCurrency': {}}))
    except Exception as e:
        print(f"[inventory error] {e}")
        return jsonify(_pf_ok({'Inventory': [], 'VirtualCurrency': {}}))


@app.route('/Client/GetPlayerProfile', methods=['GET', 'POST'])
def client_get_player_profile():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = get_playfabid_from_request(body)
        display_name = ''
        if playfabid:
            player = db_get_one('players', {'playfabid': playfabid})
            display_name = (player or {}).get('displayname') or playfabid
            if CONFIG['playfab_secret_key']:
                result = playfab_get_player_profile(playfabid)
                pf_name = (result.get('data', {}).get('data', {})
                           .get('PlayerProfile', {}).get('DisplayName'))
                if pf_name:
                    display_name = pf_name
                    if not (player or {}).get('displayname'):
                        db_update('players', {'playfabid': playfabid},
                                  {'displayname': pf_name})
        else:
            display_name = generate_code(8)
        return jsonify(_pf_ok({'PlayerProfile': {
            'PublisherId': '', 'TitleId': CONFIG['playfab_title_id'],
            'PlayerId': playfabid or '', 'DisplayName': display_name,
        }}))
    except Exception as e:
        print(f"[profile error] {e}")
        return jsonify(_pf_ok({'PlayerProfile': {'DisplayName': ''}}))


@app.route('/Client/GetTime', methods=['GET', 'POST'])
def client_get_time():
    return jsonify(_pf_ok({'Time': utc_now_iso()}))


@app.route('/Client/GetUserReadOnlyData', methods=['GET', 'POST'])
def client_get_user_read_only_data():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = get_playfabid_from_request(body)
        requested = body.get('Keys') or []
        data = {}
        if playfabid:
            rows = db_get('player_readonlydata', {'playfabid': playfabid})
            for row in rows:
                if not requested or row.get('datakey') in requested:
                    data[row['datakey']] = {
                        'Value': row.get('datavalue', ''),
                        'LastUpdated': row.get('updatedat', utc_now_iso()),
                        'Permission': 'Private',
                    }
        return jsonify(_pf_ok({'Data': data, 'DataVersion': len(data)}))
    except Exception as e:
        print(f"[readonly error] {e}")
        return jsonify(_pf_ok({'Data': {}, 'DataVersion': 0}))


@app.route('/Client/UpdateUserTitleDisplayName', methods=['GET', 'POST'])
def client_update_display_name():
    try:
        body = request.get_json(silent=True) or {}
        name = ''
        params = body.get('FunctionParameter') or body.get('Data') or {}
        if isinstance(params, dict):
            name = str(params.get('DisplayName') or params.get('name') or '')
        else:
            name = str(params)
        playfabid = get_playfabid_from_request(body)
        if playfabid and name:
            db_upsert('players', {'playfabid': playfabid, 'displayname': name}, 'playfabid')
            if CONFIG['playfab_secret_key']:
                playfab_update_display_name(playfabid, name)
        return jsonify(_pf_ok({'DisplayName': name}))
    except Exception as e:
        print(f"[display name error] {e}")
        return jsonify(_pf_ok({'DisplayName': ''}))


@app.route('/Client/PurchaseItem', methods=['GET', 'POST'])
def client_purchase_item():
    """Shiny Rocks purchases: grant the item locally (no real payment)."""
    try:
        body = request.get_json(silent=True) or {}
        playfabid = get_playfabid_from_request(body)
        item_id = ''
        params = body.get('FunctionParameter')
        if isinstance(params, dict):
            item_id = params.get('ItemId', '')
        elif isinstance(params, list) and params:
            item_id = params[0]
        if not item_id:
            item_id = body.get('ItemId', '')
        granted = []
        if item_id:
            granted = [{
                'ItemId': item_id,
                'ItemInstanceId': generate_code(16),
                'PurchaseDate': utc_now_iso(),
                'CatalogVersion': 'DLC',
                'DisplayName': item_id,
                'UnitCurrency': 'SR',
                'UnitPrice': 0,
            }]
            if playfabid and CONFIG['playfab_secret_key']:
                playfab_grant_items_to_user(playfabid, [item_id])
        return jsonify(_pf_ok({'Items': granted}))
    except Exception as e:
        print(f"[purchase error] {e}")
        return jsonify(_pf_ok({'Items': []}))


@app.route('/Client/GetTitleData', methods=['GET', 'POST'])
def client_get_title_data():
    """PlayFab SDK envelope shape (data.Data key/value)."""
    try:
        body = request.get_json(silent=True) or {}
        keys = body.get('Keys') or []
        data = _title_data_full()
        if keys:
            data = {k: data.get(k, '') for k in keys}
        return jsonify(_pf_ok({'Data': data}))
    except Exception as e:
        print(f"[title data error] {e}")
        return jsonify(_pf_ok({'Data': {}}))


@app.route('/api/TitleData', methods=['GET', 'POST'])
def api_title_data_plain():
    """LEGACY SHAPE (must stay): plain {key: value} map, NOT the PlayFab
    envelope. The modded client reads this route bare. When PlayFab is
    configured, official title data is proxied and overlaid on Supabase."""
    try:
        return jsonify(_title_data_full())
    except Exception as e:
        print(f"[title data error] {e}")
        return jsonify(get_title_data())


@app.route('/Client/GetSharedGroupData', methods=['GET', 'POST'])
def client_get_shared_group_data():
    """Official shape (captured): data.Data = {key: {Value, LastUpdated,
    Permission: Public}}. Backed by the sharedgroupdata table."""
    try:
        body = request.get_json(silent=True) or {}
        shared_group_id = body.get('SharedGroupId', '')
        keys = body.get('Keys') or []
        if not shared_group_id:
            return jsonify(_pf_ok({'Data': {}, 'DataVersion': 0}))
        rows = db_get('sharedgroupdata', {'groupid': shared_group_id})
        data = {}
        for row in rows:
            key = row.get('datakey')
            if keys and key not in keys:
                continue
            data[key] = {
                'Value': row.get('value', ''),
                'LastUpdated': row.get('updatedat', utc_now_iso()),
                'Permission': 'Public',
            }
        return jsonify(_pf_ok({'Data': data, 'DataVersion': len(data)}))
    except Exception as e:
        print(f"[shared group error] {e}")
        return jsonify(_pf_ok({'Data': {}, 'DataVersion': 0}))


@app.route('/api/SetSharedGroupData', methods=['POST'])
def api_set_shared_group_data():
    """Companion write path for shared group data (room presence)."""
    try:
        body = request.get_json(silent=True) or {}
        shared_group_id = body.get('SharedGroupId', '')
        data = body.get('Data') or {}
        if shared_group_id and isinstance(data, dict):
            for key, value in data.items():
                db_upsert('sharedgroupdata', {
                    'groupid': shared_group_id,
                    'datakey': key,
                    'value': value if isinstance(value, str) else json.dumps(value),
                    'updatedat': utc_now_iso(),
                }, ['groupid', 'datakey'])
        return jsonify(_pf_ok({'SetData': True}))
    except Exception as e:
        print(f"[shared group set error] {e}")
        return jsonify(_pf_ok({'SetData': False}))

# ============================================================================
# Routes - /api/* endpoints (explicit @app.route, no CloudScript dispatcher)
# NOTE: /api/CheckForBadName and /api/GetAcceptedAgreements are defined
#       elsewhere in this file. Not duplicated here.
# ============================================================================

# ---- helpers ----------------------------------------------------------------

def _plain_params():
    """Pull FunctionParameter / FunctionArgument out of the request body.

    Handles:
      - {"FunctionParameter": {...}} / {"FunctionArgument": {...}}
      - {"FunctionParameter": "{...json...}"} (string-encoded)
      - raw dict body
      - raw string body
      - empty body -> {}
    """
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    params = None
    if isinstance(body, dict):
        params = body.get('FunctionParameter')
        if params is None:
            params = body.get('FunctionArgument')
        if params is None:
            params = body
    elif isinstance(body, str):
        params = body

    if isinstance(params, str) and params:
        parsed = safe_json_loads(params)
        if parsed is not None:
            params = parsed
    return params


def _plain_playfabid(body=None):
    """Get playfabid from the request body (or query)."""
    if body is None:
        body = request.get_json(silent=True) or {}
    pid = ''
    if isinstance(body, dict):
        pid = body.get('PlayFabId') or body.get('playfabid') or ''
        if not pid:
            st = body.get('SessionTicket') or ''
            try:
                pid = playfab_pfid_from_session_ticket(st) or ''
            except Exception:
                pid = ''
    if not pid:
        pid = request.args.get('PlayFabId') or request.args.get('playfabid') or ''
    return pid


# ---- endpoints --------------------------------------------------------------

@app.route('/api/SubmitAcceptedAgreements', methods=['GET', 'POST'])
def api_submit_accepted_agreements():
    try:
        params = _plain_params()
        playfabid = _plain_playfabid()
        if playfabid and isinstance(params, dict):
            for key, version in params.items():
                db_upsert('acceptedagreements', {
                    'playfabid': playfabid,
                    'agreementkey': key,
                    'version': str(version),
                    'acceptedat': utc_now_iso(),
                }, ['playfabid', 'agreementkey'])
        return jsonify('Agreements submitted successfully')
    except Exception as e:
        print(f"[SubmitAcceptedAgreements error] {e}")
        return jsonify('Agreements submitted successfully')


@app.route('/api/ReturnCurrentVersionV2', methods=['GET', 'POST'])
def api_return_current_version():
    try:
        return jsonify({'version': CONFIG['game_version'], 'supported': True})
    except Exception as e:
        print(f"[ReturnCurrentVersionV2 error] {e}")
        return jsonify({'version': CONFIG['game_version'], 'supported': True})


@app.route('/api/TryDistributeCurrencyV2', methods=['GET', 'POST'])
def api_try_distribute_currency():
    try:
        playfabid = _plain_playfabid()
        if playfabid:
            today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            player = db_get_one('players', {'playfabid': playfabid})
            if player and player.get('last_daily') == today:
                return jsonify({'success': True})
            if CONFIG['playfab_secret_key']:
                playfab_grant_items_to_user(playfabid, ['SR_100'])
            db_update('players', {'playfabid': playfabid}, {'last_daily': today})
        return jsonify({'success': True})
    except Exception as e:
        print(f"[TryDistributeCurrencyV2 error] {e}")
        return jsonify({'success': True})


@app.route('/api/AddOrRemoveDLCOwnershipV2', methods=['GET', 'POST'])
def api_add_or_remove_dlc_ownership():
    return jsonify({'success': True})


@app.route('/api/BroadcastMyRoomV2', methods=['GET', 'POST'])
def api_broadcast_my_room():
    try:
        params = _plain_params()
        key_to_follow = params.get('KeyToFollow', '') if isinstance(params, dict) else ''
        room_to_join = params.get('RoomToJoin', '') if isinstance(params, dict) else ''
        if key_to_follow and room_to_join:
            db_upsert('sharedgroupdata', {
                'groupid': key_to_follow,
                'datakey': 'RoomToJoin',
                'value': room_to_join,
                'updatedat': utc_now_iso(),
            }, ['groupid', 'datakey'])
        return jsonify({'success': True})
    except Exception as e:
        print(f"[BroadcastMyRoomV2 error] {e}")
        return jsonify({'success': True})


@app.route('/api/UpdatePersonalCosmeticsList', methods=['GET', 'POST'])
def api_update_personal_cosmetics_list():
    try:
        playfabid = _plain_playfabid()
        if playfabid and CONFIG['playfab_secret_key']:
            inv = playfab_get_user_inventory(playfabid)
            items = (inv.get('data', {}).get('data', {}).get('Inventory')) or []
            if items:
                item_ids = [item['ItemId'] for item in items]
                inv_dict = {
                    item['ItemId']: {
                        'ItemId': item['ItemId'],
                        'PurchaseDate': item.get('PurchaseDate', utc_now_iso()),
                        'Annotation': None,
                    } for item in items
                }
                db_upsert('mothershipuserdata', {
                    'mothershipid': playfabid,
                    'keyname': f'{playfabid}Inventory',
                    'datavalue': json.dumps({'items': item_ids, 'dict': inv_dict}),
                    'updatedat': utc_now_iso(),
                }, ['mothershipid', 'keyname'])
        return jsonify({'success': True})
    except Exception as e:
        print(f"[UpdatePersonalCosmeticsList error] {e}")
        return jsonify({'success': True})


@app.route('/api/ReturnQueueStats', methods=['GET', 'POST'])
def api_return_queue_stats():
    try:
        params = _plain_params()
        queue_name = params.get('QueueName', '') if isinstance(params, dict) else str(params or '')
        result = {
            'queueName': queue_name,
            'playerCount': 0,
            'estimatedWaitTime': 0,
            'result': 0,
        }
        return jsonify({'success': True, 'count': result['playerCount'], **result})
    except Exception as e:
        print(f"[ReturnQueueStats error] {e}")
        return jsonify({'success': True, 'count': 0, 'queueName': '',
                        'playerCount': 0, 'estimatedWaitTime': 0, 'result': 0})


@app.route('/api/ReturnVstumpMapStats', methods=['GET', 'POST'])
def api_return_vstump_map_stats():
    return jsonify({'success': True, 'result': 0})


@app.route('/api/ShouldUserAutomutePlayer', methods=['GET', 'POST'])
def api_should_user_automute_player():
    try:
        return jsonify({'result': False, 'shouldMute': False, 'success': True})
    except Exception as e:
        print(f"[ShouldUserAutomutePlayer error] {e}")
        return jsonify({'result': False, 'shouldMute': False, 'success': True})


@app.route('/api/GetRandomName', methods=['GET', 'POST'])
def api_get_random_name():
    try:
        prefixes = ['Happy', 'Running', 'Laughing', 'Smiling', 'Cool', 'Bald']
        suffixes = ['Cat', 'Dog', 'Hippo', 'Bird', 'Gorilla', 'Chicken', 'Sloth']
        result = f"{secrets.choice(prefixes)}{secrets.choice(suffixes)}"
        return jsonify({'name': result, 'result': result})
    except Exception as e:
        print(f"[GetRandomName error] {e}")
        return jsonify({'name': '', 'result': ''})


@app.route('/api/Gorillanalytics', methods=['GET', 'POST'])
def api_gorillanalytics():
    try:
        body = request.get_json(silent=True) or {}
        params = _plain_params()
        playfabid = _plain_playfabid(body)
        sessions = params.get('data', {}).get('sessions', []) if isinstance(params, dict) else []
        users = params.get('data', {}).get('users', []) if isinstance(params, dict) else []
        if sessions or users:
            db_insert('gorillanalytics', {
                'playfabid': playfabid,
                'upload_id': params.get('upload_id', ''),
                'interval_sec': params.get('interval', 0),
                'start_time': params.get('startTime', ''),
                'sessions_json': json.dumps(sessions),
                'users_json': json.dumps(users),
            })
        return jsonify({'success': True})
    except Exception as e:
        print(f"[Gorillanalytics error] {e}")
        return jsonify({'success': True})


@app.route('/api/UnlockCompetitiveQueue', methods=['GET', 'POST'])
def api_unlock_competitive_queue():
    return jsonify({'success': True, 'unlocked': True})

# ----------------------------------------------------------------------------
# GetAcceptedAgreements legacy plain-shape route (the game also calls it bare)
# ----------------------------------------------------------------------------

@app.route('/api/GetAcceptedAgreements', methods=['GET', 'POST'])
def api_get_accepted_agreements():
    try:
        param = ''
        if request.method == 'POST':
            body = request.get_json(silent=True) or {}
            param = body.get('FunctionParameter', body.get('keys', ''))
            if isinstance(param, dict):
                param = param.get('keys', '')
        else:
            param = request.args.get('keys', request.args.get('FunctionParameter', ''))
        return jsonify(cs_get_accepted_agreements(param, None))
    except Exception:
        return jsonify({'TOS': CONFIG['agreement_version'],
                        'PrivacyPolicy': CONFIG['agreement_version']})

# ----------------------------------------------------------------------------
# CheckForBadName endpit used if cloudscript is bugged or game needs smth else
# ----------------------------------------------------------------------------

def _extract_bad_name_params():
    """Pull name / forRoom / forTroop / playfabid out of the request.

    Handles:
      - JSON dict body: {"name": "...", "forRoom": true, "forTroop": false}
      - PlayFab-wrapped: {"FunctionParameter": {...}} / {"FunctionArgument": {...}}
      - PlayFab envelope: {"Entity": {"Id": "..."}} /
        {"CallerEntityProfile": {"Lineage": {"MasterPlayerAccountId": "..."}}}
      - Raw string body: "SomeName"
      - Query string: ?name=...&forRoom=true&forTroop=false
      - Form body: name=...&forRoom=true
    """
    name = ''
    for_room = False
    for_troop = False
    playfabid = ''

    body = request.get_json(silent=True)

    if isinstance(body, dict):
        params = body.get('FunctionParameter')
        if params is None:
            params = body.get('FunctionArgument')
        if params is None:
            params = body

        if isinstance(params, str):
            parsed = safe_json_loads(params)
            params = parsed if isinstance(parsed, dict) else {'name': params}

        if isinstance(params, dict):
            name = str(params.get('name') or params.get('Name') or '')
            for_room = str(params.get('forRoom', params.get('ForRoom', 'False'))).lower() == 'true'
            for_troop = str(params.get('forTroop', params.get('ForTroop', 'False'))).lower() == 'true'

        # FIX: resolve the caller id through the shared helper so the standard
        # PlayFab envelope shapes (Entity.Id, CallerEntityProfile.Lineage,
        # PlayFabTicket, FunctionParameter.PlayFabId, body.PlayFabId) all work.
        playfabid = get_playfabid_from_request(body) or ''
        if not playfabid:
            st = body.get('SessionTicket') or body.get('PlayFabTicket') or ''
            playfabid = playfab_pfid_from_session_ticket(st) or ''

    elif isinstance(body, str) and body:
        name = body

    if not name:
        name = (request.args.get('name')
                or request.args.get('Name')
                or request.form.get('name')
                or request.form.get('Name')
                or '')
    if not for_room:
        for_room = str(request.args.get('forRoom', request.form.get('forRoom', 'False'))).lower() == 'true'
    if not for_troop:
        for_troop = str(request.args.get('forTroop', request.form.get('forTroop', 'False'))).lower() == 'true'
    if not playfabid:
        playfabid = (request.args.get('PlayFabId')
                     or request.args.get('playfabid')
                     or '')

    return name, for_room, for_troop, playfabid


@app.route('/api/CheckForBadName', methods=['GET', 'POST'])
def api_check_for_bad_name_standalone():
    """Plain-shape name filter endpoint.

    Returns {"result": 0} for OK, {"result": 2, "reason": "..."} for blocked.
    Persists the display name locally (+ PlayFab) when it's a player name
    (forRoom=False and forTroop=False) and a playfabid is present.
    """
    try:
        name, for_room, for_troop, playfabid = _extract_bad_name_params()

        result, reason = name_check_result(name)

        if result == 0 and not for_room and not for_troop and playfabid and name:
            if CONFIG['playfab_secret_key']:
                try:
                    pf = playfab_update_display_name(playfabid, name)
                    print(f"[CheckForBadName] PlayFab update: "
                          f"playfabid={playfabid!r} name={name!r} "
                          f"status={pf.get('status')} data={pf.get('data')}")
                except Exception as e:
                    print(f"[CheckForBadName] PlayFab update raised: {e}")
            else:
                print(f"[CheckForBadName] PlayFab not configured, name NOT saved: "
                      f"playfabid={playfabid!r} name={name!r}")

        out = {'result': result}
        if reason:
            out['reason'] = reason
        return jsonify(out)

    except Exception as e:
        print(f"[CheckForBadName error] {e}")
        return jsonify({'result': 0})

# ============================================================================
# Routes - Mothership v1 API
# ============================================================================

@app.route('/v1/me', methods=['GET'])
def mothership_me():
    """Mod.io profile mirror (official captured shape)."""
    mothershipid = mothership_from_headers()
    return jsonify({
        'id': 0,
        'name_id': mothershipid or 'player',
        'username': mothershipid or 'player',
        'display_name_portal': None,
        'date_online': int(time.time()),
        'date_joined': int(time.time()),
        'avatar': {'filename': '', 'original': '', 'thumb_50x50': '', 'thumb_100x100': ''},
        'timezone': '', 'language': '', 'country': '',
        'privacy_options': 4, 'status': 0, 'monetization_status': 0,
        'profile_url': '',
    })


@app.route('/v1/me/subscriptions', methods=['GET'])
@app.route('/v1/me/subscribed', methods=['GET'])
def mothership_me_subscribed():
    """Subscribed mods. Returns the official mod.io envelope, empty data."""
    return jsonify({'data': [], 'result_count': 0, 'result_offset': 0,
                    'result_limit': 100, 'result_total': 0})


@app.route('/v1/me/ratings', methods=['GET'])
def mothership_me_ratings():
    return jsonify({'data': [], 'result_count': 0, 'result_offset': 0,
                    'result_limit': 100, 'result_total': 0})


@app.route('/v1/games/<game_id>/mods', methods=['GET'])
def modio_game_mods(game_id):
    """Proxy to mod.io when configured; empty envelope otherwise."""
    if CONFIG['modio_api_key']:
        try:
            resp = requests.get(
                f"https://api.mod.io/v1/games/{game_id}/mods",
                params={'api_key': CONFIG['modio_api_key'], 'limit': 50},
                timeout=15,
            )
            if resp.status_code == 200:
                return jsonify(resp.json())
        except Exception as e:
            print(f"[modio] proxy failed: {e}")
    return jsonify({'data': [], 'result_count': 0, 'result_offset': 0,
                    'result_limit': 100, 'result_total': 0})


@app.route('/v1/games/<game_id>/mods/<mod_id>/files/<file_id>/download', methods=['GET'])
def modio_mod_download(game_id, mod_id, file_id):
    if CONFIG['modio_api_key']:
        try:
            resp = requests.get(
                f"https://api.mod.io/v1/games/{game_id}/mods/{mod_id}/files/{file_id}",
                params={'api_key': CONFIG['modio_api_key']}, timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('download', {}).get('binary_url'):
                    return jsonify(data)
        except Exception as e:
            print(f"[modio] download lookup failed: {e}")
    return jsonify({'error': 'mod.io not configured'}), 404


@app.route('/v1/agreements/types/<int:agreement_type>/current', methods=['GET'])
def modio_agreements(agreement_type):
    """Official mod.io agreement shape (type 1 = Terms, 2 = Privacy)."""
    now_ts = int(time.time())
    name = 'Terms of Use' if agreement_type == 1 else 'Privacy Policy'
    return jsonify({
        'id': agreement_type,
        'is_active': True,
        'is_latest': True,
        'type': agreement_type,
        'user': {'id': 1, 'name_id': 'intense', 'username': 'Scott',
                 'display_name_portal': None, 'date_online': 0, 'date_joined': 0,
                 'avatar': {'filename': '', 'original': '', 'thumb_50x50': '',
                            'thumb_100x100': ''},
                 'timezone': '', 'language': '', 'profile_url': ''},
        'date_added': now_ts, 'date_updated': now_ts, 'date_live': now_ts,
        'name': name,
        'changelog': 'Private edition agreement.',
        'textfile': {'filename': f'{name}.txt', 'original': '', 'thumb_50x50': '',
                     'thumb_100x100': ''},
    })


@app.route('/v1/userdata/client', methods=['GET', 'POST'])
def mothership_userdata():
    """User data key-value store (official single-object shape)."""
    try:
        mothershipid = mothership_from_headers()
        if request.method == 'POST':
            body = request.get_json(silent=True) or {}
            key_name = body.get('key_name', body.get('Key', ''))
            value = body.get('value', body.get('Value', ''))
            if not mothershipid or not key_name:
                return jsonify({'id': '', 'key_name': key_name,
                                'user_id': mothershipid, 'value': '', 'generation': 0})
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            db_upsert('mothershipuserdata', {
                'mothershipid': mothershipid,
                'keyname': key_name,
                'datavalue': value,
                'updatedat': utc_now_iso(),
            }, ['mothershipid', 'keyname'])
            return jsonify({
                'id': generate_uuid(),
                'metadata_id': '',
                'key_name': key_name,
                'user_id': mothershipid,
                'value': value,
                'generation': 1,
                'created_by': mothershipid,
                'last_written_by': mothershipid,
            })

        key_name = request.args.get('key_name', '')
        if not mothershipid or not key_name:
            return jsonify({'id': '', 'metadata_id': '', 'key_name': key_name,
                            'user_id': mothershipid, 'value': '', 'generation': 0,
                            'created_by': '', 'last_written_by': ''})
        row = db_get_one('mothershipuserdata',
                         {'mothershipid': mothershipid, 'keyname': key_name})
        if not row:
            return jsonify({'id': '', 'metadata_id': '', 'key_name': key_name,
                            'user_id': mothershipid, 'value': '', 'generation': 0,
                            'created_by': '', 'last_written_by': ''})
        return jsonify({
            'id': generate_uuid(),
            'metadata_id': '',
            'key_name': key_name,
            'user_id': mothershipid,
            'value': row.get('datavalue', ''),
            'generation': 1,
            'created_by': mothershipid,
            'last_written_by': mothershipid,
        })
    except Exception as e:
        print(f"[userdata error] {e}")
        return jsonify({'id': '', 'metadata_id': '', 'key_name': '',
                        'user_id': '', 'value': '', 'generation': 0,
                        'created_by': '', 'last_written_by': ''})


@app.route('/v1/inventory/client', methods=['GET'])
def mothership_inventory():
    """Official captured shape:
    {'Results': {<PlayerId>: {'platform','isPrimary','entitlements':[...]}}}
    SI resources are mapped to their exact official entitlement ids."""
    try:
        token = request.headers.get('x-mothership-token', '')
        decoded = verify_token(token)
        mothershipid = (decoded or {}).get('sub', '')
        platform = (decoded or {}).get('externalService', 'STEAM')
        if not mothershipid:
            return jsonify({'Results': {}})

        si_ensure_player_exists(mothershipid)
        inventory = si_get_inventory(mothershipid)

        name_by_key = {
            'TechPoints': 'SI_TechPoints', 'StrangeWood': 'SI_StrangeWood',
            'WeirdGear': 'SI_WeirdGear', 'VibratingSpring': 'SI_VibratingSpring',
            'BouncySand': 'SI_BouncySand', 'FloppyMetal': 'SI_FloppyMetal',
        }
        in_game_id_by_name = {
            'SI_TechPoints': 'SI_TECH_POINTS',
            'SI_StrangeWood': 'SI_STRANGE_WOOD',
            'SI_WeirdGear': 'SI_WEIRD_GEAR',
            'SI_VibratingSpring': 'SI_VIBRATING_SPRING',
            'SI_BouncySand': 'SI_BOUNCY_SAND',
            'SI_FloppyMetal': 'SI_FLOPPY_METAL',
        }
        entitlements = []
        for key, qty in inventory.items():
            res_name = name_by_key[key]
            entitlements.append({
                'entitlement_id': SI_ENTITLEMENT_IDS[res_name],
                'in_game_id': in_game_id_by_name[res_name],
                'name': res_name,
                'quantity': qty,
                'display_description': None,
                'display_name': None,
            })
        for ent in GR_ACCESS_ENTITLEMENTS:
            entitlements.append({
                'entitlement_id': ent['entitlement_id'],
                'in_game_id': ent['in_game_id'],
                'name': ent['name'],
                'quantity': 1,
                'display_description': None,
                'display_name': None,
            })

        return jsonify({'Results': {mothershipid: {
            'platform': platform, 'isPrimary': True, 'entitlements': entitlements,
        }}})
    except Exception as e:
        print(f"[inventory error] {e}")
        return jsonify({'Results': {}})


def _load_progression_tree_data():
    """Progression trees: Supabase title data first, then bundled file."""
    raw = get_title_data().get('progression_tree')
    if raw:
        data = safe_json_loads(raw)
        if isinstance(data, dict) and data.get('Results'):
            return data
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'data', 'progression_tree.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[progression] failed to load bundled tree: {e}")
    return {'Results': []}


@app.route('/v1/progression-tree/client', methods=['GET'])
def progression_tree_client():
    try:
        token = request.headers.get('x-mothership-token', '')
        decoded = verify_token(token)
        mothershipid = (decoded or {}).get('sub', '')

        data = _load_progression_tree_data()

        unlocked_set = set()
        if mothershipid:
            nodes = db_get('progressionnodes', {'mothershipid': mothershipid})
            unlocked_set = {f"{n['treeid']}:{n['nodeid']}" for n in nodes}

        for tree in data.get('Results', []):
            tree_name = tree.get('Tree', {}).get('name', '')
            tree['PlayerId'] = mothershipid
            # SI_Gadgets ships fully unlocked (server-side decision)
            for node in tree.get('NodeDefinitions', []):
                key = f"{tree['Tree']['id']}:{node['id']}"
                if tree_name == 'SI_Gadgets' or key in unlocked_set:
                    node['unlocked'] = True

        return jsonify(data)
    except Exception as e:
        print(f"[progression tree error] {e}")
        return jsonify({'Results': []})


@app.route('/v1/subscription/client', methods=['GET', 'POST'])
def mothership_subscription_client():
    """Fan Club subscription is granted to everyone (private server)."""
    now = utc_now_iso()
    later = (datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    mothershipid = mothership_from_headers() or request.args.get('caller_id', '')
    return jsonify({
        'subscriptions': [{
            'id': 'sub_vim_fanclub',
            'earliest_start_date': now,
            'current_sub_start_date': now,
            'most_recent_billing_cycle_start_date': now,
            'most_recent_billing_cycle_end_date': later,
            'total_lifetime_seconds': 0,
            'total_lifetime_seconds_last_update_date': now,
            'is_active': True,
            'is_cancelling': False,
            'sku': 'fan_club',
            'mothership_player_id': mothershipid,
            'trial_version': '',
            'external_service_name': 'steam',
            'external_service_org_scoped_id': '',
            'external_service_user_id': '',
            'external_service_user_name': '',
            'ref_id': '',
            'title_id': CONFIG['mothership_title_id'],
            'env_id': CONFIG['mothership_env_id'],
            'subscription_catalog_item_id': '',
        }],
        'status_code': 200,
        'error': None,
    })


@app.route('/v1/title-data/client', methods=['GET'])
def title_data_client():
    try:
        keys = request.args.get('keys', '')
        return jsonify(title_data_results(keys))
    except Exception as e:
        print(f"[title data client error] {e}")
        return jsonify({'Results': []})


# ----------------------------------------------------------------------------
# Title Data Objects - the client resolves TitleDataObjectID references from
# schedule keys (RotatingFlashback -> SetA/SetB = rotating flashback cosmetic
# sets; TimedStore -> TimedStoreEvent/B2SPromo). Served from our backend so
# the client never needs PlayFab's object CDN. Possible request shapes the
# SDK/mods use are all covered.
# ----------------------------------------------------------------------------

@app.route('/titledata/<title_id>/obj/<name>', methods=['GET'])
@app.route('/title-data/obj/<name>', methods=['GET'])
@app.route('/api/GetObjectData', methods=['GET', 'POST'])
@app.route('/v1/title-data/object/<name>', methods=['GET'])
def title_data_object(name):
    try:
        objects = _pf_title_objects()
        payload = objects.get(name)
        if payload is None:
            return jsonify({}), 404
        return jsonify(payload)
    except Exception as e:
        print(f"[title object {name} error] {e}")
        return jsonify({}), 500


@app.route('/api/GetObjectsData', methods=['GET', 'POST'])
def title_data_objects_all():
    """All resolved Title Data Objects at once: {name: payload}."""
    try:
        return jsonify(_pf_title_objects())
    except Exception as e:
        print(f"[title objects error] {e}")
        return jsonify({}), 500


@app.route('/v1/title-data/<dataset>', methods=['POST'])
def title_data_dataset(dataset):
    """Hash-diff custom title-data datasets (HEATWAVE/Summer23/Science24)."""
    try:
        if dataset not in TITLE_DATA_FILES:
            return jsonify({}), 404
        body = request.get_json(silent=True) or {}
        client_hashes = body.get('data', {}) or {}
        title_data = load_custom_title_data(TITLE_DATA_FILES[dataset])
        if title_data is None:
            return jsonify({}), 200
        return jsonify(build_changed_title_data(title_data, client_hashes)), 200
    except Exception as e:
        print(f"[title data {dataset} error] {e}")
        return jsonify({}), 500


@app.route('/v1/data/client', methods=['GET'])
def data_client():
    return jsonify({'admins': [
        {'userId': CONFIG['admin_playfab_id'], 'username': 'admin', 'role': 2},
    ]})


@app.route('/v1/client/analytics/event/batch', methods=['POST'])
def analytics_batch():
    """Analytics sink. Official response: list of {EventId} acks. Persists
    ghost_game_end events for the Ghost Reactor economy."""
    try:
        body = request.get_json(silent=True) or {}
        events = body.get('Events', [])
        acks = []
        for evt in events:
            name = evt.get('EventName') or 'event'
            evt_body = evt.get('Body', {}) or {}
            tags = evt.get('CustomTags', {}) or {}
            acks.append({'EventId': f"{name}-{utc_now_iso()}"})

            if name == 'ghost_game_end':
                mothershipid = evt_body.get('mothership_id', '')
                if mothershipid:
                    db_insert('ghostgames', {
                        'mothershipid': mothershipid,
                        'ghost_game_id': evt_body.get('ghost_game_id'),
                        'event_timestamp': evt_body.get('event_timestamp'),
                        'final_cores_balance': int(evt_body.get('final_cores_balance', 0) or 0),
                        'total_cores_collected_by_player': int(evt_body.get('total_cores_collected_by_player', 0) or 0),
                        'total_cores_collected_by_group': int(evt_body.get('total_cores_collected_by_group', 0) or 0),
                        'total_cores_spent_by_player': int(evt_body.get('total_cores_spent_by_player', 0) or 0),
                        'total_cores_spent_by_group': int(evt_body.get('total_cores_spent_by_group', 0) or 0),
                        'gates_unlocked': int(evt_body.get('gates_unlocked', 0) or 0),
                        'died': int(evt_body.get('died', 0) or 0),
                        'items_purchased': json.dumps(evt_body.get('items_purchased', [])),
                        'shift_cut_data': str(evt_body.get('shift_cut_data', '0')),
                        'play_duration': int(evt_body.get('play_duration', 0) or 0),
                        'started_late': str(evt_body.get('started_late', 'False')),
                        'time_started': str(evt_body.get('time_started', '0')),
                        'reason': evt_body.get('reason', 'unknown'),
                        'max_number_in_game': int(evt_body.get('max_number_in_game', 0) or 0),
                        'end_number_in_game': int(evt_body.get('end_number_in_game', 1) or 1),
                        'items_picked_up': json.dumps(evt_body.get('items_picked_up', {})),
                        'revives': int(evt_body.get('revives', 0) or 0),
                        'num_shifts_played': int(evt_body.get('num_shifts_played', 0) or 0),
                        'game_version': tags.get('tag1'),
                        'game_environment': tags.get('tag2'),
                    })
        return jsonify(acks)
    except Exception as e:
        print(f"[analytics batch error] {e}")
        return jsonify([])

# ============================================================================
# Routes - kid safety / age verification (official captured shapes)
# ============================================================================

AGE_PERMISSIONS = [
    {'managedBy': 'PLAYER', 'name': 'custom-username', 'enabled': True},
    {'managedBy': 'PLAYER', 'name': 'join-groups', 'enabled': True},
    {'managedBy': 'PLAYER', 'name': 'leaderboard-and-rankings', 'enabled': True},
    {'managedBy': 'PLAYER', 'name': 'mods', 'enabled': True},
    {'managedBy': 'PLAYER', 'name': 'multiplayer', 'enabled': True},
    {'managedBy': 'PLAYER', 'name': 'online-status', 'enabled': True},
    {'managedBy': 'PLAYER', 'name': 'send-accept-friend-requests', 'enabled': True},
    {'managedBy': 'PLAYER', 'name': 'voice-chat', 'enabled': True},
]

@app.route('/api/GetPlayerData', methods=['GET'])
def kid_get_player_data():
    """Official captured shape (adult session, all permissions enabled)."""
    session_id = generate_uuid()
    return jsonify({
        'status': 'PASS',
        'session': {
            'status': 'ACTIVE',
            'ageStatus': 'LEGAL_ADULT',
            'ageCategory': 'adult',
            'managedBy': 'PLAYER',
            'sessionId': session_id,
            'kuid': None,
            'etag': hashlib.sha256(session_id.encode()).hexdigest(),
            'permissions': AGE_PERMISSIONS,
            'allowances': None,
            'dateOfBirth': CONFIG['kid_dob'],
            'jurisdiction': CONFIG['kid_jurisdiction'],
            'hasApproverEmail': False,
        },
        'age': None,
        'defaultSession': None,
        'permissions': None,
        'hasConfirmedSetup': True,
    })


@app.route('/api/VerifyAge', methods=['POST'])
def kid_verify_age():
    session = {
        'AgeStatus': 'adult', 'AgeCategory': 'adult',
        'Jurisdiction': CONFIG['kid_jurisdiction'],
        'IsMinor': False, 'IsConsentRequired': False,
    }
    return jsonify({'Status': 'active', 'Session': session, 'DefaultSession': session})


@app.route('/api/GetRequirements', methods=['GET'])
def kid_get_requirements():
    return jsonify({
        'platformMinimumAge': 0,
        'shouldDisplay': True,
        'ageAssuranceRequired': True,
        'digitalConsentAge': 16,
        'civilAge': 18,
        'minimumAge': 0,
        'approvedAgeCollectionMethods': ['date-of-birth', 'age-slider', 'platform-account'],
    })


@app.route('/api/SetPlayerData', methods=['POST'])
def kid_set_player_data():
    return jsonify({'success': True})

# ============================================================================
# Routes - friends & privacy
# ============================================================================

@app.route('/api/GetFriendsV2', methods=['POST'])
def get_friends_v2():
    """Official captured shape:
    {'result': {'friends': [...], 'myPrivacyState': N}, 'statusCode', 'error'}"""
    try:
        body = request.get_json(silent=True) or {}
        playfabid = body.get('PlayFabId', '')
        if not playfabid and body.get('MothershipToken'):
            decoded = verify_token(body['MothershipToken'])
            if decoded:
                ms = db_get_one('mothershipplayers', {'mothershipid': decoded.get('sub', '')})
                playfabid = (ms or {}).get('userid', '')

        friends = []
        if playfabid:
            links = db_get('friendlinks', {'playerid': playfabid})
            for link in links:
                friend_id = link.get('friendid')
                presence = db_get_one('friendpresence', {'playfabid': friend_id})
                privacy = db_get_one('privacystates', {'playfabid': friend_id})
                player = db_get_one('players', {'playfabid': friend_id})

                display_name = (player or {}).get('displayname') or friend_id
                if not (player or {}).get('displayname') and CONFIG['playfab_secret_key']:
                    try:
                        pf = playfab_get_player_profile(friend_id)
                        pf_name = (pf.get('data', {}).get('data', {})
                                   .get('PlayerProfile', {}).get('DisplayName'))
                        if pf_name:
                            display_name = pf_name
                            db_upsert('players', {'playfabid': friend_id,
                                                  'displayname': pf_name}, 'playfabid')
                    except Exception:
                        pass

                bypass = playfabid == CONFIG['admin_playfab_id']
                room_id = zone = region = ''
                if presence and (bypass or not privacy
                                 or not privacy.get('state')
                                 or privacy.get('state') == 'VISIBLE'):
                    room_id = presence.get('roomid', '') or ''
                    zone = presence.get('zone', '') or ''
                    region = presence.get('region', '') or ''

                friends.append({
                    'Presence': {
                        'FriendLinkId': friend_id,
                        'UserName': display_name,
                        'RoomId': room_id,
                        'Zone': zone,
                        'Region': region,
                        'IsPublic': True,
                    },
                    'Created': link.get('createdat', utc_now_iso()),
                })

        privacystate = 0
        prow = db_get_one('privacystates', {'playfabid': playfabid})
        if prow:
            state = prow.get('state')
            if state == 'PUBLIC_ONLY':
                privacystate = 1
            elif state == 'HIDDEN':
                privacystate = 2

        return jsonify({'result': {'friends': friends, 'myPrivacyState': privacystate},
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[friends error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/SetPrivacyState', methods=['POST'])
def set_privacy_state():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = body.get('PlayFabId', '')
        state = str(body.get('PrivacyState', ''))
        if not playfabid:
            return jsonify({'StatusCode': 400, 'Error': 'Missing PlayFabId'}), 400
        state_map = {'0': 'VISIBLE', '1': 'PUBLIC_ONLY', '2': 'HIDDEN'}
        resolved = state_map.get(state, state)
        db_upsert('privacystates', {'playfabid': playfabid, 'state': resolved}, 'playfabid')
        return jsonify({'StatusCode': 200, 'Error': None})
    except Exception as e:
        print(f"[privacy error] {e}")
        return jsonify({'StatusCode': 500, 'Error': 'Internal error'}), 500


@app.route('/api/RequestFriend', methods=['POST'])
def request_friend():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = body.get('PlayFabId', '')
        friendid = body.get('FriendFriendLinkId', body.get('FriendId', ''))
        if not playfabid or not friendid:
            return jsonify({'error': 'Missing fields'}), 400
        db_upsert('friendlinks', {'playerid': playfabid, 'friendid': friendid,
                                  'createdat': utc_now_iso()}, ['playerid', 'friendid'])
        db_upsert('friendlinks', {'playerid': friendid, 'friendid': playfabid,
                                  'createdat': utc_now_iso()}, ['playerid', 'friendid'])
        return jsonify({'success': True})
    except Exception as e:
        print(f"[add friend error] {e}")
        return jsonify({'error': 'Internal error'}), 500


@app.route('/api/RemoveFriend', methods=['POST'])
def remove_friend():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = body.get('PlayFabId', '')
        friendid = body.get('FriendFriendLinkId', body.get('FriendId', ''))
        if not playfabid or not friendid:
            return jsonify({'error': 'Missing fields'}), 400
        db_delete('friendlinks', {'playerid': playfabid, 'friendid': friendid})
        db_delete('friendlinks', {'playerid': friendid, 'friendid': playfabid})
        return jsonify({'success': True})
    except Exception as e:
        print(f"[remove friend error] {e}")
        return jsonify({'error': 'Internal error'}), 500

# ============================================================================
# Routes - MMR / tiers / matches
# ============================================================================

def _tier_from_elo(elo):
    """Official-style tier mapping (major tiers every 400 elo, 133-step minors)."""
    elo = max(0.0, float(elo))
    major = min(5, int(elo // 400))
    remainder = elo - major * 400
    minor = min(2, int(remainder // 133))
    progress = (remainder % 133) / 133.0
    return major, minor, round(progress, 4)


@app.route('/api/GetTier', methods=['GET', 'POST'])
def get_tier():
    try:
        if request.method == 'GET':
            ids = request.args.get('playfabIds', '')
            playfabids = [p for p in ids.split(',') if p.strip()]
            if not playfabids:
                body = request.get_json(silent=True) or {}
                playfabids = (body.get('playfabIds')
                              or ([body.get('mothershipId')] if body.get('mothershipId') else []))
        else:
            body = request.get_json(silent=True) or {}
            playfabids = body.get('playfabIds') or []

        results = []
        for pid in playfabids:
            if not pid:
                continue
            ensure_ranked_data(pid, 'PC')
            ensure_ranked_data(pid, 'Quest')
            rows = db_get('rankeddata', {'playfabid': pid})
            platform_data = [{
                'platform': row.get('platform'),
                'elo': row.get('elo', 1000),
                'majorTier': row.get('majortier', 2),
                'minorTier': row.get('minortier', 0),
                'rankProgress': row.get('rankprogress', 0),
            } for row in rows]
            for platform in ('PC', 'Quest'):
                if not any(p['platform'] == platform for p in platform_data):
                    platform_data.append({'platform': platform, 'elo': 1000,
                                          'majorTier': 2, 'minorTier': 0, 'rankProgress': 0})
            results.append({'playfabID': pid, 'platformData': platform_data})

        return jsonify(results)
    except Exception as e:
        print(f"[mmr error] {e}")
        return jsonify([]), 500


@app.route('/api/CreateMatchId', methods=['POST'])
def create_match_id():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('mothershipId', body.get('MothershipId', ''))
        platform = body.get('platform', 'PC')
        matchid = generate_code(8)
        db_insert('matchids', {'matchid': matchid, 'createdby': mothershipid,
                               'platform': platform, 'isactive': 1})
        return matchid, 200
    except Exception as e:
        print(f"[create match error] {e}")
        return '', 500


@app.route('/api/ValidateMatchJoin', methods=['POST'])
def validate_match_join():
    try:
        body = request.get_json(silent=True) or {}
        matchid = body.get('matchId', '')
        mothershipid = body.get('mothershipId', '')
        if not matchid:
            return jsonify({'validJoin': False})
        match = db_get_one('matchids', {'matchid': matchid, 'isactive': 1})
        if match:
            db_upsert('matchparticipants',
                      {'matchid': matchid, 'playfabid': mothershipid},
                      ['matchid', 'playfabid'])
            return jsonify({'validJoin': True})
        return jsonify({'validJoin': False})
    except Exception as e:
        print(f"[validate match error] {e}")
        return jsonify({'validJoin': False}), 500


@app.route('/api/SubmitMatchScores', methods=['POST'])
def submit_match_scores():
    try:
        body = request.get_json(silent=True) or {}
        matchid = body.get('matchId', '')
        scores = body.get('playerScores', [])
        if not matchid or not scores:
            return 'Bad request', 400
        if len(scores) < 2:
            db_update('matchids', {'matchid': matchid}, {'isactive': 0})
            return 'OK', 200

        sorted_scores = sorted(scores, key=lambda s: s.get('gameScore', 0), reverse=True)
        for i, s in enumerate(sorted_scores):
            pid = s.get('playfabId', '')
            if not pid:
                continue
            ensure_ranked_data(pid, 'PC')
            ensure_ranked_data(pid, 'Quest')
            placement = i / (len(sorted_scores) - 1)
            elo_change = (1 - placement) * 20 - 10

            current = db_get_one('rankeddata', {'playfabid': pid, 'platform': 'PC'})
            new_elo = max(0, float((current or {}).get('elo', 1000)) + elo_change)
            db_update('rankeddata', {'playfabid': pid, 'platform': 'PC'}, {'elo': new_elo})

            for row in db_get('rankeddata', {'playfabid': pid}):
                if not row.get('platform'):
                    continue
                major, minor, progress = _tier_from_elo(row.get('elo', 1000))
                db_update('rankeddata',
                          {'playfabid': pid, 'platform': row['platform']},
                          {'majortier': major, 'minortier': minor,
                           'rankprogress': progress})

        db_update('matchids', {'matchid': matchid}, {'isactive': 0})
        return 'OK', 200
    except Exception as e:
        print(f"[submit scores error] {e}")
        return 'Error', 500


@app.route('/api/PingRoom', methods=['POST'])
def ping_room():
    try:
        body = request.get_json(silent=True) or {}
        matchid = body.get('matchId', '')
        if matchid:
            db_update('matchids', {'matchid': matchid},
                      {'lastping': utc_now_iso()})
        return 'OK', 200
    except Exception as e:
        print(f"[ping room error] {e}")
        return 'Error', 500

# ============================================================================
# Routes - MonkeBiz daily/weekly quests (points ledger)
#
# Client contract (ref game files 25/ProgressionController.cs):
#   POST /api/GetQuestStatus   {PlayFabId, PlayFabTicket, MothershipId, MothershipToken}
#   POST /api/SetQuestComplete {..., QuestId, ClientVersion}
#   -> {"result":{"dailyPoints":{"MM/DD/YYYY":int},"weeklyPoints":{isoweek:int},
#                 "userPointsTotal":int},"statusCode":200,"error":null}
# The client awards only the INCREASE of userPointsTotal, its weekly progress is
# min(sum(dailyPoints)+sum(weeklyPoints), 25) and a 403 makes it drop its queued
# completions. So: prune stale keys, mirror the cap, and never answer with a
# plain 4xx (that permanently jams the client's completion queue).
# ============================================================================

QUEST_WEEKLY_POINT_CAP = 25       # ProgressionController.WeeklyCap
QUEST_DAILY_POINT_VALUE = 1       # daily quest reward
QUEST_WEEKLY_POINT_VALUE = 5      # weekly quest reward (official ledger {"41": 5})

_pf_quest_sets_cache = {'daily': None, 'weekly': None, 'ts': 0.0}
_PF_QUEST_SETS_TTL = 300.0


def _quest_set_ids():
    """(daily_ids, weekly_ids) parsed from title-data AllActiveQuests.

    The quest board itself is served by PlayFab title data; membership decides
    whether a completion pays 1 (daily) or 5 (weekly) points.
    """
    now = time.time()
    if (_pf_quest_sets_cache['daily'] is not None
            and now - _pf_quest_sets_cache['ts'] < _PF_QUEST_SETS_TTL):
        return _pf_quest_sets_cache['daily'], _pf_quest_sets_cache['weekly']
    daily, weekly = set(), set()
    try:
        raw = get_title_data().get('AllActiveQuests')
        data = safe_json_loads(raw, {}) if isinstance(raw, str) else (raw or {})
        for section, bucket in (('DailyQuests', daily), ('WeeklyQuests', weekly)):
            for group in (data or {}).get(section, []) or []:
                for quest in (group or {}).get('quests', []) or []:
                    qid = quest.get('questID') if isinstance(quest, dict) else None
                    if qid is not None:
                        bucket.add(int(qid))
    except Exception as e:
        print(f"[quests] AllActiveQuests parse failed: {e}")
    _pf_quest_sets_cache.update({'daily': daily, 'weekly': weekly, 'ts': now})
    return daily, weekly


def _quest_points_for(questid):
    """Official split: daily quest = 1 point, weekly quest = 5 points.
    Unknown ids (title data unavailable) count as daily."""
    try:
        qid = int(questid)
    except (TypeError, ValueError):
        return 'daily', QUEST_DAILY_POINT_VALUE, None
    _daily_ids, weekly_ids = _quest_set_ids()
    if qid in weekly_ids:
        return 'weekly', QUEST_WEEKLY_POINT_VALUE, qid
    return 'daily', QUEST_DAILY_POINT_VALUE, qid


def quest_player_id(body):
    """Resolve the quest-ledger owner without ever failing the client.
    PlayFabId -> MothershipId/token subject -> PlayFabTicket prefix."""
    playfabid = str(body.get('PlayFabId') or body.get('PlayFabID') or '').strip()
    if not playfabid:
        playfabid = str(body.get('MothershipId') or '').strip()
    if not playfabid:
        mothershipid, _err = si_request_identity(body, require_token=False)
        playfabid = str(mothershipid or '').strip()
    if not playfabid:
        playfabid = playfab_pfid_from_session_ticket(body.get('PlayFabTicket') or '')
    return playfabid


def _prune_quest_points(daily, weekly, now=None):
    """Keep only the current week. The client sums every key it receives and
    clamps at 25, so leftover history would pin its progress at the cap (and
    our own cap check would answer 403) for the rest of time."""
    now = now or datetime.now(timezone.utc)
    today = now.date()
    monday = today - timedelta(days=today.weekday())
    pruned_daily = {}
    for key, value in (daily or {}).items():
        try:
            day = datetime.strptime(str(key), '%m/%d/%Y').date()
        except Exception:
            continue
        if monday <= day <= today:
            pruned_daily[str(key)] = int(value or 0)
    week = week_number_key(now)
    pruned_weekly = {str(k): int(v or 0) for k, v in (weekly or {}).items()
                     if str(k) == week}
    return pruned_daily, pruned_weekly


def _quest_row(playfabid):
    """Read the ledger row; a missing row is an empty in-memory default (no
    write on reads - only SetQuestComplete persists)."""
    row = db_get_one('queststatus', {'playfabid': playfabid})
    return row or {'playfabid': playfabid, 'dailypoints': '{}',
                   'weeklypoints': '{}', 'userpointstotal': 0}


def _quest_payload(row, daily=None, weekly=None):
    if daily is None:
        daily = safe_json_loads(row.get('dailypoints'), {}) or {}
    if weekly is None:
        weekly = safe_json_loads(row.get('weeklypoints'), {}) or {}
    return {
        'dailyPoints': daily,
        'weeklyPoints': weekly,
        'userPointsTotal': int(row.get('userpointstotal', 0) or 0),
    }


def _save_quest_row(playfabid, daily, weekly, total):
    """Atomic whole-row write (upsert) so a completion can never half-apply."""
    return db_upsert('queststatus', {
        'playfabid': playfabid,
        'dailypoints': json.dumps(daily),
        'weeklypoints': json.dumps(weekly),
        'userpointstotal': int(total),
        'updatedat': utc_now_iso(),
    }, ['playfabid'])


@app.route('/api/GetQuestStatus', methods=['GET', 'POST'])
def get_quest_status():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = quest_player_id(body)
        if not playfabid:
            print(f"[quest status] unresolved player id: {str(body)[:220]}")
            return jsonify({'result': {'dailyPoints': {}, 'weeklyPoints': {},
                                       'userPointsTotal': 0},
                            'statusCode': 200, 'error': None})
        row = _quest_row(playfabid)
        daily, weekly = _prune_quest_points(
            safe_json_loads(row.get('dailypoints'), {}) or {},
            safe_json_loads(row.get('weeklypoints'), {}) or {})
        return jsonify({'result': _quest_payload(row, daily, weekly),
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[quest status error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/SetQuestComplete', methods=['GET', 'POST'])
def set_quest_complete():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = quest_player_id(body)
        questid = body.get('QuestId', body.get('QuestID', body.get('questId')))
        kind, points, qid = _quest_points_for(questid)

        if not playfabid:
            print(f"[quest complete] unresolved player id: {str(body)[:220]}")
            return jsonify({'result': {'dailyPoints': {}, 'weeklyPoints': {},
                                       'userPointsTotal': 0},
                            'statusCode': 200, 'error': None})

        row = _quest_row(playfabid)
        daily, weekly = _prune_quest_points(
            safe_json_loads(row.get('dailypoints'), {}) or {},
            safe_json_loads(row.get('weeklypoints'), {}) or {})
        total = int(row.get('userpointstotal', 0) or 0)

        weekly_progress = sum(daily.values()) + sum(weekly.values())
        if weekly_progress >= QUEST_WEEKLY_POINT_CAP:
            print(f"[quest complete] playfab={playfabid} weekly cap reached "
                  f"({weekly_progress}/{QUEST_WEEKLY_POINT_CAP})")
            return jsonify({'result': None, 'statusCode': 403,
                            'error': 'Weekly cap reached'}), 403

        if kind == 'weekly':
            week = week_number_key()
            weekly[week] = int(weekly.get(week, 0)) + points
        else:
            today = date_key()
            daily[today] = int(daily.get(today, 0)) + points
        total += points

        _save_quest_row(playfabid, daily, weekly, total)
        print(f"[quest complete] playfab={playfabid} quest={qid} kind={kind} "
              f"+{points} total={total}")
        return jsonify({'result': {'dailyPoints': daily, 'weeklyPoints': weekly,
                                   'userPointsTotal': total},
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[set quest error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': 'Internal error'}), 500

# ============================================================================
# Routes - Super Infection
# ============================================================================

@app.route('/api/IncrementSIResource', methods=['GET', 'POST'])
def increment_si_resource():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid, err = si_request_identity(body, require_token=(request.method == 'POST'))
        if err:
            return err
        if not mothershipid:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': 'Missing MothershipId'}), 400

        resourcetype = body.get('ResourceType', '')
        if resourcetype not in SI_RESOURCE_COLUMNS:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': f'Unknown resource type: {resourcetype}'}), 400

        col = SI_RESOURCE_COLUMNS[resourcetype]
        inv_key = next(k for c, k in SI_INVENTORY_KEYS if c == col)

        # read-modify-write with one retry against concurrent writers
        updated = None
        for _attempt in range(3):
            current = si_get_inventory(mothershipid)
            si_update_resources(mothershipid, {col: int(current.get(inv_key, 0)) + 1})
            updated = si_get_inventory(mothershipid)
            if int(updated.get(inv_key, 0)) >= int(current.get(inv_key, 0)) + 1:
                break

        return jsonify({'resourceType': resourcetype,
                        'result': {'inventory': updated},
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[increment resource error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': str(e)}), 500


@app.route('/api/GetActiveSIQuests', methods=['GET', 'POST'])
def get_active_si_quests():
    try:
        return jsonify(si_load_quest_definitions())
    except Exception as e:
        print(f"[GetActiveSIQuests error] {e}")
        return jsonify({'result': {'quests': SI_QUEST_DEFINITIONS_FALLBACK, 'version': '4'},
                        'statusCode': 200, 'error': None})


@app.route('/api/GetSIQuestsStatus', methods=['GET', 'POST'])
def get_si_quests_status():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid, err = si_request_identity(body, require_token=(request.method == 'POST'))
        if err:
            return err
        if not mothershipid:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': 'Missing MothershipId'}), 400
        si_ensure_player_exists(mothershipid)
        status = si_roll_daily_reset(mothershipid)
        return jsonify(si_quest_status_response(status))
    except Exception as e:
        print(f"[si status error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/SetSIQuestComplete', methods=['GET', 'POST'])
def set_si_quest_complete():
    """Official captured flow: quests 9->8->7, idol untouched, every 4th
    completion banks a bonus point, and every claim pays 1 TechPoint (official
    inventory delta 8->9->10 around the captured SetSIQuestComplete calls)."""
    try:
        body = request.get_json(silent=True) or {}
        mothershipid, err = si_request_identity(body, require_token=(request.method == 'POST'))
        if err:
            return err
        if not mothershipid:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': 'Missing MothershipId'}), 400
        quest_id = body.get('QuestID', body.get('QuestId'))

        si_ensure_player_exists(mothershipid)
        status = si_roll_daily_reset(mothershipid)

        new_stashed = max(0, int(status.get('stashed_quests', 0) or 0) - 1)
        new_bonus_progress = int(status.get('bonus_progress', 0) or 0) + 1
        new_stashed_bonus = max(0, int(status.get('stashed_bonus_points', 0) or 0))
        if new_bonus_progress >= 4:
            new_stashed_bonus += 1
            new_bonus_progress = 0

        db_update('si_player_quest_status', {'mothershipid': mothershipid}, {
            'stashed_quests': new_stashed,
            'bonus_progress': new_bonus_progress,
            'stashed_bonus_points': new_stashed_bonus,
            'updated_at': utc_now_iso(),
        })

        # Every accepted quest claim pays one TechPoint - this is what the
        # game's SI reward machine banks. Read-modify-write with retries.
        updated = None
        for _attempt in range(3):
            current = si_get_inventory(mothershipid)
            si_update_resources(mothershipid,
                                {'tech_points': int(current.get('TechPoints', 0)) + 1})
            updated = si_get_inventory(mothershipid)
            if int(updated.get('TechPoints', 0)) >= int(current.get('TechPoints', 0)) + 1:
                break

        print(f"[SI claim] mothership={mothershipid} quest={quest_id} "
              f"claimable={new_stashed} bonus={new_stashed_bonus} "
              f"techPoints={int((updated or {}).get('TechPoints', 0))}")
        return jsonify(si_quest_status_response(si_get_quest_status(mothershipid)))
    except Exception as e:
        print(f"[SetSIQuestComplete error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': str(e)}), 500


@app.route('/api/SetSIIdolCollect', methods=['GET', 'POST'])
def set_si_idol_collect():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid, err = si_request_identity(body, require_token=(request.method == 'POST'))
        if err:
            return err
        if not mothershipid:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': 'Missing MothershipId'}), 400
        si_ensure_player_exists(mothershipid)
        si_roll_daily_reset(mothershipid)
        db_update('si_player_quest_status', {'mothershipid': mothershipid},
                  {'daily_limited_turned_in': True, 'updated_at': utc_now_iso()})
        return jsonify(si_quest_status_response(si_get_quest_status(mothershipid)))
    except Exception as e:
        print(f"[SetSIIdolCollect error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': str(e)}), 500


@app.route('/api/ResetSIQuestsStatus', methods=['POST'])
def reset_si_quests_status():
    """Admin/debug helper: reset claimables to a fresh day (9/3/1)."""
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': 'Missing MothershipId'}), 400
        si_ensure_player_exists(mothershipid)
        db_update('si_player_quest_status', {'mothershipid': mothershipid}, {
            'stashed_quests': SI_DAILY_CLAIMABLE_QUESTS,
            'stashed_bonus_points': SI_DAILY_CLAIMABLE_BONUS, 'bonus_progress': 0,
            'daily_limited_turned_in': False,
            'last_reset_date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            'updated_at': utc_now_iso(),
        })
        return jsonify(si_quest_status_response({
            'stashed_quests': SI_DAILY_CLAIMABLE_QUESTS,
            'stashed_bonus_points': SI_DAILY_CLAIMABLE_BONUS,
            'daily_limited_turned_in': False,
        }))
    except Exception as e:
        print(f"[si reset error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/PurchaseTechPoints', methods=['GET', 'POST'])
def purchase_tech_points():
    """Shiny Rocks -> Tech Points (SR wallet is PlayFab-side; no deduction)."""
    try:
        body = request.get_json(silent=True) or {}
        mothershipid, err = si_request_identity(body, require_token=(request.method == 'POST'))
        if err:
            return err
        if not mothershipid:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': 'Missing MothershipId'}), 400
        try:
            amount = int(body.get('TechPointsAmount', 0) or 0)
        except (TypeError, ValueError):
            amount = 0
        if amount <= 0:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': 'Invalid TechPointsAmount'}), 400

        si_ensure_player_exists(mothershipid)
        updated = None
        for _attempt in range(3):
            current = si_get_inventory(mothershipid)
            si_update_resources(mothershipid,
                                {'tech_points': int(current.get('TechPoints', 0)) + amount})
            updated = si_get_inventory(mothershipid)
            if int(updated.get('TechPoints', 0)) >= int(current.get('TechPoints', 0)) + amount:
                break
        return jsonify({'result': {'inventory': updated},
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[PurchaseTechPoints error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': str(e)}), 500


@app.route('/api/PurchaseResources', methods=['POST'])
def purchase_resources():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return jsonify({'result': None, 'statusCode': 400,
                            'error': 'Missing MothershipId'}), 400
        si_ensure_player_exists(mothershipid)
        si_update_resources(mothershipid, {
            'strange_wood': 20, 'weird_gear': 20, 'vibrating_spring': 20,
            'bouncy_sand': 20, 'floppy_metal': 20,
        })
        return jsonify({'result': {'inventory': si_get_inventory(mothershipid)},
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[PurchaseResources error] {e}")
        return jsonify({'result': None, 'statusCode': 500, 'error': str(e)}), 500

# ============================================================================
# Routes - progression tracks
# ============================================================================

@app.route('/api/GetProgression', methods=['GET', 'POST'])
def get_progression():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        trackid = body.get('TrackId', '')
        if not mothershipid or not trackid:
            return '0', 200
        row = db_get_one('progression', {'mothershipid': mothershipid,
                                         'trackid': trackid})
        return str((row or {}).get('progress', 0)), 200
    except Exception as e:
        print(f"[progression error] {e}")
        return '0', 200


@app.route('/api/SetProgression', methods=['POST'])
def set_progression():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        trackid = body.get('TrackId', '')
        progress = int(body.get('Progress', 0) or 0)
        if not mothershipid or not trackid:
            return jsonify({'statusCode': 400, 'error': 'Missing fields'}), 400
        db_upsert('progression', {'mothershipid': mothershipid, 'trackid': trackid,
                                  'progress': progress}, ['mothershipid', 'trackid'])
        return jsonify({'trackId': trackid, 'progress': progress,
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[set progression error] {e}")
        return jsonify({'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/UnlockProgressionTreeNode', methods=['POST'])
def unlock_progression_node():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        treeid = body.get('TreeId', body.get('TreeID', ''))
        nodeid = body.get('NodeId', body.get('NodeID', ''))
        if not mothershipid or not treeid or not nodeid:
            return jsonify({'error': 'Missing fields'}), 400
        db_upsert('progressionnodes', {
            'mothershipid': mothershipid, 'treeid': treeid, 'nodeid': nodeid,
            'unlockedat': utc_now_iso(),
        }, ['mothershipid', 'treeid', 'nodeid'])
        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"[unlock node error] {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Routes - shift credits / juicer / dock wrist / ghost reactor
# ============================================================================

SHIFT_CREDIT_CAP_BASE = 1000
SHIFT_CREDIT_CAP_PER_INCREASE = 50
SHIFT_CREDIT_CAP_INCREASES_MAX = 25


@app.route('/api/GetShiftCredit', methods=['GET', 'POST'])
def get_shift_credit():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        target = body.get('TargetMothershipId', mothershipid)
        if not target:
            return jsonify({'currentShiftCredits': 100, 'currentShiftCreditCapIncreases': 0,
                            'currentShiftCreditCapIncreasesMax': SHIFT_CREDIT_CAP_INCREASES_MAX,
                            'targetMothershipId': '', 'statusCode': 200, 'error': None})
        ensure_shift_credits(target)
        row = db_get_one('shiftcredits', {'mothershipid': target}) or {}
        return jsonify({
            'currentShiftCredits': row.get('currentcredits', 100),
            'currentShiftCreditCapIncreases': row.get('capincreases', 0),
            'currentShiftCreditCapIncreasesMax': SHIFT_CREDIT_CAP_INCREASES_MAX,
            'targetMothershipId': target,
            'statusCode': 200, 'error': None,
        })
    except Exception as e:
        print(f"[shift credit error] {e}")
        return jsonify({'currentShiftCredits': 100, 'currentShiftCreditCapIncreases': 0,
                        'currentShiftCreditCapIncreasesMax': SHIFT_CREDIT_CAP_INCREASES_MAX,
                        'targetMothershipId': '', 'statusCode': 200, 'error': None})


@app.route('/api/PurchaseShiftCreditCapIncrease', methods=['POST'])
def purchase_shift_credit_cap():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return 'Missing MothershipId', 400
        ensure_shift_credits(mothershipid)
        row = db_get_one('shiftcredits', {'mothershipid': mothershipid})
        if row and row.get('capincreases', 0) >= row.get('capincreasesmax',
                                                        SHIFT_CREDIT_CAP_INCREASES_MAX):
            return 'User Already Has Purchased Max Shift Credit Cap', 400
        db_update('shiftcredits', {'mothershipid': mothershipid},
                  {'capincreases': row.get('capincreases', 0) + 1})
        updated = db_get_one('shiftcredits', {'mothershipid': mothershipid}) or {}
        return jsonify({
            'currentShiftCreditCapIncreases': updated.get('capincreases', 0),
            'currentShiftCreditCapIncreasesMax': SHIFT_CREDIT_CAP_INCREASES_MAX,
            'targetMothershipId': mothershipid,
            'statusCode': 200, 'error': None,
        })
    except Exception as e:
        print(f"[purchase cap error] {e}")
        return jsonify({'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/PurchaseShiftCredit', methods=['POST'])
def purchase_shift_credit():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return 'Missing MothershipId', 400
        ensure_shift_credits(mothershipid)
        row = db_get_one('shiftcredits', {'mothershipid': mothershipid})
        max_credits = (SHIFT_CREDIT_CAP_BASE
                       + (row or {}).get('capincreases', 0) * SHIFT_CREDIT_CAP_PER_INCREASE)
        if row and row.get('currentcredits', 0) >= max_credits:
            return 'User Already at Max Shift Credit', 400
        new_credits = min((row or {}).get('currentcredits', 0) + 100, max_credits)
        db_update('shiftcredits', {'mothershipid': mothershipid},
                  {'currentcredits': new_credits})
        return jsonify({'currentShiftCredits': new_credits,
                        'targetMothershipId': mothershipid,
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[purchase credit error] {e}")
        return jsonify({'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/SubtractShiftCredit', methods=['GET', 'POST'])
def subtract_shift_credit():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        amount = int(body.get('ShiftCreditToRemove', 0) or 0)
        if not mothershipid:
            return jsonify({'statusCode': 400, 'error': 'Missing MothershipId'}), 400
        ensure_shift_credits(mothershipid)
        row = db_get_one('shiftcredits', {'mothershipid': mothershipid})
        new_credits = max(0, (row or {}).get('currentcredits', 0) - amount)
        db_update('shiftcredits', {'mothershipid': mothershipid},
                  {'currentcredits': new_credits})
        updated = db_get_one('shiftcredits', {'mothershipid': mothershipid}) or {}
        return jsonify({
            'currentShiftCredits': updated.get('currentcredits', new_credits),
            'currentShiftCreditCapIncreases': updated.get('capincreases', 0),
            'currentShiftCreditCapIncreasesMax': SHIFT_CREDIT_CAP_INCREASES_MAX,
            'targetMothershipId': None,
            'statusCode': 200, 'error': None,
        })
    except Exception as e:
        print(f"[subtract credit error] {e}")
        return jsonify({'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/DepositGRCore', methods=['GET', 'POST'])
def deposit_gr_core():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        coretype = int(body.get('CoreBeingDeposited', 0) or 0)
        if not mothershipid:
            return jsonify({'statusCode': 400, 'error': 'Missing MothershipId'}), 400
        ensure_shift_credits(mothershipid)
        if coretype == 3:
            db_update('shiftcredits', {'mothershipid': mothershipid},
                      {'currentcredits': 0})
            return jsonify({'currentShiftCredits': 0, 'statusCode': 200, 'error': None})
        credit_gain = 15 if coretype == 2 else 5
        row = db_get_one('shiftcredits', {'mothershipid': mothershipid})
        db_update('shiftcredits', {'mothershipid': mothershipid},
                  {'currentcredits': (row or {}).get('currentcredits', 0) + credit_gain})
        updated = db_get_one('shiftcredits', {'mothershipid': mothershipid}) or {}
        return jsonify({'currentShiftCredits': updated.get('currentcredits', 0),
                        'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[deposit core error] {e}")
        return jsonify({'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/RecycleTool', methods=['GET', 'POST'])
def recycle_tool():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        tooltype = int(body.get('ToolBeingRecycled', 0) or 0)
        if not mothershipid:
            return jsonify({'statusCode': 400, 'error': 'Missing MothershipId'}), 400
        recycle_values = {11: 10, 1: 5, 2: 5, 3: 5, 4: 5, 5: 5, 6: 10, 7: 10,
                          8: 15, 9: 10, 10: 15, 12: 10, 13: 15}
        credit_gain = recycle_values.get(tooltype, 5)
        ensure_shift_credits(mothershipid)
        row = db_get_one('shiftcredits', {'mothershipid': mothershipid})
        db_update('shiftcredits', {'mothershipid': mothershipid},
                  {'currentcredits': (row or {}).get('currentcredits', 0) + credit_gain})
        updated = db_get_one('shiftcredits', {'mothershipid': mothershipid}) or {}
        return jsonify({
            'currentShiftCredits': updated.get('currentcredits', 0),
            'currentShiftCreditCapIncreases': updated.get('capincreases', 0),
            'currentShiftCreditCapIncreasesMax': SHIFT_CREDIT_CAP_INCREASES_MAX,
            'targetMothershipId': mothershipid,
            'statusCode': 200, 'error': None,
        })
    except Exception as e:
        print(f"[recycle tool error] {e}")
        return jsonify({'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/GetJuicerStatus', methods=['GET', 'POST'])
def get_juicer_status():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return 'Missing MothershipId', 400
        ensure_juicer_status(mothershipid)
        row = db_get_one('juicerstatus', {'mothershipid': mothershipid}) or {}
        return jsonify({
            'mothershipId': mothershipid,
            'currentCoreCount': row.get('corecount', 0),
            'coreProcessingTimeSec': 10800,
            'coreProcessingPercent': row.get('processingpercent', 0),
            'overdriveSupply': row.get('overdrivesupply', 0),
            'overdriveCap': row.get('overdrivecap', 5),
            'coresProcessedByOverdrive': row.get('coresbyoverdrive', 0),
            'refreshJuice': bool(row.get('refreshjuice', 0)),
            'statusCode': 200, 'error': None,
        })
    except Exception as e:
        print(f"[juicer status error] {e}")
        return 'Error', 500


@app.route('/api/PurchaseOverdrive', methods=['POST'])
def purchase_overdrive():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return jsonify({'statusCode': 400, 'error': 'Missing MothershipId'}), 400
        ensure_juicer_status(mothershipid)
        row = db_get_one('juicerstatus', {'mothershipid': mothershipid})
        if row and row.get('overdrivesupply', 0) >= row.get('overdrivecap', 5):
            return 'User Already At Overdrive Cap', 400
        db_update('juicerstatus', {'mothershipid': mothershipid},
                  {'overdrivesupply': (row or {}).get('overdrivecap', 5)})
        return jsonify({'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[overdrive error] {e}")
        return 'Error', 500


@app.route('/api/AdvanceDockWristUpgrade', methods=['POST'])
def advance_dock_wrist():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        upgrade = int(body.get('Upgrade', 0) or 0)
        if not mothershipid:
            return 'Missing MothershipId', 400
        ensure_dock_wrist(mothershipid)
        col = f"upgrade{upgrade}level" if upgrade in (1, 2, 3) else "upgrade1level"
        row = db_get_one('dockwrist', {'mothershipid': mothershipid}) or {}
        db_update('dockwrist', {'mothershipid': mothershipid},
                  {col: row.get(col, 0) + 1})
        updated = db_get_one('dockwrist', {'mothershipid': mothershipid}) or {}
        return jsonify({
            'CurrentUpgrade1Level': updated.get('upgrade1level', 0),
            'CurrentUpgrade2Level': updated.get('upgrade2level', 0),
            'CurrentUpgrade3Level': updated.get('upgrade3level', 0),
            'Upgrade1LevelMax': updated.get('upgrade1max', 10),
            'Upgrade2LevelMax': updated.get('upgrade2max', 10),
            'Upgrade3LevelMax': updated.get('upgrade3max', 10),
        })
    except Exception as e:
        print(f"[dock wrist error] {e}")
        return 'Error', 500


@app.route('/api/GetDockWristUpgradeStatus', methods=['POST'])
def get_dock_wrist_status():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return 'Missing MothershipId', 400
        ensure_dock_wrist(mothershipid)
        row = db_get_one('dockwrist', {'mothershipid': mothershipid}) or {}
        return jsonify({
            'CurrentUpgrade1Level': row.get('upgrade1level', 0),
            'CurrentUpgrade2Level': row.get('upgrade2level', 0),
            'CurrentUpgrade3Level': row.get('upgrade3level', 0),
            'Upgrade1LevelMax': row.get('upgrade1max', 10),
            'Upgrade2LevelMax': row.get('upgrade2max', 10),
            'Upgrade3LevelMax': row.get('upgrade3max', 10),
        })
    except Exception as e:
        print(f"[dock status error] {e}")
        return 'Error', 500


@app.route('/api/StartOfShift', methods=['POST'])
def start_of_shift():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        shiftid = body.get('ShiftId', '')
        if not mothershipid or not shiftid:
            return jsonify({'statusCode': 400, 'error': 'Missing fields'}), 400
        db_upsert('shifts', {
            'shiftid': shiftid,
            'mothershipid': mothershipid,
            'coresrequired': int(body.get('CoresRequired', 0) or 0),
            'numberofplayers': int(body.get('NumberOfPlayers', 0) or 0),
            'depth': int(body.get('Depth', 0) or 0),
            'startedat': utc_now_iso(),
            'completed': 0,
        }, 'shiftid')
        return jsonify({'statusCode': 200, 'error': None})
    except Exception as e:
        print(f"[start shift error] {e}")
        return jsonify({'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/EndOfShiftReward', methods=['POST'])
def end_of_shift_reward():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        shiftid = body.get('ShiftId', '')
        if not mothershipid:
            return jsonify({'statusCode': 400, 'error': 'Missing MothershipId'}), 400
        if shiftid:
            db_update('shifts', {'shiftid': shiftid}, {'completed': 1})
        ensure_shift_credits(mothershipid)
        row = db_get_one('shiftcredits', {'mothershipid': mothershipid})
        db_update('shiftcredits', {'mothershipid': mothershipid},
                  {'currentcredits': (row or {}).get('currentcredits', 0) + 25})
        updated = db_get_one('shiftcredits', {'mothershipid': mothershipid}) or {}
        return jsonify({
            'currentShiftCredits': updated.get('currentcredits', 0),
            'currentShiftCreditCapIncreases': updated.get('capincreases', 0),
            'currentShiftCreditCapIncreasesMax': SHIFT_CREDIT_CAP_INCREASES_MAX,
            'targetMothershipId': mothershipid,
            'statusCode': 200, 'error': None,
        })
    except Exception as e:
        print(f"[end shift error] {e}")
        return jsonify({'statusCode': 500, 'error': 'Internal error'}), 500


@app.route('/api/GetGhostReactorStats', methods=['POST'])
def get_ghost_reactor_stats():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return 'Missing MothershipId', 400
        ensure_reactor_stats(mothershipid)
        row = db_get_one('reactorstats', {'mothershipid': mothershipid}) or {}
        return jsonify({'MothershipId': mothershipid,
                        'MaxDepthReached': row.get('maxdepthreached', 0)})
    except Exception as e:
        print(f"[reactor stats error] {e}")
        return 'Error', 500


@app.route('/api/GetGhostReactorInventory', methods=['POST'])
def get_ghost_reactor_inventory():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid:
            return 'Missing MothershipId', 400
        ensure_reactor_inventory(mothershipid)
        row = db_get_one('reactorinventory', {'mothershipid': mothershipid}) or {}
        return jsonify({'MothershipId': mothershipid,
                        'InventoryJson': row.get('inventoryjson', '{}')})
    except Exception as e:
        print(f"[reactor inventory error] {e}")
        return 'Error', 500


@app.route('/api/SetGhostReactorInventory', methods=['POST'])
def set_ghost_reactor_inventory():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        inventoryjson = body.get('InventoryJson', '{}')
        if not mothershipid:
            return 'Missing MothershipId', 400
        if isinstance(inventoryjson, (dict, list)):
            inventoryjson = json.dumps(inventoryjson)
        else:
            if safe_json_loads(inventoryjson) is None:
                return 'Invalid JSON', 400
        ensure_reactor_inventory(mothershipid)
        db_update('reactorinventory', {'mothershipid': mothershipid},
                  {'inventoryjson': inventoryjson})
        return jsonify({'MothershipId': mothershipid})
    except Exception as e:
        print(f"[set reactor inventory error] {e}")
        return 'Error', 500

# ============================================================================
# Routes - shared maps / Monke Blocks (Virtual Stump / Destinations)
#
# Client contract (ref game files 25/GorillaTagScripts.Builder/
# SharedBlocksManager.cs): Publish/GetMaps/GetMapData/MapVote/UpdateMapActive.
# Every call carries mothershipId + mothershipToken in the body; when the id is
# empty we fall back to the token so an auth quirk cannot turn a working call
# into a 400. Publish returns a plain 8-char map id from the official alphabet
# (^[CFGHKMNPRTWXZ256789]{8}$ - the client validates the pattern itself).
# ============================================================================

def map_request_identity(body):
    """Resolve the Monke Blocks caller: body mothershipId, else the Mothership
    token from the body, else the x-mothership-token header."""
    mothershipid = str(body.get('mothershipId') or body.get('MothershipId') or '').strip()
    if mothershipid:
        return mothershipid
    token = body.get('mothershipToken') or body.get('MothershipToken') or ''
    decoded = verify_token(token) if token else None
    if not decoded:
        decoded = verify_token(request.headers.get('x-mothership-token', ''))
    return str((decoded or {}).get('sub', '') or '').strip()


def db_insert_strict(table, data):
    """Insert and report real success. db_insert() swallows errors, which
    would let /api/Publish answer 'success' for a map that was never stored."""
    if not supabase:
        return False
    try:
        supabase.table(table).insert(data).execute()
        return True
    except Exception as e:
        print(f"[db_insert_strict error] {table}: {e}")
        return False


@app.route('/api/Publish', methods=['POST'])
def publish_map():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = map_request_identity(body)
        metadatakey = str(body.get('userdataMetadataKey')
                          or body.get('userDataMetadataKey') or '').strip()
        nickname = str(body.get('playerNickname') or body.get('PlayerNickname') or '')
        if not mothershipid or not metadatakey:
            print(f"[publish map] missing fields id={bool(mothershipid)} "
                  f"key={metadatakey!r} body={str(body)[:220]}")
            return 'Missing fields', 400

        mapid = generate_map_id()
        ud = db_get_one('mothershipuserdata',
                        {'mothershipid': mothershipid, 'keyname': metadatakey})
        mapdata = (ud or {}).get('datavalue', '')
        if not mapdata:
            print(f"[publish map] no userdata row {mothershipid}/{metadatakey} - "
                  f"publishing empty map data")

        inserted = db_insert_strict('sharedmaps', {
            'mapid': mapid,
            'mothershipid': mothershipid,
            'userdatametadatakey': metadatakey,
            'nickname': nickname,
            'mapdata': mapdata,
            'isactive': 1,
        })
        if not inserted:
            print(f"[publish map] sharedmaps insert failed for {mapid} - not reporting success")
            return 'Error', 500
        print(f"[publish map] id={mapid} key={metadatakey} nickname={nickname!r} "
              f"bytes={len(mapdata)}")
        return mapid, 200
    except Exception as e:
        print(f"[publish map error] {e}")
        return 'Error', 500


@app.route('/api/GetMapData', methods=['POST'])
def get_map_data():
    """Returns the stored map payload verbatim - the official server hands the
    client the same base64/gzip blob it uploaded to Mothership user data."""
    try:
        body = request.get_json(silent=True) or {}
        mapid = str(body.get('mapId') or body.get('MapId') or '').strip()
        if not mapid:
            return '', 400
        row = db_get_one('sharedmaps', {'mapid': mapid}, 'mapdata')
        if not row:
            print(f"[get map data] unknown map id {mapid}")
            return '', 404
        return (row or {}).get('mapdata', ''), 200
    except Exception as e:
        print(f"[get map error] {e}")
        return '', 500


@app.route('/api/GetMaps', methods=['POST'])
def get_maps():
    """Official captured shape: [{mapId, nickname, createdTime, updatedTime,
    voteCount, isActive}]. sort carries the client's MapSortMethod name:
    'Top' | 'NewlyCreated' | 'RecentlyUpdated'."""
    try:
        body = request.get_json(silent=True) or {}
        page = max(0, int(body.get('page', 0) or 0))
        pagesize = min(max(1, int(body.get('pageSize', 20) or 20)), 100)
        sort = str(body.get('sort', 'Top') or 'Top')
        show_inactive = bool(body.get('ShowInactive', False))

        order_col = 'createdat'
        if sort == 'Top':
            order_col = 'votecount'
        elif sort == 'RecentlyUpdated':
            order_col = 'updatedat'

        rows = db_get('sharedmaps',
                      None if show_inactive else {'isactive': 1},
                      order_by=(order_col, True))

        start = page * pagesize
        page_rows = rows[start:start + pagesize]

        maps = [{
            'mapId': row.get('mapid'),
            'nickname': row.get('nickname'),
            'createdTime': row.get('createdat') or '',
            'updatedTime': row.get('updatedat') or '',
            'voteCount': int(row.get('votecount', 0) or 0),
            'isActive': bool(row.get('isactive', 0)),
        } for row in page_rows]
        return jsonify(maps)
    except Exception as e:
        print(f"[get maps error] {e}")
        return jsonify([]), 500


@app.route('/api/MapVote', methods=['POST'])
def map_vote():
    """Official captured response: {'voteCount': N, 'statusCode': 201, 'error': None}
    vote is +1 / -1; re-voting replaces that player's previous value."""
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = map_request_identity(body)
        mapid = str(body.get('mapId') or body.get('MapId') or '').strip()
        try:
            vote = int(body.get('vote', 0) or 0)
        except (TypeError, ValueError):
            vote = 0
        vote = max(-1, min(1, vote))
        if not mothershipid or not mapid:
            print(f"[map vote] missing fields id={bool(mothershipid)} map={mapid!r}")
            return 'Missing fields', 400

        db_upsert('mapvotes', {'mapid': mapid, 'mothershipid': mothershipid,
                               'vote': vote}, ['mapid', 'mothershipid'])
        total = sum(int(v.get('vote', 0) or 0)
                    for v in db_get('mapvotes', {'mapid': mapid}))
        db_update('sharedmaps', {'mapid': mapid}, {'votecount': total})
        print(f"[map vote] mothership={mothershipid} map={mapid} vote={vote} total={total}")
        return jsonify({'voteCount': total, 'statusCode': 201, 'error': None}), 201
    except Exception as e:
        print(f"[map vote error] {e}")
        return 'Error', 500


@app.route('/api/UpdateMapActive', methods=['POST'])
def update_map_active():
    """Called by SharedBlocksManager when a save slot's published map is
    (de)activated. Body: {mothershipId, mothershipToken, userdataMetadataKey,
    setActive}; the client only checks for a 2xx response."""
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = map_request_identity(body)
        metadatakey = str(body.get('userdataMetadataKey')
                          or body.get('userDataMetadataKey') or '').strip()
        set_active = bool(body.get('setActive', body.get('SetActive', False)))
        if not mothershipid or not metadatakey:
            print(f"[update map active] missing fields id={bool(mothershipid)} "
                  f"key={metadatakey!r}")
            return 'Missing fields', 400

        rows = db_get('sharedmaps', {'mothershipid': mothershipid,
                                     'userdatametadatakey': metadatakey})
        for row in rows:
            db_update('sharedmaps', {'mapid': row.get('mapid')},
                      {'isactive': 1 if set_active else 0,
                       'updatedat': utc_now_iso()})
        print(f"[update map active] mothership={mothershipid} key={metadatakey} "
              f"active={set_active} maps={len(rows)}")
        return 'OK', 200
    except Exception as e:
        print(f"[update map active error] {e}")
        return 'Error', 500

# ============================================================================
# Routes - Monke Vote polls
#
# Poll definitions come from api/data/Every Poll Question.json (the official
# FetchPoll dump shape, pollId 20+); Supabase poll_votes stores what players on
# THIS server voted. Client contract (MonkeVoteController.cs):
#   POST /api/FetchPoll {TitleId, PlayFabId, PlayFabTicket, IncludeInactive}
#        -> JSON ARRAY of {pollId, question, voteOptions, voteCount,
#                          predictionCount, startTime, endTime, isActive}
#   POST /api/Vote {PollId, TitleId, PlayFabId, OculusId, UserNonce,
#                   UserPlatform, OptionIndex, IsPrediction, PlayFabTicket}
#        -> {pollId, titleId, voteOptions, voteCount, predictionCount}
# The client hides results while a poll is RUNNING (official returns empty
# count arrays then) and shows the previous poll's counts, and it expects a 429
# for a duplicate vote ("User already voted on this poll!"). A vote and a
# prediction are independent rows: the client's own state machine requires the
# vote first, but the official server accepts a prediction on its own (the
# captured Vote request was IsPrediction=true with no prior vote in the dump), so
# we do too.
# ============================================================================

POLL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'data', 'Every Poll Question.json')
_poll_file_cache = {'polls': None, 'ts': 0.0, 'mtime': None}
_POLL_FILE_TTL = 60.0


def _load_poll_file():
    """Poll definitions from data/Every Poll Question.json.

    The file has been seen both as plain JSON and as a double-escaped JSON
    string (every quote stored as \\"), so parse plain first and fall back to
    decoding it as an escaped string.
    """
    try:
        mtime = os.path.getmtime(POLL_FILE)
    except OSError as e:
        print(f"[polls] cannot stat {POLL_FILE}: {e}")
        return []
    now = time.time()
    if (_poll_file_cache['polls'] is not None
            and _poll_file_cache['mtime'] == mtime
            and now - _poll_file_cache['ts'] < _POLL_FILE_TTL):
        return _poll_file_cache['polls']

    polls = []
    try:
        with open(POLL_FILE, 'r', encoding='utf-8') as f:
            raw = f.read()
        try:
            polls = json.loads(raw)
        except Exception:
            polls = json.loads(json.loads('"' + raw.strip() + '"'))
        if not isinstance(polls, list):
            polls = []
    except Exception as e:
        print(f"[polls] failed to load {POLL_FILE}: {e}")
        polls = []

    if polls:
        print(f"[polls] loaded {len(polls)} polls from file")
    _poll_file_cache.update({'polls': polls, 'ts': now, 'mtime': mtime})
    return polls


def _poll_definition(poll_id):
    for poll in _load_poll_file():
        try:
            if int(poll.get('pollId')) == int(poll_id):
                return poll
        except (TypeError, ValueError):
            continue
    return None


def _poll_vote_counts(poll_id, option_count=2):
    """This server's votes/predictions for one poll (Supabase overlay)."""
    votes = [0] * option_count
    preds = [0] * option_count
    for row in db_get('poll_votes', {'poll_id': poll_id}):
        try:
            idx = int(row.get('option_index', -1))
        except (TypeError, ValueError):
            continue
        if 0 <= idx < option_count:
            if row.get('is_prediction'):
                preds[idx] += 1
            else:
                votes[idx] += 1
    return votes, preds


def _vote_payload(poll, title_id=None):
    """Official VoteResponse: exactly the five captured keys - the client's
    VoteResponse class has no board fields (question/times/isActive)."""
    full = _poll_payload(poll, include_counts=not bool(poll.get('isActive')),
                         with_title=True, title_id=title_id)
    return {k: full[k] for k in ('pollId', 'titleId', 'voteOptions',
                                 'voteCount', 'predictionCount')}


def _poll_payload(poll, include_counts=True, with_title=False, title_id=None):
    """Official poll object; base counts from the file + our own votes."""
    options = list(poll.get('voteOptions') or [])
    vote_counts, pred_counts = _poll_vote_counts(poll.get('pollId'),
                                                max(2, len(options)))
    base_votes = list(poll.get('voteCount') or [])
    base_preds = list(poll.get('predictionCount') or [])
    out_votes = []
    out_preds = []
    for i in range(len(options)):
        base_v = int(base_votes[i]) if i < len(base_votes) and base_votes[i] is not None else 0
        base_p = int(base_preds[i]) if i < len(base_preds) and base_preds[i] is not None else 0
        out_votes.append(base_v + vote_counts[i])
        out_preds.append(base_p + pred_counts[i])
    payload = {
        'pollId': int(poll.get('pollId') or 0),
        'question': poll.get('question', ''),
        'voteOptions': options,
        'voteCount': out_votes if include_counts else [],
        'predictionCount': out_preds if include_counts else [],
        'startTime': poll.get('startTime') or '',
        'endTime': poll.get('endTime') or '',
        'isActive': bool(poll.get('isActive')),
    }
    if with_title:
        # official VoteResponse echoes the request's TitleId (captured: '63FDD')
        payload['titleId'] = title_id or CONFIG['playfab_title_id']
    return payload


@app.route('/api/FetchPoll', methods=['GET', 'POST'])
def fetch_poll():
    try:
        body = request.get_json(silent=True) or {}
        include_inactive = bool(body.get('IncludeInactive', True))
        polls = sorted(_load_poll_file(),
                       key=lambda p: int(p.get('pollId') or 0))
        results = []
        active_seen = False
        for poll in polls:
            is_active = bool(poll.get('isActive'))
            if is_active:
                active_seen = True
            if not include_inactive and not is_active:
                continue
            # results stay hidden while a poll is running (official shape)
            results.append(_poll_payload(poll, include_counts=not is_active))
        if not active_seen:
            print("[polls] warning: no active poll in Every Poll Question.json - "
                  "add/advance the newest poll so the vote machine works")
        return jsonify(results)
    except Exception as e:
        print(f"[fetch poll error] {e}")
        return jsonify([]), 500


@app.route('/api/Vote', methods=['GET', 'POST'])
def vote():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = str(body.get('PlayFabId') or '').strip() or quest_player_id(body)
        is_prediction = bool(body.get('IsPrediction', False))
        try:
            poll_id = int(body.get('PollId'))
        except (TypeError, ValueError):
            poll_id = 0
        try:
            option_index = int(body.get('OptionIndex'))
        except (TypeError, ValueError):
            option_index = -1

        if not playfabid or not poll_id or option_index < 0:
            print(f"[poll vote] missing fields: {str(body)[:220]}")
            return jsonify({'error': 'Missing fields'}), 400

        poll = _poll_definition(poll_id)
        if not poll:
            print(f"[poll vote] unknown poll {poll_id}")
            return jsonify({'error': 'Poll not found'}), 404
        options = list(poll.get('voteOptions') or [])
        if option_index >= len(options):
            return jsonify({'error': 'Invalid option'}), 400

        # Mirror the definition into Supabase so poll_votes' FK to polls holds.
        db_upsert('polls', {
            'id': poll_id,
            'question': poll.get('question', ''),
            'options_json': json.dumps(options),
            'created_at': poll.get('startTime') or utc_now_iso(),
            'expires_at': poll.get('endTime') or None,
        }, ['id'])

        existing = db_get_one('poll_votes', {
            'poll_id': poll_id, 'playfabid': playfabid,
            'is_prediction': 1 if is_prediction else 0})
        if existing:
            # official answers 429 - the client treats it as "already voted"
            print(f"[poll vote] duplicate playfab={playfabid} poll={poll_id} "
                  f"prediction={is_prediction}")
            return jsonify({'error': 'Already voted'}), 429

        db_insert('poll_votes', {
            'poll_id': poll_id, 'playfabid': playfabid,
            'option_index': option_index,
            'is_prediction': 1 if is_prediction else 0,
            'created_at': utc_now_iso(),
        })
        print(f"[poll vote] playfab={playfabid} poll={poll_id} "
              f"option={option_index} prediction={is_prediction}")
        return jsonify(_vote_payload(poll,
                                     title_id=str(body.get('TitleId') or '').strip()))
    except Exception as e:
        print(f"[vote error] {e}")
        return jsonify({'error': 'Internal error'}), 500

# ============================================================================
# Routes - redeemable codes
# ============================================================================

@app.route('/api/ConsumeCodeItem', methods=['POST'])
def consume_code_item():
    try:
        body = request.get_json(silent=True) or {}
        code = (body.get('itemGUID', '') or '').strip().upper()
        playfabid = body.get('playFabID', '')
        mothershipid = body.get('mothershipId', body.get('MothershipId', ''))

        if not code or len(code) < 8:
            return jsonify({'result': 'Invalid'})

        code_row = db_get_one('redeemable_codes', {'code': code, 'active': 1})
        if not code_row:
            return jsonify({'result': 'Invalid'})

        now = datetime.now(timezone.utc)
        if code_row.get('start_time'):
            start = safe_json_loads(code_row['start_time'])
            try:
                if now < datetime.fromisoformat(str(code_row['start_time']).replace('Z', '+00:00')):
                    return jsonify({'result': 'TooEarly'})
            except Exception:
                pass
        if code_row.get('end_time'):
            try:
                if now > datetime.fromisoformat(str(code_row['end_time']).replace('Z', '+00:00')):
                    return jsonify({'result': 'TooLate'})
            except Exception:
                pass
        if code_row.get('max_uses', -1) >= 0 and \
                code_row.get('use_count', 0) >= code_row['max_uses']:
            return jsonify({'result': 'AlreadyRedeemed'})

        if mothershipid and db_get_one('code_redemptions',
                                       {'code': code, 'mothershipid': mothershipid}):
            return jsonify({'result': 'AlreadyRedeemed'})

        db_insert('code_redemptions', {
            'code_id': code_row.get('id'), 'code': code,
            'mothershipid': mothershipid, 'playfabid': playfabid,
            'createdat': utc_now_iso(),
        })
        db_update('redeemable_codes', {'id': code_row['id']},
                  {'use_count': code_row.get('use_count', 0) + 1})

        if code_row.get('type') == 'discord_link' and code_row.get('discord_id'):
            db_upsert('discord_links', {
                'discord_id': code_row['discord_id'],
                'playfabid': playfabid,
                'mothershipid': mothershipid,
                'linked_at': utc_now_iso(),
            }, 'discord_id')

        if playfabid and code_row.get('playfab_item_name') and CONFIG['playfab_secret_key']:
            playfab_grant_items_to_user(playfabid, [code_row['playfab_item_name']])

        return jsonify({'result': 'Success', 'itemID': code_row.get('item_id'),
                        'playFabItemName': code_row.get('playfab_item_name')})
    except Exception as e:
        print(f"[code redeem error] {e}")
        return jsonify({'result': 'Error'}), 500

# ============================================================================
# Routes - moderation / presence
# ============================================================================

@app.route('/api/CCU', methods=['GET', 'POST'])
def ccu_endpoint():
    """BOTH key spellings are returned: the official client reads 'ccuTotal'
    (captured) while legacy mods read 'ccount'."""
    ccu = get_ccu()
    return jsonify({'ccuTotal': ccu, 'ccount': ccu, 'errorMessage': None})


@app.route('/api/UpdatePresence', methods=['POST'])
def update_presence():
    try:
        body = request.get_json(silent=True) or {}
        playfabid = body.get('PlayFabId', '')
        mothershipid = body.get('MothershipId', '')
        if playfabid:
            db_upsert('friendpresence', {
                'playfabid': playfabid,
                'roomid': body.get('RoomId', ''),
                'region': body.get('Region', ''),
                'zone': body.get('Zone', ''),
                'updatedat': utc_now_iso(),
            }, 'playfabid')
        if mothershipid:
            update_player_presence(mothershipid)
        elif playfabid:
            update_player_presence(playfabid)
        return jsonify({'success': True})
    except Exception as e:
        print(f"[presence error] {e}")
        return jsonify({'success': False}), 500

# ============================================================================
# Routes - Dear Lemming
# ============================================================================

DEAR_LEMMING_COOLDOWN_SECONDS = 300

DEAR_LEMMING_BAD_WORDS = [
    'nigger', 'nigga', 'faggot', 'kike', 'spic', 'chink', 'gook', 'tranny',
    'cunt', 'whore', 'slut', 'motherfucker', 'niglet', '@everyone',
]

def _dear_lemming_cooldown(mothershipid):
    last = db_get_one('dear_lemmings', {'mothershipid': mothershipid},
                      order_by=('createdat', True))
    if not last or not last.get('createdat'):
        return 0, None
    try:
        last_time = datetime.fromisoformat(str(last['createdat']).replace('Z', '+00:00'))
    except Exception:
        return 0, None
    elapsed = (datetime.now(timezone.utc) - last_time).total_seconds()
    if elapsed < DEAR_LEMMING_COOLDOWN_SECONDS:
        remaining = DEAR_LEMMING_COOLDOWN_SECONDS - elapsed
        next_time = datetime.now(timezone.utc) + timedelta(seconds=remaining)
        return remaining, next_time.isoformat()
    return 0, None


@app.route('/api/CheckDearLemming', methods=['POST'])
def check_dear_lemming():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid and body.get('MothershipToken'):
            decoded = verify_token(body['MothershipToken'])
            if decoded:
                mothershipid = decoded.get('sub', '')
        if not mothershipid:
            return jsonify({'CanSubmit': False, 'NextSubmitTimeUtc': None,
                            'SecondsUntilNextSubmit': None, 'Error': 'Missing ID',
                            'StatusCode': 400})
        remaining, next_time = _dear_lemming_cooldown(mothershipid)
        if remaining:
            return jsonify({'CanSubmit': False, 'NextSubmitTimeUtc': next_time,
                            'SecondsUntilNextSubmit': int(remaining), 'Error': None,
                            'StatusCode': 200})
        return jsonify({'CanSubmit': True, 'NextSubmitTimeUtc': None,
                        'SecondsUntilNextSubmit': None, 'Error': None,
                        'StatusCode': 200})
    except Exception as e:
        print(f"[check lemming error] {e}")
        return jsonify({'CanSubmit': False, 'NextSubmitTimeUtc': None,
                        'SecondsUntilNextSubmit': None, 'Error': str(e),
                        'StatusCode': 500})


@app.route('/api/SubmitDearLemming', methods=['POST'])
def submit_dear_lemming():
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipId', '')
        if not mothershipid and body.get('MothershipToken'):
            decoded = verify_token(body['MothershipToken'])
            if decoded:
                mothershipid = decoded.get('sub', '')
        message_text = (body.get('MessageText', '') or '').strip()[:500]

        if not mothershipid:
            return jsonify({'CanSubmit': False, 'NextSubmitTimeUtc': None,
                            'SecondsUntilNextSubmit': None, 'Error': 'Missing ID',
                            'StatusCode': 400})
        if not message_text:
            return jsonify({'CanSubmit': False, 'NextSubmitTimeUtc': None,
                            'SecondsUntilNextSubmit': None, 'Error': 'Invalid message',
                            'StatusCode': 400})

        msg_lower = message_text.lower()
        for word in DEAR_LEMMING_BAD_WORDS:
            if word in msg_lower:
                # auto-ban via PlayFab when linked (private-server moderation)
                try:
                    ms = db_get_one('mothershipplayers', {'mothershipid': mothershipid})
                    pf_id = (ms or {}).get('userid', '')
                    if pf_id and CONFIG['playfab_secret_key']:
                        playfab_ban_users([pf_id],
                                          f'INAPPROPRIATE CONTENT SENT IN DEAR LEMMING MACHINE: {word}',
                                          0)
                except Exception:
                    pass
                return jsonify({'CanSubmit': False, 'NextSubmitTimeUtc': None,
                                'SecondsUntilNextSubmit': None,
                                'Error': 'Inappropriate content', 'StatusCode': 400})

        remaining, next_time = _dear_lemming_cooldown(mothershipid)
        if remaining:
            return jsonify({'CanSubmit': False, 'NextSubmitTimeUtc': next_time,
                            'SecondsUntilNextSubmit': int(remaining), 'Error': None,
                            'StatusCode': 200})

        display_name = None
        ms = db_get_one('mothershipplayers', {'mothershipid': mothershipid})
        if ms and ms.get('userid'):
            pf = db_get_one('players', {'playfabid': ms['userid']})
            display_name = (pf or {}).get('displayname')

        db_insert('dear_lemmings', {
            'mothershipid': mothershipid,
            'message_text': message_text,
            'display_name': display_name,
            'createdat': utc_now_iso(),
        })
        return jsonify({'CanSubmit': True, 'NextSubmitTimeUtc': None,
                        'SecondsUntilNextSubmit': None, 'Error': None,
                        'StatusCode': 200})
    except Exception as e:
        print(f"[submit lemming error] {e}")
        return jsonify({'CanSubmit': False, 'NextSubmitTimeUtc': None,
                        'SecondsUntilNextSubmit': None, 'Error': str(e),
                        'StatusCode': 500})

# ============================================================================
# Routes - Photon webhooks (room lifecycle, presence, reports)
# ============================================================================

def handle_photon_event(args):
    """Handle all Photon webhook events (Create/Join/Leave/Close/Event)."""
    try:
        if not args or not args.get('GameId'):
            return jsonify({'ResultCode': 0, 'Message': 'Success'})

        playfab_id = args.get('PlayFabId') or args.get('UserId') or ''
        game_id = args.get('GameId', '')
        region = args.get('Region', '')
        nickname = args.get('Username') or args.get('Nickname') or ''
        actor_nr = args.get('ActorNr', 0)
        event_type = args.get('Type', '')

        # Friend presence
        try:
            if event_type in ('Create', 'Join') and playfab_id:
                db_upsert('friendpresence', {
                    'playfabid': playfab_id,
                    'roomid': game_id,
                    'zone': '',
                    'region': region,
                    'nickname': nickname,
                    'updatedat': utc_now_iso(),
                }, 'playfabid')
            elif event_type in ('ClientDisconnect', 'TimeoutDisconnect') and playfab_id:
                db_update('friendpresence', {'playfabid': playfab_id},
                          {'roomid': '', 'updatedat': utc_now_iso()})
        except Exception as e:
            print(f"[Photon] presence error: {e}")

        # Room registry
        try:
            if event_type == 'Create':
                db_upsert('rooms', {'gameid': game_id, 'region': region,
                                    'createdat': utc_now_iso(), 'isactive': 1},
                          'gameid')
            elif event_type == 'Close':
                db_update('rooms', {'gameid': game_id}, {'isactive': 0})
        except Exception as e:
            print(f"[Photon] rooms error: {e}")

        # Shared-group room data (actor -> inventory string), self-hosted
        try:
            group_id = game_id + region
            if event_type == 'Create':
                if isinstance(args.get('CreateOptions'), dict):
                    pass  # visibility stored implicitly
                db_upsert('sharedgroupdata',
                          {'groupid': group_id, 'datakey': str(actor_nr),
                           'value': '', 'updatedat': utc_now_iso()},
                          ['groupid', 'datakey'])
            elif event_type == 'Join':
                db_upsert('sharedgroupdata',
                          {'groupid': group_id, 'datakey': str(actor_nr),
                           'value': '', 'updatedat': utc_now_iso()},
                          ['groupid', 'datakey'])
            elif event_type in ('ClientDisconnect', 'TimeoutDisconnect'):
                db_delete('sharedgroupdata',
                          {'groupid': group_id, 'datakey': str(actor_nr)})
            elif event_type == 'Close':
                rows = db_get('sharedgroupdata', {'groupid': group_id})
                for row in rows:
                    db_delete('sharedgroupdata',
                              {'groupid': group_id, 'datakey': row.get('datakey')})
        except Exception as e:
            print(f"[Photon] shared group error: {e}")

        # Custom events
        try:
            if event_type == 'Event':
                ev_code = args.get('EvCode', 0)
                if ev_code == 50:
                    # Player report
                    data = args.get('Data', []) or []
                    reported_id = data[0] if len(data) > 0 else 'Unknown'
                    report_code = int(data[1]) if len(data) > 1 and \
                        str(data[1]).isdigit() else 0
                    reported_name = data[2] if len(data) > 2 else 'Unknown'
                    reporter_name = data[3] if len(data) > 3 else nickname or 'Unknown'
                    reasons = ['None', 'Hate Speech', 'Harassment', 'Cheating',
                               'Trolling', 'Inappropriate Name', 'Toxicity', 'Other']
                    reason = reasons[report_code] if report_code < len(reasons) else 'Unknown'
                    db_insert('player_reports', {
                        'reporter_playfabid': playfab_id,
                        'reporter_name': reporter_name,
                        'reported_playfabid': reported_id,
                        'reported_name': reported_name,
                        'reason': reason,
                        'room_code': game_id,
                        'createdat': utc_now_iso(),
                    })
                    print(f"[Photon] report: {reporter_name} -> {reported_name} ({reason})")
        except Exception as e:
            print(f"[Photon] event error: {e}")

        return jsonify({'ResultCode': 0, 'Message': 'Success'})
    except Exception as e:
        print(f"[Photon] error: {e}")
        return jsonify({'ResultCode': 0, 'Message': 'Success'})


@app.route('/api/photon', methods=['POST'])
def photon_auth():
    """Photon custom authentication webhook. Legacy response includes the
    'resources' block (pre-rewrite shape) - empty when no SI data exists."""
    try:
        body = request.get_json(silent=True) or {}
        ticket = body.get('Ticket') or body.get('token') or ''
        if not ticket:
            return jsonify({'resultCode': 2, 'message': 'Invalid token',
                            'userId': None, 'nickname': None}), 403

        playfabid = playfab_pfid_from_session_ticket(ticket)
        if not playfabid:
            return jsonify({'resultCode': 2, 'message': 'Invalid token',
                            'userId': None, 'nickname': None}), 403

        nickname = playfabid
        mothershipid = None
        player = db_get_one('players', {'playfabid': playfabid})
        if player and player.get('displayname'):
            nickname = player['displayname']
        elif CONFIG['playfab_secret_key']:
            try:
                pf = playfab_get_player_profile(playfabid)
                pf_name = (pf.get('data', {}).get('data', {})
                           .get('PlayerProfile', {}).get('DisplayName'))
                if pf_name:
                    nickname = pf_name
            except Exception:
                pass

        ms = db_get_one('mothershipplayers', {'userid': playfabid})
        if ms:
            mothershipid = ms.get('mothershipid')
        else:
            device = db_get_one('device_players', {'playfabid': playfabid})
            if device:
                mothershipid = device.get('mothershipid')

        update_player_presence(mothershipid or playfabid)

        resources = {}
        if mothershipid:
            try:
                si_ensure_player_exists(mothershipid)
                inv = si_get_inventory(mothershipid)
                resources = {
                    'techPoints': inv.get('TechPoints', 0),
                    'strangeWood': inv.get('StrangeWood', 0),
                    'weirdGear': inv.get('WeirdGear', 0),
                    'vibratingSpring': inv.get('VibratingSpring', 0),
                    'bouncySand': inv.get('BouncySand', 0),
                    'floppyMetal': inv.get('FloppyMetal', 0),
                }
            except Exception as e:
                print(f"[photon auth] resources error: {e}")

        return jsonify({
            'resultCode': 1,
            'message': 'Authenticated',
            'userId': playfabid,
            'nickname': nickname,
            'mothershipId': mothershipid,
            'resources': resources,
        })
    except Exception as e:
        print(f"[photon auth error] {e}")
        return jsonify({'resultCode': 0, 'message': 'Something went wrong'}), 500


@app.route('/api/photon/Create', methods=['POST'])
def photon_create():
    try:
        body = request.get_json(silent=True) or {}
        body['Type'] = 'Create'
        return handle_photon_event(body)
    except Exception as e:
        print(f"[photon/Create error] {e}")
        return jsonify({'ResultCode': 0, 'Message': 'Success'})


@app.route('/api/photon/Join', methods=['POST'])
def photon_join():
    try:
        body = request.get_json(silent=True) or {}
        body['Type'] = 'Join'
        return handle_photon_event(body)
    except Exception as e:
        print(f"[photon/Join error] {e}")
        return jsonify({'ResultCode': 0, 'Message': 'Success'})


@app.route('/api/photon/ClientDisconnect', methods=['POST'])
def photon_client_disconnect():
    try:
        body = request.get_json(silent=True) or {}
        body['Type'] = 'ClientDisconnect'
        return handle_photon_event(body)
    except Exception as e:
        print(f"[photon/ClientDisconnect error] {e}")
        return jsonify({'ResultCode': 0, 'Message': 'Success'})


@app.route('/api/photon/TimeoutDisconnect', methods=['POST'])
def photon_timeout_disconnect():
    try:
        body = request.get_json(silent=True) or {}
        body['Type'] = 'TimeoutDisconnect'
        return handle_photon_event(body)
    except Exception as e:
        print(f"[photon/TimeoutDisconnect error] {e}")
        return jsonify({'ResultCode': 0, 'Message': 'Success'})


@app.route('/api/photon/Event', methods=['POST'])
def photon_event():
    try:
        body = request.get_json(silent=True) or {}
        body['Type'] = 'Event'
        return handle_photon_event(body)
    except Exception as e:
        print(f"[photon/Event error] {e}")
        return jsonify({'ResultCode': 0, 'Message': 'Success'})


@app.route('/api/photon/GameProperties', methods=['POST'])
def photon_game_properties():
    return jsonify({'ResultCode': 0, 'Message': 'Success'})


@app.route('/api/photon/Close', methods=['POST'])
def photon_close():
    """Room close with optional Save state (reconnection support)."""
    try:
        body = request.get_json(silent=True) or {}
        game_id = body.get('GameId', '')
        event_type = body.get('Type', 'Close')

        if event_type == 'Save' and body.get('State') and game_id:
            state = body['State']
            state.setdefault('CustomProperties', {})
            state['CustomProperties']['roomControlsEnabled'] = True
            state['MaxPlayers'] = 20
            db_upsert('room_states', {
                'gameid': game_id,
                'region': body.get('Region', ''),
                'state_json': json.dumps(state),
                'updatedat': utc_now_iso(),
            }, 'gameid')
        else:
            body['Type'] = 'Close'
            return handle_photon_event(body)

        return jsonify({'ResultCode': 0, 'Message': 'Success'})
    except Exception as e:
        print(f"[photon/Close error] {e}")
        return jsonify({'ResultCode': 0, 'Message': 'Success'})


@app.route('/webhook', methods=['POST'])
@app.route('/webhook/<path:path>', methods=['POST', 'GET'])
def photon_webhook(path=None):
    """Universal Photon webhook handler for official webhook paths."""
    try:
        data = request.get_json(silent=True) or {}
        mapping = {
            'PathCreate': 'Create', 'Create': 'Create',
            'PathJoin': 'Join', 'Join': 'Join',
            'PathLeave': 'ClientDisconnect', 'Leave': 'ClientDisconnect',
            'PathRaiseEvent': 'Event', 'RaiseEvent': 'Event',
        }
        if path in ('PathClose', 'Close'):
            return photon_close()
        if path in mapping:
            data['Type'] = mapping[path]
            return handle_photon_event(data)
        return jsonify({'ResultCode': 0, 'Message': 'OK'})
    except Exception as e:
        print(f"[webhook error] {e}")
        return jsonify({'ResultCode': 1, 'Message': str(e)}), 500


@app.route('/api/GetRoomState', methods=['POST'])
def get_room_state():
    try:
        body = request.get_json(silent=True) or {}
        gameid = body.get('GameId', '')
        state = db_get_one('room_states', {'gameid': gameid})
        if state:
            return jsonify({'ResultCode': 0,
                            'State': safe_json_loads(state.get('state_json'))})
        return jsonify({'ResultCode': 0, 'State': None})
    except Exception as e:
        print(f"[room state error] {e}")
        return jsonify({'ResultCode': 1, 'Message': 'Error'}), 500


@app.route('/api/SaveRoomState', methods=['POST'])
def save_room_state():
    try:
        body = request.get_json(silent=True) or {}
        gameid = body.get('GameId', '')
        state = body.get('State', {})
        if gameid and state:
            db_upsert('room_states', {
                'gameid': gameid,
                'state_json': json.dumps(state),
                'updatedat': utc_now_iso(),
            }, 'gameid')
        return jsonify({'ResultCode': 0, 'Success': True})
    except Exception as e:
        print(f"[save room state error] {e}")
        return jsonify({'ResultCode': 1, 'Message': 'Error'}), 500

# ============================================================================
# Routes - IAP / misc
# ============================================================================

@app.route('/api/ConsumeOculusIAP', methods=['POST'])
def consume_iap():
    try:
        body = request.get_json(silent=True) or {}
        if not body.get('sku', body.get('Sku', '')):
            return jsonify({'error': True}), 400
        return jsonify({'result': True})
    except Exception as e:
        print(f"[iap error] {e}")
        return jsonify({'error': True}), 500


@app.route('/api/GetMySubscriptionsAndTheirBenefits', methods=['GET', 'POST'])
def get_subscriptions():
    """Fan Club (VIM) is granted to EVERY player on this private server.

    IMPORTANT (pre-rewrite behavior that must stay): returning an empty
    Subscriptions list strips VIM from everyone - the game gates VIM cosmetics
    and rooms on this response. The official captured shape is used, but with
    one active fan_club subscription always present.
    """
    body = request.get_json(silent=True) or {}
    mothershipid = body.get('MothershipId', '')
    if mothershipid:
        update_player_presence(mothershipid)
    now = utc_now_iso()
    month_later = (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
        '%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    return jsonify({
        'Subscriptions': [{
            'SubscriptionId': f"sub_{generate_code(8)}",
            'EarliestStartDate': now,
            'CurrentStartDate': now,
            'MostRecentBillingCycleStartDate': now,
            'MostRecentBillingCycleEndDate': month_later,
            'TotalLifetimeSeconds': 0,
            'IsActive': True,
            'IsCancelling': False,
            'Sku': 'fan_club',
            'PlayerId': mothershipid or 'unknown',
            'TrialType': 'none',
            'ExternalServiceName': 'steam',
            'ExternalSubscriptionId': '',
            'SubscriptionCatalogItemId': '',
        }],
        'PreviouslyGrantedBenefitsBySubscriptionSku': None,
        'NewlyGrantedBenefitsBySubscriptionSku': None,
        'NewlyRevokedBenefitsBySubscriptionSku': None,
        'SharedGroupDataUpdateSucceeded': True,
        'CacheForOtherFunctionsSucceeded': True,
    })


@app.route('/api/AssociatePlayFabAndModIO', methods=['POST'])
def associate_modio():
    """Official captured shape."""
    try:
        body = request.get_json(silent=True) or {}
        mothershipid = body.get('MothershipPlayerId', '')
        modioid = body.get('ModIOId', '')
        return jsonify({'Results': [{
            'MothershipPlayerId': mothershipid,
            'AssociationId': generate_uuid(),
            'ExternalServiceName': 'MODIO',
            'ExternalServiceUserId': str(modioid or ''),
            'ExternalServiceOrgScopedId': str(modioid or ''),
            'ExternalServiceUserName': '',
            'TitleId': CONFIG['mothership_title_id'],
            'EnvId': CONFIG['mothership_env_id'],
            'CreatedTime': utc_now_iso(),
        }]})
    except Exception as e:
        print(f"[modio error] {e}")
        return jsonify({'Results': []}), 500


@app.route('/api/rslog', methods=['POST'])
def rslog():
    try:
        body = request.get_json(silent=True) or {}
        messages = body.get('messages', []) or []
        for msg in messages:
            print(f"[rslib][{msg.get('level', 'info')}][{msg.get('tag', 'RSTag')}] "
                  f"{msg.get('text', '')}")
        return jsonify({'ok': True, 'received': len(messages)})
    except Exception as e:
        print(f"[rslog error] {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/UnlockCompetitiveQueue', methods=['POST'])
def unlock_competitive_queue():
    return jsonify({'success': True, 'unlocked': True})

# ============================================================================
# Error handlers / entry points
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return 'Not found', 404


@app.errorhandler(500)
def internal_error(error):
    print(f"[500] {error}")
    return 'Internal error', 500


# Vercel expects the Flask app object at module scope.
app = app

if __name__ == '__main__':
    print(f"[server] Starting on {CONFIG['host']}:{CONFIG['port']}")
    app.run(host=CONFIG['host'], port=CONFIG['port'])
