import os
from flask import Flask, render_template, request, jsonify
import random
import time
import json
from base64 import b64encode
import threading
import re
import tls_client
import logging
import uuid
import string
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', force=True)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')

API_VERSION = "v9"
BASE_URL = f"https://discord.com/api/{API_VERSION}"

ALLOW_DANGEROUS_ACTIONS = False

class Proxy:
    def __init__(self, proxy_string, proxy_type="http"):
        self.proxy_string = proxy_string
        self.proxy_type = proxy_type.lower()
        self.ip = None
        self.port = None
        self.username = None
        self.password = None
        self.parse_proxy()

    def parse_proxy(self):
        patterns = [
            r'^(?P<ip>[^:]+):(?P<port>\d+)(?::(?P<user>[^:]+):(?P<pass>[^:]+))?$',
            r'^(?P<user>[^:]+):(?P<pass>[^@]+)@(?P<ip>[^:]+):(?P<port>\d+)$',
        ]
        for pattern in patterns:
            match = re.match(pattern, self.proxy_string)
            if match:
                gd = match.groupdict()
                self.ip = gd.get('ip')
                self.port = gd.get('port')
                self.username = gd.get('user')
                self.password = gd.get('pass')
                return
        raise ValueError(f"Invalid proxy format: {self.proxy_string}")

    def to_dict(self):
        if self.username and self.password:
            return {f"{self.proxy_type}": f"{self.username}:{self.password}@{self.ip}:{self.port}"}
        return {f"{self.proxy_type}": f"{self.ip}:{self.port}"}

class State:
    def __init__(self):
        self.tokens = []
        self.valid_tokens = []
        self.proxies = []
        self.joiner_running = False
        self.leaver_running = False
        self.spammer_running = False
        self.checker_running = False
        self.joiner_results = []
        self.leaver_results = []
        self.spammer_results = []
        self.checker_results = []
        self.token_info = []
        self.fun_results = []

state = State()
EMOJIS = ['😀', '😂', '😍', '😎', '🤓', '👍', '👀', '🚀', '🔥', '💀']

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]

class Raider:
    def __init__(self):
        self.cookies = "locale=en-US"

    def super_properties(self):
        payload = {
            "os": random.choice(["Windows", "Mac OS X", "Linux", "iOS"]),
            "browser": random.choice(["Chrome", "Firefox", "Safari", "Discord Client"]),
            "release_channel": "stable",
            "client_version": f"1.0.{random.randint(9000, 9999)}",
            "os_version": f"{random.randint(10, 14)}.{random.randint(0, 5)}.{random.randint(0, 9999)}",
            "system_locale": "en",
            "browser_user_agent": random.choice(USER_AGENTS),
            "browser_version": f"{random.randint(90, 120)}.{random.randint(0, 5)}.{random.randint(0, 999)}",
            "client_build_number": random.randint(350000, 400000),
            "native_build_number": random.randint(50000, 60000),
            "client_event_source": None,
        }
        return b64encode(json.dumps(payload).encode()).decode()

    def headers(self, token):
        return {
            "authority": "discord.com",
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "authorization": token,
            "cookie": self.cookies,
            "content-type": "application/json",
            "user-agent": random.choice(USER_AGENTS),
            "x-discord-locale": "en-US",
            "x-debug-options": "bugReporterEnabled",
            "x-super-properties": self.super_properties(),
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }

    def safe_request(self, method, url, session, headers, max_retries=4, **kwargs):
        attempt = 0
        backoff = 1.0
        while attempt < max_retries:
            try:
                response = session.request(method, url, headers=headers, **kwargs)
                status = getattr(response, "status_code", None)

                if status == 429:
                    retry_after = 5.0
                    try:
                        j = response.json()
                        retry_after = float(j.get("retry_after", j.get("retry_after_ms", 5)) )
                    except Exception:
                        pass
                    wait = retry_after + random.uniform(0.2, 1.0)
                    time.sleep(wait)
                    attempt += 1
                    backoff *= 2
                    continue

                return response
            except Exception:
                time.sleep(backoff + random.uniform(0, 0.5))
                backoff *= 2
                attempt += 1
        return None

    def token_checker(self, token, proxy=None):
        session = tls_client.Session(client_identifier="chrome_128", random_tls_extension_order=True)
        session.timeout_seconds = 10
        if proxy:
            session.proxies = proxy.to_dict()
        elif state.proxies:
            p = random.choice(state.proxies)
            session.proxies = p.to_dict()

        headers = self.headers(token)
        resp = self.safe_request("GET", f"{BASE_URL}/users/@me", session, headers, max_retries=3)
        if resp is None:
            state.checker_results.append({'token': token[:10] + '...', 'fullToken': token, 'status': 'error', 'message': 'Request failed', 'nitro': False})
            return

        status = getattr(resp, "status_code", None)
        try:
            j = resp.json()
        except Exception:
            j = {}

        if status == 200:
            verified = j.get('verified', False)
            nitro = bool(j.get('premium_type'))
            uid = j.get('id')
            created_at = 'N/A'
            try:
                if uid:
                    created_at = datetime.fromtimestamp(((int(uid) >> 22) + 1420070400000) / 1000).strftime('%Y-%m-%d')
            except Exception:
                created_at = 'N/A'

            token_info = {
                'token': token[:10] + '...',
                'fullToken': token,
                'status': 'success',
                'message': f"Valid{' (Nitro)' if nitro else ''}{' (Unverified)' if not verified else ''}",
                'nitro': nitro,
                'email': j.get('email', 'N/A'),
                'created_at': created_at,
                'username': j.get('username', 'N/A'),
                'user_id': uid or 'N/A',
                'avatar': f"https://cdn.discordapp.com/avatars/{j.get('id')}/{j.get('avatar')}.png" if j.get('avatar') and j.get('id') else 'N/A',
                'verified': verified
            }
            state.checker_results.append(token_info)
            state.token_info.append(token_info)
            logger.info(f"[checker] Token valid: {token[:10]}... user={token_info['username']}")
        elif status == 403:
            state.checker_results.append({'token': token[:10] + '...', 'fullToken': token, 'status': 'error', 'message': "Locked/Forbidden", 'nitro': False})
        elif status == 401:
            state.checker_results.append({'token': token[:10] + '...', 'fullToken': token, 'status': 'error', 'message': "Unauthorized/Invalid token", 'nitro': False})
        else:
            err = j.get('message', f'HTTP {status}')
            state.checker_results.append({'token': token[:10] + '...', 'fullToken': token, 'status': 'error', 'message': err, 'nitro': False})

    def joiner(self, token, invite, proxy=None, max_retries=3):
        logger.info(f"[joiner] Requested join by {token[:10]}... to invite {invite} proxy={proxy.proxy_string if proxy else 'None'}")
        if not ALLOW_DANGEROUS_ACTIONS:
            state.joiner_results.append({'token': token[:10] + '...', 'status': 'error', 'message': 'Join disabled in safe mode'})
            return
        state.joiner_results.append({'token': token[:10] + '...', 'status': 'success', 'message': 'Join simulated'})

    def leaver(self, token, guild, proxy=None):
        logger.info(f"[leaver] Requested leave by {token[:10]}... from guild {guild} proxy={proxy.proxy_string if proxy else 'None'}")
        if not ALLOW_DANGEROUS_ACTIONS:
            state.leaver_results.append({'token': token[:10] + '...', 'status': 'error', 'message': 'Leave disabled in safe mode'})
            return
        state.leaver_results.append({'token': token[:10] + '...', 'status': 'success', 'message': 'Leave simulated'})

    def spammer(self, token, channel, message, random_emojis=False, random_strings=False, add_everyone=False, proxy=None):
        logger.info(f"[spammer] Requested spam by {token[:10]}... to channel {channel} proxy={proxy.proxy_string if proxy else 'None'}")
        if not ALLOW_DANGEROUS_ACTIONS:
            state.spammer_results.append({'token': token[:10] + '...', 'status': 'error', 'message': 'Spam disabled in safe mode'})
            return
        state.spammer_results.append({'token': token[:10] + '...', 'status': 'success', 'message': 'Spam simulated'})

    def ghost_pinger(self, token, channel_id, mention, proxy=None):
        logger.info(f"[ghost_pinger] Requested by {token[:10]}... channel={channel_id} mention={mention}")
        if not ALLOW_DANGEROUS_ACTIONS:
            state.fun_results.append({'token': token[:10] + '...', 'status': 'error', 'message': 'Ghost pinger disabled in safe mode'})
            return
        state.fun_results.append({'token': token[:10] + '...', 'status': 'success', 'message': 'Ghost pinger simulated'})

    def button_spammer(self, token, message_link, click_count, fetch_channel=False, proxy=None):
        logger.info(f"[button_spammer] Requested by {token[:10]}... link={message_link} clicks={click_count}")
        if not ALLOW_DANGEROUS_ACTIONS:
            state.fun_results.append({'token': token[:10] + '...', 'status': 'error', 'message': 'Button spammer disabled in safe mode'})
            return
        state.fun_results.append({'token': token[:10] + '...', 'status': 'success', 'message': 'Button spammer simulated'})

    def emoji_reaction(self, token, channel_id, message_id, emojis, proxy=None):
        logger.info(f"[emoji_reaction] Requested by {token[:10]}... message={message_id} emojis={emojis}")
        if not ALLOW_DANGEROUS_ACTIONS:
            state.fun_results.append({'token': token[:10] + '...', 'status': 'error', 'message': 'Emoji reaction disabled in safe mode'})
            return
        state.fun_results.append({'token': token[:10] + '...', 'status': 'success', 'message': 'Emoji reaction simulated'})

raider = Raider()

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception:
        return "Discord management API (safe-mode).", 200

@app.route('/join', methods=['POST'])
def join():
    data = request.json
    state.tokens = data.get('tokens', [])
    invite = data.get('inviteCode', '')
    delay = float(data.get('delay', 1))
    max_joins = int(data.get('maxJoins', len(state.valid_tokens) if state.valid_tokens else len(state.tokens)))
    max_threads = int(data.get('maxThreads', 5))

    if not state.tokens or not invite:
        return jsonify({'message': 'Tokens or invite code required', 'results': []}), 400

    state.joiner_results = []

    if not state.valid_tokens:
        state.checker_running = True
        state.checker_results = []
        state.token_info = []

        def run_auto_checker():
            threads = []
            for token in state.tokens:
                thread = threading.Thread(target=raider.token_checker, args=(token,))
                threads.append(thread)
                thread.start()
                time.sleep(0.1)
            for thread in threads:
                thread.join()
            state.valid_tokens = [r['fullToken'] for r in state.checker_results if r.get('status') == 'success']
            state.checker_running = False
            if not state.valid_tokens:
                state.joiner_results.append({'token': 'N/A', 'status': 'error', 'message': 'No valid tokens found'})
                return
            start_joiner(invite, delay, max_joins, max_threads)

        threading.Thread(target=run_auto_checker, daemon=True).start()
        return jsonify({'message': 'Checking tokens before joining', 'results': []})

    return start_joiner(invite, delay, max_joins, max_threads)

def start_joiner(invite, delay, max_joins, max_threads):
    invite_code = re.sub(r"(https?://)?(www\.)?(discord\.(gg|com)/(invite/)?|\.gg/)", "", invite)
    state.joiner_running = True
    state.joiner_results = []

    try:
        sample_token = state.valid_tokens[0]
        session = tls_client.Session(client_identifier="chrome_128", random_tls_extension_order=True)
        response = session.get(f"{BASE_URL}/invites/{invite_code}", headers=raider.headers(sample_token))
        if response.status_code != 200:
            error_msg = response.json().get('message', f'HTTP {response.status_code}')
            state.joiner_results.append({'token': 'N/A', 'status': 'error', 'message': f"Invalid invite: {error_msg}"})
            state.joiner_running = False
            return jsonify({'message': f"Invalid invite: {error_msg}", 'results': state.joiner_results}), 400
    except Exception as e:
        state.joiner_results.append({'token': 'N/A', 'status': 'error', 'message': f"Error validating invite: {str(e)}"})
        state.joiner_running = False
        return jsonify({'message': f"Error validating invite: {str(e)}", 'results': state.joiner_results}), 400

    def run_joiner():
        join_tokens = state.valid_tokens[:max_joins]
        active_threads = []
        used_proxies = set()

        for token in join_tokens:
            if not state.joiner_running:
                break

            available_proxies = [p for p in state.proxies if p.proxy_string not in used_proxies] if state.proxies else []
            proxy = random.choice(available_proxies) if available_proxies else None
            if proxy:
                used_proxies.add(proxy.proxy_string)

            while len(active_threads) >= max_threads:
                active_threads = [t for t in active_threads if t.is_alive()]
                time.sleep(0.1)

            thread = threading.Thread(target=raider.joiner, args=(token, invite_code, proxy))
            thread.daemon = True
            active_threads.append(thread)
            thread.start()

            time.sleep(random.uniform(delay, delay + 3))

        for thread in active_threads:
            thread.join()

        state.joiner_running = False

    threading.Thread(target=run_joiner, daemon=True).start()
    return jsonify({'message': 'Joiner started (safe-mode)', 'results': []})

@app.route('/leave', methods=['POST'])
def leave():
    data = request.json
    state.tokens = data.get('tokens', [])
    guild_id = data.get('serverId', '')
    delay = float(data.get('delay', 1))
    max_threads = int(data.get('maxThreads', 5))

    if not state.tokens or not guild_id:
        return jsonify({'message': 'Tokens or guild ID required', 'results': []}), 400
    if not state.valid_tokens:
        return jsonify({'message': 'No valid tokens found. Run Checker first.', 'results': []}), 400

    state.leaver_results = []
    state.leaver_running = True

    def run_leaver():
        leave_tokens = state.valid_tokens[:]
        active_threads = []

        for token in leave_tokens:
            if not state.leaver_running:
                break

            while len(active_threads) >= max_threads:
                active_threads = [t for t in active_threads if t.is_alive()]
                time.sleep(0.1)

            proxy = random.choice(state.proxies) if state.proxies else None
            thread = threading.Thread(target=raider.leaver, args=(token, guild_id, proxy))
            thread.daemon = True
            active_threads.append(thread)
            thread.start()

            time.sleep(delay)

        for thread in active_threads:
            thread.join()

        state.leaver_running = False

    threading.Thread(target=run_leaver, daemon=True).start()
    return jsonify({'message': 'Leaver started (safe-mode)', 'results': []})

@app.route('/spam', methods=['POST'])
def spam():
    data = request.json
    state.tokens = data.get('tokens', [])
    channel_id = data.get('channelId', '')
    message = data.get('message', '')
    delay = float(data.get('delay', 1))
    disable_delay = data.get('disableDelay', False)
    count = int(data.get('spamCount', 10))
    max_threads = int(data.get('maxThreads', 5))
    random_emojis = data.get('randomEmojis', False)
    random_strings = data.get('randomStrings', False)
    add_everyone = data.get('addEveryone', False)

    if not state.tokens or not channel_id or not message:
        return jsonify({'message': 'Tokens, channel ID, or message required', 'results': []}), 400
    if not state.valid_tokens:
        return jsonify({'message': 'No valid tokens found. Run Checker first.', 'results': []}), 400

    state.spammer_results = []
    state.spammer_running = True

    def run_spammer():
        spam_tokens = state.valid_tokens[:]
        for i in range(count):
            if not state.spammer_running:
                break

            active_threads = []
            for token in spam_tokens:
                proxy = random.choice(state.proxies) if state.proxies else None
                thread = threading.Thread(target=raider.spammer, args=(token, channel_id, message, random_emojis, random_strings, add_everyone, proxy))
                thread.daemon = True
                active_threads.append(thread)
                thread.start()

                while len(active_threads) >= max_threads:
                    active_threads = [t for t in active_threads if t.is_alive()]
                    time.sleep(0.1)

                if not disable_delay:
                    time.sleep(delay / len(spam_tokens))

            for thread in active_threads:
                thread.join()

            if not disable_delay:
                time.sleep(delay)

        state.spammer_running = False

    threading.Thread(target=run_spammer, daemon=True).start()
    return jsonify({'message': 'Spammer started (safe-mode)', 'results': []})

@app.route('/check', methods=['POST'])
def check():
    data = request.json
    state.tokens = data.get('tokens', [])
    max_threads = int(data.get('maxThreads', 5))

    if not state.tokens:
        return jsonify({'message': 'Tokens required', 'results': []}), 400

    state.checker_results = []
    state.valid_tokens = []
    state.token_info = []
    state.checker_running = True

    def run_checker():
        active_threads = []
        for token in state.tokens:
            if not state.checker_running:
                break

            while len(active_threads) >= max_threads:
                active_threads = [t for t in active_threads if t.is_alive()]
                time.sleep(0.1)

            proxy = random.choice(state.proxies) if state.proxies else None
            thread = threading.Thread(target=raider.token_checker, args=(token, proxy))
            thread.daemon = True
            active_threads.append(thread)
            thread.start()

            time.sleep(0.1)
            
        for thread in active_threads:
            thread.join()

        state.valid_tokens = [r['fullToken'] for r in state.checker_results if r['status'] == 'success']
        state.checker_running = False

    threading.Thread(target=run_checker, daemon=True).start()
    return jsonify({'message': 'Checker started', 'results': []})

@app.route('/fun_ghost_pinger', methods=['POST'])
def fun_ghost_pinger():
    data = request.json
    state.tokens = data.get('tokens', [])
    channel_id = data.get('channelId', '')
    mention = data.get('mention', '')
    max_threads = int(data.get('maxThreads', 5))

    if not state.tokens or not channel_id or not mention:
        return jsonify({'message': 'Tokens, channel ID, or mention required', 'results': []}), 400
    if not state.valid_tokens:
        return jsonify({'message': 'No valid tokens found. Run Checker first.', 'results': []}), 400

    state.fun_results = []

    def run_ghost_pinger():
        active_threads = []
        for token in state.valid_tokens:
            while len(active_threads) >= max_threads:
                active_threads = [t for t in active_threads if t.is_alive()]
                time.sleep(0.1)

            proxy = random.choice(state.proxies) if state.proxies else None
            thread = threading.Thread(target=raider.ghost_pinger, args=(token, channel_id, mention, proxy))
            thread.daemon = True
            active_threads.append(thread)
            thread.start()

            time.sleep(0.1)

        for thread in active_threads:
            thread.join()

    threading.Thread(target=run_ghost_pinger, daemon=True).start()
    return jsonify({'message': 'Ghost Pinger started (safe-mode)', 'results': []})

@app.route('/fun_button_spammer', methods=['POST'])
def fun_button_spammer():
    data = request.json
    state.tokens = data.get('tokens', [])
    message_link = data.get('messageLink', '')
    click_count = int(data.get('clickCount', 5))
    fetch_channel = data.get('fetchChannel', False)
    max_threads = int(data.get('maxThreads', 5))

    if not state.tokens or not message_link:
        return jsonify({'message': 'Tokens or message link required', 'results': []}), 400
    if not state.valid_tokens:
        return jsonify({'message': 'No valid tokens found. Run Checker first.', 'results': []}), 400

    state.fun_results = []

    def run_button_spammer():
        active_threads = []
        for token in state.valid_tokens:
            while len(active_threads) >= max_threads:
                active_threads = [t for t in active_threads if t.is_alive()]
                time.sleep(0.1)

            proxy = random.choice(state.proxies) if state.proxies else None
            thread = threading.Thread(target=raider.button_spammer, args=(token, message_link, click_count, fetch_channel, proxy))
            thread.daemon = True
            active_threads.append(thread)
            thread.start()

            time.sleep(0.1)

        for thread in active_threads:
            thread.join()

    threading.Thread(target=run_button_spammer, daemon=True).start()
    return jsonify({'message': 'Button Spammer started (safe-mode)', 'results': []})

@app.route('/fun_emoji_reaction', methods=['POST'])
def fun_emoji_reaction():
    data = request.json
    state.tokens = data.get('tokens', [])
    channel_id = data.get('channelId', '')
    message_id = data.get('messageId', '')
    emojis = data.get('emojis', [])
    max_threads = int(data.get('maxThreads', 5))

    if not state.tokens or not channel_id or not message_id or not emojis:
        return jsonify({'message': 'Tokens, channel ID, message ID, or emojis required', 'results': []}), 400
    if not state.valid_tokens:
        return jsonify({'message': 'No valid tokens found. Run Checker first.', 'results': []}), 400

    state.fun_results = []

    def run_emoji_reaction():
        active_threads = []
        for token in state.valid_tokens:
            while len(active_threads) >= max_threads:
                active_threads = [t for t in active_threads if t.is_alive()]
                time.sleep(0.1)

            proxy = random.choice(state.proxies) if state.proxies else None
            thread = threading.Thread(target=raider.emoji_reaction, args=(token, channel_id, message_id, emojis, proxy))
            thread.daemon = True
            active_threads.append(thread)
            thread.start()

            time.sleep(0.1)

        for thread in active_threads:
            thread.join()

    threading.Thread(target=run_emoji_reaction, daemon=True).start()
    return jsonify({'message': 'Emoji Reaction started (safe-mode)', 'results': []})

@app.route('/stop_joiner', methods=['POST'])
def stop_joiner():
    state.joiner_running = False
    return jsonify({'message': 'Joiner stopped'})

@app.route('/stop_leaver', methods=['POST'])
def stop_leaver():
    state.leaver_running = False
    return jsonify({'message': 'Leaver stopped'})

@app.route('/stop_spammer', methods=['POST'])
def stop_spammer():
    state.spammer_running = False
    return jsonify({'message': 'Spammer stopped'})

@app.route('/check_status', methods=['GET'])
def check_status():
    return jsonify({
        'joiner_running': state.joiner_running,
        'joiner_results': state.joiner_results,
        'leaver_running': state.leaver_running,
        'leaver_results': state.leaver_results,
        'spammer_running': state.spammer_running,
        'spammer_results': state.spammer_results,
        'checker_running': state.checker_running,
        'checker_results': state.checker_results,
        'valid_tokens': len(state.valid_tokens),
        'token_info': state.token_info,
        'fun_results': state.fun_results
    })

@app.route('/proxies', methods=['POST'])
def save_proxies():
    data = request.json
    proxies_data = data.get('proxies', [])
    state.proxies = []
    for proxy in proxies_data:
        try:
            proxy_string = proxy.get('proxy_string', '')
            proxy_type = proxy.get('proxy_type', 'http')
            if proxy_type not in ['http', 'https', 'socks4', 'socks5']:
                proxy_type = 'http'
            state.proxies.append(Proxy(proxy_string, proxy_type))
        except ValueError:
            pass
    return jsonify({'message': f"Saved {len(state.proxies)} proxies"})

@app.route('/export_tokens', methods=['GET'])
def export_tokens():
    return jsonify({'tokens': state.token_info})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
