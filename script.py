import os
import requests
import logging
from threading import Timer
from urllib3.exceptions import InsecureRequestWarning
import config

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s"
)

# ---------------------------------------------------------------------------
# GLOBAL STATE
# ---------------------------------------------------------------------------
last_status = None                 # последний известный статус ("green","yellow","red","unknown")
last_problems_keys = set()         # сигнатуры проблем из прошлого цикла
status_message_id = None           # message_id редактируемого статус-бара
STATUS_ID_FILE = "status_msg_id.txt"

STATUS_EMOJIS = {
    "red": "🔴",
    "yellow": "🟡",
    "green": "🟢",
    "unknown": "❔",
}

# ---------------------------------------------------------------------------
# PT NAD API CLIENT
# ---------------------------------------------------------------------------
class PTNADClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        self.headers = {}

    def authenticate(self) -> bool:
        url = f"{self.base_url}/auth/login"
        try:
            r = self.session.post(url, json={"username": self.username, "password": self.password})
            if r.status_code == 200:
                logging.info("Успешная аутентификация в PT NAD")
                if 'csrftoken' in self.session.cookies:
                    self.headers['X-CSRFToken'] = self.session.cookies['csrftoken']
                return True
            logging.error("Ошибка аутентификации: %s %s", r.status_code, r.text)
            return False
        except Exception as e:
            logging.error("Исключение при аутентификации: %s", e)
            return False

    def get_monitoring_status(self) -> dict:
        url = f"{self.base_url}/monitoring/status"
        try:
            r = self.session.get(url, headers=self.headers)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (401, 403) and self.authenticate():
                r2 = self.session.get(url, headers=self.headers)
                if r2.status_code == 200:
                    return r2.json()
            logging.error("Ошибка получения статуса: %s %s", r.status_code, r.text)
            return {}
        except Exception as e:
            logging.error("Исключение при запросе статуса: %s", e)
            return {}

# ---------------------------------------------------------------------------
# TELEGRAM STATUS BAR
# ---------------------------------------------------------------------------
def upsert_status_bar(html: str):
    """Создать или отредактировать единственное сообщение-статус-бар."""
    global status_message_id
    base = f"https://api.telegram.org/bot{config.TELEGRAM_TOKEN}"
    # восстановить ID после рестарта
    if status_message_id is None and os.path.exists(STATUS_ID_FILE):
        try:
            status_message_id = int(open(STATUS_ID_FILE).read().strip())
        except:
            status_message_id = None
    # редактируем, если можем
    if status_message_id:
        resp = requests.post(f"{base}/editMessageText", data={
            "chat_id": config.CHAT_ID,
            "message_id": status_message_id,
            "text": html,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        })
        if resp.status_code == 200:
            return
        # если удалено вручную
        if resp.status_code == 400 and 'message to edit not found' in resp.text.lower():
            status_message_id = None
    # иначе отправляем новое
    resp = requests.post(f"{base}/sendMessage", data={
        "chat_id": config.CHAT_ID,
        "text": html,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    })
    if resp.status_code == 200:
        status_message_id = resp.json()['result']['message_id']
        with open(STATUS_ID_FILE, 'w') as f:
            f.write(str(status_message_id))

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def signature(problem: dict) -> tuple:
    return (
        problem.get('status', ''),
        problem.get('template', ''),
        str(problem.get('vars', {})),
    )


def render_status(status: str, problems: list) -> str:
    """Генерирует HTML-текст для статуса и списка проблем."""
    lines = [f"<b>Статус PT NAD:</b> {STATUS_EMOJIS.get(status, '❔')}"]
    if problems:
        lines.append("<b>Проблемы:</b>")
        for idx, p in enumerate(problems, 1):
            emoji = STATUS_EMOJIS.get(p['status'], '❔')
            description = p['template'].format(**p['vars'])
            lines.append(f"{idx}.{emoji} {description}")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# MONITOR LOOP
# ---------------------------------------------------------------------------
def monitor():
    global last_status, last_problems_keys
    data = client.get_monitoring_status()
    if data:
        curr = data.get('status', 'unknown')
        probs = data.get('problems', [])
    else:
        curr, probs = 'unknown', []

    keys = {signature(p) for p in probs}

    # выявляем новые критические проблемы
    new_red_problems = [
        p for p in probs
        if signature(p) not in last_problems_keys
        and p.get('status') == 'red'
        and 'свободн' not in p.get('template', '').lower()
    ]

    for p in new_red_problems:
        emoji = STATUS_EMOJIS.get(p['status'], '❔')
        description = p['template'].format(**p.get('vars', {}))
        message = f"{emoji} <b>Новая критичная проблема:</b>\n{description}"
        requests.post(
            f"https://api.telegram.org/bot{config.TELEGRAM_TOKEN}/sendMessage",
            data={
                "chat_id": config.CHAT_ID,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
        )

    # обновляем только при изменении статуса или проблем
    if curr != last_status or keys != last_problems_keys:
        html = render_status(curr, probs)
        upsert_status_bar(html)
        last_status, last_problems_keys = curr, keys

    Timer(config.CHECK_INTERVAL, monitor).start()

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    client = PTNADClient(config.BASE_URL, config.USERNAME, config.PASSWORD)
    if client.authenticate():
        monitor()
    else:
        logging.error('Не удалось пройти аутентификацию, выходим')
