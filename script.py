import requests
import logging
from threading import Timer
from urllib3.exceptions import InsecureRequestWarning
import config

logging.basicConfig(level=logging.INFO)

server_down_notified = False
last_status = None
last_problems_keys = set()

STATUS_EMOJIS = {
    "red": "🔴",
    "yellow": "🟡",
    "green": "🟢",
    "unknown": "❔"
}



class PTNADClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password




        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        self.headers = {}
        self.csrf_token = None

    def authenticate(self):
        auth_url = f"{self.base_url}/auth/login"
        try:
            response = self.session.post(auth_url, json={
                "username": self.username,
                "password": self.password
            })
            if response.status_code == 200:
                logging.info("Успешная аутентификация.")
                if 'csrftoken' in self.session.cookies:
                    self.csrf_token = self.session.cookies['csrftoken']
                    self.headers["X-CSRFToken"] = self.csrf_token
                    logging.info("CSRF-токен получен и добавлен в заголовки.")
                else:
                    logging.warning("CSRF-токен не найден. Возможно, не требуется.")
                return True
            else:
                logging.error(f"Ошибка аутентификации: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logging.error(f"Ошибка при аутентификации: {e}")
            return False

    def get_monitoring_status(self) -> dict:
        url = f"{self.base_url}/monitoring/status"
        try:
            response = self.session.get(url, headers=self.headers)

            if response.status_code == 200:
                return response.json()

            elif response.status_code in (401, 403):
                logging.warning(f"Получен код {response.status_code}, пробуем заново аутентифицироваться...")

                if self.authenticate():
                    response2 = self.session.get(url, headers=self.headers)
                    if response2.status_code == 200:
                        return response2.json()
                    else:
                        logging.error(
                            f"Ошибка после повторной аутентификации: {response2.status_code} - {response2.text}")
                        return {}
                else:
                    logging.error("Не удалось переавторизоваться после 401/403.")
                    return {}

            else:
                logging.error(f"Ошибка при запросе {url}: {response.status_code} - {response.text}")
                return {}

        except Exception as e:
            logging.error(f"Исключение при запросе к {url}: {e}")
            return {}


def problem_signature(problem: dict) -> tuple:
    return (
        problem.get("status", ""),
        problem.get("template", ""),
        str(problem.get("vars", {}))
    )


def send_telegram_message(message: str):
    """
    Отправка сообщения в Телеграм.
    """
    url = f"https://api.telegram.org/bot{config.TELEGRAM_TOKEN}/sendMessage"
    data = {"chat_id": config.CHAT_ID, "text": message}
    try:
        logging.info(f"Отправка сообщения в Telegram: {message}")
        response = requests.post(url, data=data)
        if response.status_code == 200:
            logging.info("Сообщение успешно отправлено в Telegram")
        else:
            logging.error(f"Ошибка при отправке сообщения в Telegram. Код: {response.status_code}, Ответ: {response.text}")
    except Exception as e:
        logging.error(f"Не удалось отправить сообщение в Телеграм: {e}")




def monitor():
    global last_problems_keys, last_status, server_down_notified

    logging.info("Начало проверки статуса мониторинга")
    monitoring_data = nad_client.get_monitoring_status()
    logging.info(f"Получены данные мониторинга: {monitoring_data}")

    if not monitoring_data:
        if not server_down_notified:
            logging.warning("Сервер недоступен, отправка уведомления")
            send_telegram_message("❗ Сервер PT NAD недоступен.")
            server_down_notified = True
        last_problems_keys = set()
        last_status = None
    else:
        if server_down_notified:
            logging.info("Сервер снова доступен, отправка уведомления")
            send_telegram_message("✅ Сервер PT NAD снова доступен.")
            server_down_notified = False

        current_status = monitoring_data.get("status", "unknown")
        problems = monitoring_data.get("problems", [])
        new_problems_keys = {problem_signature(p) for p in problems}
        
        logging.info(f"Текущий статус: {current_status}, Предыдущий статус: {last_status}")
        logging.info(f"Количество проблем: {len(problems)}")

        if current_status != last_status or new_problems_keys != last_problems_keys:
            status_emoji = STATUS_EMOJIS.get(current_status, "❔")
            logging.info(f"Обнаружено изменение статуса или проблем, отправка уведомления")

            if current_status in ("red", "yellow"):
                message_lines = [f"Текущий статус PT NAD: {status_emoji}"]
                if problems:
                    message_lines.append("Список проблем:")
                    for idx, problem in enumerate(problems, start=1):
                        p_status = problem.get("status", "")
                        template = problem.get("template", "")
                        problem_emoji = STATUS_EMOJIS.get(p_status, "❔")
                        message_lines.append(f" {idx}. Уровень: {problem_emoji}, Описание: {template}")
                else:
                    message_lines.append("Статус не GREEN, но список проблем пуст.")
                send_telegram_message("\n".join(message_lines))

            last_status = current_status
            last_problems_keys = new_problems_keys
        else:
            logging.info("Изменений в статусе или проблемах не обнаружено")

    logging.info(f"Следующая проверка через {config.CHECK_INTERVAL} секунд")
    Timer(config.CHECK_INTERVAL, monitor).start()

def main():
    global nad_client
    nad_client = PTNADClient(config.BASE_URL, config.USERNAME, config.PASSWORD)
    nad_client.authenticate()
    monitor()


if __name__ == "__main__":
    main()
