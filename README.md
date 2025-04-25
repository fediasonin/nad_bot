# PT NAD Monitoring Bot

Этот бот предназначен для мониторинга состояния сервиса PT NAD и отправки уведомлений о его статусе и проблемах в Telegram.

## 📦 Возможности

- Аутентификация на сервере PT NAD
- Запрос статуса мониторинга
- Обработка списка проблем
- Уведомление в Telegram при:
  - Изменении статуса системы (зеленый, желтый, красный)
  - Появлении или исчезновении проблем
  - Недоступности сервера

## 🛠 Конфигурация

Создайте файл config.py в том же каталоге со следующим содержимым:
### config.py

BASE_URL = "https://your-nad-server.com" 

USERNAME = "your_username"

PASSWORD = "your_password"

TELEGRAM_TOKEN = "your_telegram_bot_token"

CHAT_ID = "your_chat_id"

CHECK_INTERVAL = 60  # интервал проверки в секундах

## 🚀 Запуск

```bash
docker build -t
```

```bash
docker run -d --name my-container-name my-image-name
```
