# PhishGuard AI

**Система автоматического обнаружения фишинговых веб-сайтов с использованием нейронных сетей**

Современный веб-интерфейс в стиле cybersecurity dashboard с Flask backend и подготовкой под TensorFlow/Keras модель.

## Возможности

- Анализ URL в реальном времени через REST API
- Извлечение 11 признаков для ML-классификации
- Mock-предсказание (готово к замене на обученную нейросеть)
- Адаптивный dark UI с glassmorphism и неоновыми акцентами

## Структура проекта

```
Fishguard/
├── app.py                 # Flask backend
├── requirements.txt
├── templates/
│   └── index.html         # Главная страница
├── static/
│   ├── style.css          # Стили cybersecurity dashboard
│   └── script.js          # Frontend логика
├── models/                # Сюда поместить .h5 модель Keras
└── README.md
```

## Установка и запуск

```bash
# Создать виртуальное окружение (рекомендуется)
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS

pip install -r requirements.txt
python app.py
```

Откройте в браузере: **http://127.0.0.1:5000**

## API

### `POST /predict`

**Request:**
```json
{
  "url": "https://example-suspicious-login.com/verify"
}
```

**Response:**
```json
{
  "status": "Phishing",
  "risk": 87,
  "features": {
    "url_length": 42,
    "dot_count": 2,
    "has_https": 1,
    ...
  },
  "explanation": ["Обнаружено подозрительное ключевое слово..."],
  "feature_vector": [42.0, 2.0, ...]
}
```

## Подключение TensorFlow модели

1. Обучите модель и сохраните в `models/phishguard_model.h5`
2. Раскомментируйте `tensorflow` в `requirements.txt`
3. В `app.py` замените `predict_phishing()`:

```python
import numpy as np
import tensorflow as tf

model = tf.keras.models.load_model("models/phishguard_model.h5")

def predict_phishing(features):
    vector = np.array([features_to_vector(features)])
    prob = float(model.predict(vector, verbose=0)[0][0])
    risk = int(prob * 100)
    status = "Phishing" if risk >= 70 else "Suspicious" if risk >= 40 else "Safe"
    ...
```

Порядок признаков в векторе задан в `FEATURE_VECTOR_ORDER`.

## Извлекаемые признаки

| Признак | Описание |
|---------|----------|
| `url_length` | Длина URL |
| `dot_count` | Количество точек |
| `digit_count` | Количество цифр |
| `special_char_count` | Спецсимволы |
| `has_https` | Использование HTTPS |
| `has_ip_address` | IP вместо домена |
| `at_symbol` | Символ @ |
| `dash_count` | Количество дефисов |
| `suspicious_word_count` | Подозрительные слова |
| `subdomain_count` | Количество поддоменов |
| `is_shortened` | Сервис сокращения ссылок |

## Технологии

- **Frontend:** HTML5, CSS3, JavaScript (Fetch API)
- **Backend:** Python Flask
- **ML (planned):** TensorFlow / Keras

## Лицензия

Дипломный проект © 2026
