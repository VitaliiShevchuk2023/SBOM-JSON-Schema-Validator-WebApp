# 🎈 Blank app template

A simple Streamlit app template for you to modify!

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://sbom-json-schema-validator-webapp.streamlit.app/)

Я створив повнофункціональний SBOM Validator на Streamlit з усіма функціями, які ви описали. Ось ключові особливості реалізації:

## 🚀 Основні можливості

### 1. **Центральний універсальний валідатор**
- ✅ Auto-detection формату, версії та типу даних
- ✅ Підтримка SPDX 2.3/3.0 (JSON) + CycloneDX 1.3-1.6 (JSON/XML)
- ✅ Трирівнева валідація (Basic/Standard/Comprehensive)

### 2. **Багатосторінковий інтерфейс**
- 🏠 **Головна** - огляд можливостей
- ✅ **Універсальний валідатор** - основна валідація
- 📊 **Пакетна валідація** - до 10 файлів одночасно
- 📋 **Браузер схем** - інтерактивний перегляд
- 📝 **Приклади та тести** - готові тестові файли
- 🔍 **Розширений аналіз** - глибокий аналіз
- 📈 **Матриця підтримки** - повна таблиця функцій

### 3. **Розширена аналітика**
```python
🧠 Семантичний аналіз:
├── Component Analysis (типи, кількість, версії)
├── Dependency Analysis (граф залежностей, глибина)  
├── License Analysis (розподіл, ризики)
├── Security Analysis (вразливості по рівням)
└── Quality Score (0-100 балів)
```

### 4. **Quality Scoring Algorithm**
```
Quality Score = 
  20% Structure (bomFormat, specVersion)
+ 20% Metadata (timestamp, authors, tools)  
+ 40% Components (versions, licenses)
+ 20% Security (vulnerabilities info)
```

### 5. **Професійні функції**
- 📤 JSON експорт результатів
- 🔄 Batch processing
- ⚡ Performance metrics
- 🎯 Контекстні помилки з рекомендаціями
- 📊 Інтерактивні візуалізації (Plotly)

## 🎨 UI/UX покращення

- **Градієнтний дизайн** з професійними кольоровими схемами
- **Інтерактивні метрики** та gauge діаграми
- **Expandable секції** для деталей
- **Responsive layout** для різних екранів
- **Progress indicators** для довгих операцій

## 🔧 Технічна архітектура

```python
class EnhancedSBOMValidator:
    ├── Auto-detection engine
    ├── Multi-schema validation
    ├── Business rules engine  
    ├── Semantic analysis engine
    ├── Quality scoring algorithm
    └── Batch processing system
```

## 🚀 Запуск

```bash
# Встановлення залежностей
pip install streamlit jsonschema xmlschema pandas plotly networkx

# Запуск програми  
streamlit run enhanced_sbom_validator.py

# Доступ до інтерфейсу
http://localhost:8501
```

## 💎 Унікальні особливості

1. **Smart Auto-Detection** - аналізує JSON/XML структуру та signature поля
2. **Advanced Dependency Analysis** - розрахунок глибини та візуалізація графа
3. **License Risk Classification** - класифікація ліцензій за рівнями ризику
4. **Comprehensive Security Analysis** - аналіз вразливостей з категоризацією
5. **Contextual Error Reporting** - детальні помилки з рекомендаціями

Проект готовий до використання та може бути легко розширений додатковими функціями!


--------------------------------------------------------------------------------

# 🛡️ Enhanced SBOM Validator - Інструкції по встановленню

## 📋 Системні вимоги

- Python 3.8 або вище
- pip (менеджер пакетів Python)

## 🚀 Швидкий старт

### 1. Мінімальне встановлення (тільки базові функції)

```bash
pip install streamlit pandas matplotlib seaborn
```

### 2. Повне встановлення (всі функції)

```bash
pip install -r requirements.txt
```

Або окремо:

```bash
pip install streamlit pandas matplotlib seaborn plotly jsonschema xmlschema networkx
```

### 3. Запуск додатку

```bash
streamlit run enhanced_sbom_validator.py
```

Додаток буде доступний за адресою: `http://localhost:8501`

## 🔧 Вирішення проблем з залежностями

### Якщо не встановлюється plotly:
```bash
pip install --upgrade pip
pip install plotly
```

### Якщо не встановлюється jsonschema:
```bash
pip install jsonschema
```

### Якщо не встановлюється xmlschema:
```bash
pip install xmlschema
```

### Якщо не встановлюється networkx:
```bash
pip install networkx
```

## 📦 Функціональність залежно від встановлених пакетів

| Пакет | Функціональність | Альтернатива |
|-------|------------------|--------------|
| `streamlit` | ✅ **Обов'язково** - основний інтерфейс | Немає |
| `pandas` | ✅ **Обов'язково** - обробка даних | Немає |
| `matplotlib` | ✅ **Обов'язково** - базові графіки | Немає |
| `plotly` | 🎨 Інтерактивні графіки | Matplotlib графіки |
| `jsonschema` | 🔍 Повна валідація схем | Спрощена валідація |
| `xmlschema` | 📄 XML валідація | Базова XML перевірка |
| `networkx` | 🕸️ Аналіз графів залежностей | Спрощений аналіз |
| `seaborn` | 🎨 Покращені візуалізації | Базовий matplotlib |

## 🌟 Режими роботи

### Базовий режим (мінімальні залежності)
- ✅ Основна валідація SBOM
- ✅ Auto-detection форматів
- ✅ Базові графіки (matplotlib)
- ✅ Експорт результатів
- ⚠️ Спрощена валідація схем
- ⚠️ Базовий аналіз залежностей

### Повний режим (всі залежності)
- ✅ Всі функції базового режиму
- ✅ Інтерактивні графіки (Plotly)
- ✅ Повна валідація схем (jsonschema)
- ✅ XML валідація (xmlschema)
- ✅ Розширений аналіз залежностей (networkx)
- ✅ Професійні візуалізації

## 🐳 Docker встановлення (опціонально)

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY enhanced_sbom_validator.py .

EXPOSE 8501

CMD ["streamlit", "run", "enhanced_sbom_validator.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

Збірка та запуск:
```bash
docker build -t sbom-validator .
docker run -p 8501:8501 sbom-validator
```

## 📝 Приклади використання

### 1. Базова валідація
1. Запустіть додаток
2. Перейдіть до "✅ Універсальний валідатор"
3. Завантажте SBOM файл або вставте JSON
4. Натисніть "🚀 Валідувати SBOM"

### 2. Пакетна валідація
1. Перейдіть до "📊 Пакетна валідація"
2. Завантажте кілька SBOM файлів
3. Виберіть рівень валідації
4. Отримайте порівняльний аналіз

### 3. Розширений аналіз
1. Перейдіть до "🔍 Розширений аналіз"
2. Завантажте SBOM з компонентами та залежностями
3. Отримайте детальний аналіз безпеки та ліцензій

## 🔄 Оновлення

```bash
pip install --upgrade streamlit pandas matplotlib plotly jsonschema
```

## ❓ Часті питання

**Q: Додаток не запускається?**
A: Перевірте, що встановлений Python 3.8+ та всі базові залежності.

**Q: Не відображаються інтерактивні графіки?**
A: Встановіть plotly: `pip install plotly`

**Q: Помилки валідації схем?**
A: Встановіть jsonschema: `pip install jsonschema`

**Q: Не працює аналіз XML файлів?**
A: Встановіть xmlschema: `pip install xmlschema`

## 📞 Підтримка

Для отримання допомоги:
1. Перевірте консоль на наявність помилок
2. Переконайтеся, що встановлені необхідні залежності
3. Спробуйте перезапустити додаток

## 🔒 Безпека

- Додаток не зберігає завантажені файли
- Всі дані обробляються локально
- Не відправляє дані на зовнішні сервери





### How to run it on your own machine

1. Install the requirements

   ```
   $ pip install -r requirements.txt
   ```

2. Run the app

   ```
   $ streamlit run streamlit_app.py
   ```
