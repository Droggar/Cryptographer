# Aplikacja kryptograficzna (Python)

## 📌 Opis projektu

Projekt jest aplikacją napisaną w języku **Python**, wykorzystującą bibliotekę **Tkinter** do stworzenia interfejsu graficznego. Aplikacja prezentuje i demonstruje wybrane algorytmy kryptograficzne (np. **ECDSA / ECDH**), umożliwiając ich uruchamianie z poziomu GUI.

Projekt został przygotowany w celach **edukacyjnych / akademickich**.

---

## 🧩 Funkcjonalności

* Graficzny interfejs użytkownika (GUI)
* Uruchamianie modułów kryptograficznych (np. ECDSA)
* Testowanie szyfrogramu przy pomocy testów
* Modularna struktura plików
* Obsługa bibliotek zewnętrznych

---

## 🛠️ Wymagania

* Python **3.10+** (testowane na Python 3.13)
* System Windows / Linux / macOS

### Biblioteki Python

Wszystkie wymagane biblioteki znajdują się w pliku `requirements.txt`.

---

## 🚀 Instalacja i uruchomienie

### 1️⃣ Klonowanie repozytorium

```bash
git clone <URL_REPOZYTORIUM>
cd Cryptographer
```

### 2️⃣ Instalacja zależności

```bash
pip install -r requirements.txt
```

### 3️⃣ Uruchomienie aplikacji

```bash
python main.py
```

---

## 📂 Struktura projektu

```
Aplikacja/
├─ main.py          # Główny plik aplikacji (GUI)
├─ ECDSA.py         # Moduł kryptograficzny ECDSA
├─ ECDH.py         # Moduł kryptograficzny ECDH
├─ requirements.txt # Lista zależności
├─ README.md        # Dokumentacja
└─ .gitignore
```

---

## ⚠️ Uwagi

* Projekt wykorzystuje bibliotekę `cryptography`, która **musi być zainstalowana** przed uruchomieniem.
* Dołączone algorytmy służą **wyłącznie do celów demonstracyjnych**.

---

## 📜 Licencja

Projekt udostępniony na potrzeby edukacyjne.
