import os
import tkinter as tk

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_keys():
    global lokalny_klucz_prywatny, local_public_key, second_private_key, second_public_key
    ecdh_lokalny = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdh_zdalny = ec.generate_private_key(ec.SECP256R1(), default_backend())
    lokalny_klucz_prywatny = ecdh_lokalny
    local_public_key = ecdh_lokalny.public_key()
    second_private_key = ecdh_zdalny
    second_public_key = ecdh_zdalny.public_key()
    lokalny_klucz_prywatny_tekst.delete(1.0, tk.END)
    lokalny_klucz_prywatny_tekst.insert(tk.END, lokalny_klucz_prywatny.private_bytes(encoding=serialization.Encoding.PEM,
                                                                             format=serialization.PrivateFormat.PKCS8,
                                                                             encryption_algorithm=serialization.NoEncryption()))
    local_public_key_tekst.delete(1.0, tk.END)
    local_public_key_tekst.insert(tk.END, local_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))

    second_private_key_tekst.delete(1.0, tk.END)
    second_private_key_tekst.insert(tk.END, second_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                                             format=serialization.PrivateFormat.PKCS8,
                                                                             encryption_algorithm=serialization.NoEncryption()))
    second_public_key_tekst.delete(1.0, tk.END)
    second_public_key_tekst.insert(tk.END, second_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                          format=serialization.PublicFormat.SubjectPublicKeyInfo))


def encrypt_message():
    second_public_key_pem = second_public_key_tekst.get("1.0", "end-1c")
    second_public_key_pem_bytes = second_public_key_pem.encode('utf-8')
    second_public_key = serialization.load_pem_public_key(second_public_key_pem_bytes, default_backend())
    local_secret = lokalny_klucz_prywatny.exchange(ec.ECDH(), second_public_key)
    original_message = original_message_text.get("1.0", "end-1c").encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'salt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    encryption_key = kdf.derive(local_secret)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(original_message) + encryptor.finalize()
    authentication_tag = encryptor.tag
    encrypted_message.delete(1.0, tk.END)
    encrypted_message.insert(tk.END, nonce.hex() + authentication_tag.hex() + ciphertext.hex())


def decrypt_message():
    local_public_key_pem = local_public_key_tekst.get("1.0", "end-1c")
    local_public_key_pem_bytes = local_public_key_pem.encode('utf-8')
    local_public_key = serialization.load_pem_public_key(local_public_key_pem_bytes, default_backend())
    second_secret = second_private_key.exchange(ec.ECDH(), local_public_key)
    encrypted_message_hex = encrypted_message.get("1.0", "end-1c")
    nonce = bytes.fromhex(encrypted_message_hex[:24])
    authentication_tag = bytes.fromhex(encrypted_message_hex[24:56])
    ciphertext = bytes.fromhex(encrypted_message_hex[56:])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'salt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    decryption_key = kdf.derive(second_secret)
    cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(nonce, authentication_tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(b'')
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    encrypt_message_text.delete(1.0, tk.END)
    encrypt_message_text.insert(tk.END, decrypted_data.decode('utf-8'))


def back():
    root.destroy()
    current_directory = os.path.dirname(__file__)
    file_path = os.path.join(current_directory, 'main.py')
    exec(open(file_path, encoding="utf-8").read(), globals())


def series_test(data):
    bit_count = len(data)

    k_max = 6  # Maksymalna spodziewana długość serii

    # Inicjalizacja liczników serii
    ones_series_counts = [0] * (k_max + 1)
    zeros_series_counts = [0] * (k_max + 1)

    # Zliczanie serii
    current_series_length = 1
    current_series_symbol = data[0]
    for i in range(1, bit_count):
        if data[i] == current_series_symbol:
            current_series_length += 1
        else:
            if current_series_symbol == '1':
                ones_series_counts[min(current_series_length, k_max)] += 1
            else:
                zeros_series_counts[min(current_series_length, k_max)] += 1

            current_series_symbol = data[i]
            current_series_length = 1

    # Zliczanie ostatniej serii
    if current_series_symbol == '1':
        ones_series_counts[min(current_series_length, k_max)] += 1
    else:
        zeros_series_counts[min(current_series_length, k_max)] += 1

    # Obliczanie statystyki chi-kwadrat
    chi_squared = 0
    for i in range(1, k_max + 1):
        expected_frequency = (bit_count - i + 3) / (2 ** (i + 2))
        chi_squared += (ones_series_counts[i] - expected_frequency) ** 2 / expected_frequency
        chi_squared += (zeros_series_counts[i] - expected_frequency) ** 2 / expected_frequency

    return chi_squared


def poker_test(data):
    bit_count = len(data)
    m = 4  # długość podciągu
    k = bit_count // m  # liczba pełnych podciągów
    n = k * m  # długość badanego ciągu
    blocks = [data[i:i + m] for i in range(0, bit_count, m)]
    unique_patterns = set(blocks)
    observed_frequencies = [blocks.count(pattern) for pattern in unique_patterns]
    expected_frequency = (2 ** m / k) * sum(count ** 2 for count in observed_frequencies) - k
    poker_test_statistic = expected_frequency
    return poker_test_statistic


def frequency_test(data):
    bit_count = len(data)
    ones_count = data.count('1')
    zeros_count = bit_count - ones_count

    frequency_test_statistic = (ones_count - zeros_count) ** 2 / bit_count

    return frequency_test_statistic


def two_bit_test(data):
    n = len(data)
    n0 = data.count('0')
    n1 = n - n0
    n00 = sum(1 for i in range(n - 1) if data[i:i + 2] == '00')
    n10 = sum(1 for i in range(n - 1) if data[i:i + 2] == '10')
    n01 = sum(1 for i in range(n - 1) if data[i:i + 2] == '01')
    n11 = sum(1 for i in range(n - 1) if data[i:i + 2] == '11')

    two_bit_test_statistic = 4 * (n00 ** 2 + n01 ** 2 + n10 ** 2 + n11 ** 2) / (n - 1) - (
            2 * (n0 ** 2 + n1 ** 2) / n) + 1

    return two_bit_test_statistic


def run_two_bit_test():
    sample_data_hex = encrypted_message.get("1.0", "end-1c")
    sample_data = ''.join(format(int(x, 16), '04b') for x in sample_data_hex)

    # Przeprowadź test dwubitowy
    two_bit_test_result = two_bit_test(sample_data)

    # Porównaj wyniki z wartościami krytycznymi i wyświetl rezultaty
    check_result(two_bit_test_result, 3.841, "testu dwubitowego", two_bit_result_label)


def run_frequency_test():
    sample_data_hex = encrypted_message.get("1.0", "end-1c")
    sample_data = ''.join(format(int(x, 16), '04b') for x in sample_data_hex)

    # Przeprowadź test częstości
    frequency_test_result = frequency_test(sample_data)

    # Porównaj wyniki z wartościami krytycznymi i wyświetl rezultaty
    check_result(frequency_test_result, 3.841, "testu częstości", frequency_result_label)


def run_poker_test():
    sample_data_hex = encrypted_message.get("1.0", "end-1c")
    sample_data = ''.join(format(int(x, 16), '04b') for x in sample_data_hex)

    # Przeprowadź test pokerowy
    poker_test_result = poker_test(sample_data)

    # Porównaj wyniki z wartościami krytycznymi i wyświetl rezultaty
    check_result(poker_test_result, 23.685, "testu pokerowego", poker_result_label)


def run_series_test():
    sample_data_hex = encrypted_message.get("1.0", "end-1c")
    sample_data = ''.join(format(int(x, 16), '04b') for x in sample_data_hex)
    # Przeprowadź test serii
    series_test_result = series_test(sample_data)

    # Porównaj wyniki z wartościami krytycznymi i wyświetl rezultaty
    check_result(series_test_result, 18.307, "testu serii", series_result_label)


def check_result(result, critical_value, test_name, result_label):
    result_label.config(state='normal')
    result_label.delete(0, "end")

    if result > critical_value:
        result_label.insert(0, f"Wynik {test_name}: {result}. Wartość maksymalna: {critical_value}. Test niezdany!")
    else:
        result_label.insert(0, f"Wynik {test_name}: {result}. Wartość maksymalna: {critical_value}. Test zdany!")

    result_label.config(state='disabled')


def check_all_tests():
    test_results_label.config(state='normal')
    test_results_label.delete(0, "end")
    if ("Test zdany!" in two_bit_result_label.get() and
            "Test zdany!" in frequency_result_label.get() and
            "Test zdany!" in poker_result_label.get() and
            "Test zdany!" in series_result_label.get()):
        test_results_label.delete(0, tk.END)
        test_results_label.insert(tk.END, "Wszystkie testy są zdane. Szyfrogram jest poprawny.")
    else:
        test_results_label.delete(0, tk.END)
        test_results_label.insert(tk.END, "Niektóre testy nie są zdane. Sprawdź wyniki indywidualnych testów.")
    test_results_label.config(state='disabled')


root = tk.Tk()
root.title("ECDH Szyfrowanie Wiadomości")
root.geometry("1550x520")
root.resizable(False, False)
# Lewa strona - pola do generowania kluczy i przycisk
lokalny_klucz_prywatny_label = tk.Label(root, text="Lokalny Klucz Prywatny:")
lokalny_klucz_prywatny_label.place(x=10, y=10)

lokalny_klucz_prywatny_tekst = tk.Text(root, height=5, width=40)
lokalny_klucz_prywatny_tekst.place(x=10, y=30)

local_public_key_label = tk.Label(root, text="Lokalny Klucz Publiczny:")
local_public_key_label.place(x=10, y=120)

local_public_key_tekst = tk.Text(root, height=5, width=40)
local_public_key_tekst.place(x=10, y=140)

second_private_key_label = tk.Label(root, text="Zdalny Klucz Prywatny:")
second_private_key_label.place(x=10, y=230)

second_private_key_tekst = tk.Text(root, height=5, width=40)
second_private_key_tekst.place(x=10, y=250)

second_public_key_label = tk.Label(root, text="Zdalny Klucz Publiczny:")
second_public_key_label.place(x=10, y=340)

second_public_key_tekst = tk.Text(root, height=5, width=40)
second_public_key_tekst.place(x=10, y=360)

generate_keys_przycisk = tk.Button(root, text="Generuj Klucze", command=generate_keys)
generate_keys_przycisk.place(x=120, y=460)

# Prawa strona - pola do wiadomości i przyciski
original_message_label = tk.Label(root, text="Oryginalna Wiadomość:")
original_message_label.place(x=380, y=10)

original_message_text = tk.Text(root, height=5, width=40)
original_message_text.place(x=380, y=30)

zaszyfruj_przycisk = tk.Button(root, text="Zaszyfruj Wiadomość", command=encrypt_message)
zaszyfruj_przycisk.place(x=480, y=130)

encrypted_message_label = tk.Label(root, text="Zaszyfrowana Wiadomość:")
encrypted_message_label.place(x=380, y=180)

encrypted_message = tk.Text(root, height=5, width=40)
encrypted_message.place(x=380, y=200)
deszyfruj_przycisk = tk.Button(root, text="Deszyfruj Wiadomość", command=decrypt_message)
deszyfruj_przycisk.place(x=480, y=300)
encrypt_message_label = tk.Label(root, text="Odszyfrowana Wiadomość:")
encrypt_message_label.place(x=380, y=340)

encrypt_message_text = tk.Text(root, height=5, width=40)
encrypt_message_text.place(x=380, y=360)

label6 = tk.Label(root, text="Wynik testu dwubitowego:")
label6.place(x=760, y=10)

two_bit_result_label = tk.Entry(root, width=100)
two_bit_result_label.place(x=760, y=30)

two_bit_button = tk.Button(root, text="Test Dwubitowy", command=run_two_bit_test)
two_bit_button.place(x=1410, y=25)

label7 = tk.Label(root, text="Wynik testu częstości:")
label7.place(x=760, y=70)

frequency_result_label = tk.Entry(root, width=100)
frequency_result_label.place(x=760, y=90)

frequency_button = tk.Button(root, text="Test Częstości", command=run_frequency_test)
frequency_button.place(x=1410, y=85)

label8 = tk.Label(root, text="Wynik testu pokerowego:")
label8.place(x=760, y=125)

poker_result_label = tk.Entry(root, width=100)
poker_result_label.place(x=760, y=145)

poker_button = tk.Button(root, text="Test Pokerowy", command=run_poker_test)
poker_button.place(x=1410, y=140)

label9 = tk.Label(root, text="Wynik testu serii:")
label9.place(x=760, y=180)

series_result_label = tk.Entry(root, width=100)
series_result_label.place(x=760, y=200)

series_button = tk.Button(root, text="Test Serii", command=run_series_test)
series_button.place(x=1410, y=195)
label9 = tk.Label(root, text="Podsumowanie:")
label9.place(x=760, y=230)
test_results_label = tk.Entry(root, width=100)
test_results_label.place(x=760, y=250)
check_all_tests_button = tk.Button(root, text="Podsumowanie", command=check_all_tests)
check_all_tests_button.place(x=1410, y=245)
back_button = tk.Button(root, text="Powrót", command=back, width=20, height=2)
back_button.place(x=1000, y=290)

root.mainloop()
