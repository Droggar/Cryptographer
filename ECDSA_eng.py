import os
import tkinter as tk
import ecdsa
from ecdsa import SigningKey, VerifyingKey, BadSignatureError


def private_key():
    private_key = SigningKey.generate()
    entry_field1.delete(0, "end")
    entry_field1.insert(0, private_key.to_string().hex())


def public_key():
    private_key_hex = entry_field1.get()
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        private_key = SigningKey.from_string(private_key_bytes)
        public_key = private_key.get_verifying_key()
        public_key_hex = public_key.to_string().hex()
        entry_field2.delete(0, "end")
        entry_field2.insert(0, public_key_hex)
    except (ValueError, ecdsa.keys.MalformedPointError):
        entry_field2.delete(0, "end")
        entry_field2.insert(0, "Error: Invalid private key.")


def sign():
    private_key_hex = entry_field1.get()
    message = entry_field3.get()
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = SigningKey.from_string(private_key_bytes)
    signature = private_key.sign(message.encode('utf-8'))
    signature_hex = signature.hex()
    entry_field4.delete(0, "end")
    entry_field4.insert(0, signature_hex)


def check():
    public_key_hex = entry_field2.get()
    signature_hex = entry_field4.get()
    message = entry_field3.get()
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        public_key = VerifyingKey.from_string(public_key_bytes)
        signature_bytes = bytes.fromhex(signature_hex)
        entry_field5.config(state='normal')
        try:
            public_key.verify(signature_bytes, message.encode('utf-8'))
            entry_field5.delete(0, "end")
            entry_field5.insert(0, "The signature is valid.")
            entry_field5.config(state='disabled')
        except BadSignatureError:
            entry_field5.delete(0, "end")
            entry_field5.insert(0, "The signature is invalid.")
            entry_field5.config(state='disabled')
    except (ValueError, ecdsa.keys.MalformedPointError):
        entry_field5.config(state='normal')
        entry_field5.delete(0, "end")
        entry_field5.insert(0, "Error: Invalid public key.")


def back():
    root.destroy()
    current_directory = os.path.dirname(__file__)
    file_path = os.path.join(current_directory, 'main_eng.py')
    exec(open(file_path, encoding="utf-8").read(), globals())


def series_test(data):
    bit_count = len(data)
    k_max = 6
    ones_series_counts = [0] * (k_max + 1)
    zeros_series_counts = [0] * (k_max + 1)
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
    if current_series_symbol == '1':
        ones_series_counts[min(current_series_length, k_max)] += 1
    else:
        zeros_series_counts[min(current_series_length, k_max)] += 1

    chi_squared = 0
    for i in range(1, k_max + 1):
        expected_frequency = (bit_count - i + 3) / (2 ** (i + 2))
        chi_squared += (ones_series_counts[i] - expected_frequency) ** 2 / expected_frequency
        chi_squared += (zeros_series_counts[i] - expected_frequency) ** 2 / expected_frequency

    return chi_squared


def poker_test(data):
    bit_count = len(data)
    m = 4
    k = bit_count // m
    blocks = [data[i:i + m] for i in range(0, bit_count, m)]
    unique_patterns = set(blocks)
    observed_frequencies = [blocks.count(pattern) for pattern in unique_patterns]
    expected_frequency = (2 ** m / k) * sum(count ** 2 for count in observed_frequencies) - k
    poker_test_statistic = expected_frequency
    return poker_test_statistic


def frequency_test(data):
    bit_count = len(data)
    one_count = data.count('1')
    zero_count = bit_count - one_count
    frequency_test_statistic = (one_count - zero_count) ** 2 / bit_count
    return frequency_test_statistic


def two_bit_test(data):
    n = len(data)
    n0 = data.count('0')
    n1 = n - n0
    n00 = sum(1 for i in range(n - 1) if data[i:i + 2] == '00')
    n10 = sum(1 for i in range(n - 1) if data[i:i + 2] == '10')
    n01 = sum(1 for i in range(n - 1) if data[i:i + 2] == '01')
    n11 = sum(1 for i in range(n - 1) if data[i:i + 2] == '11')
    two_bit_test_statistic = (4 * (n00 ** 2 + n01 ** 2 + n10 ** 2 + n11 ** 2) / (n - 1) -
                              (2 * (n0 ** 2 + n1 ** 2) / n) + 1)
    return two_bit_test_statistic


def run_two_bit_test():
    sample_data_hex = entry_field4.get()
    sample_data = ''.join(format(int(x, 16), '04b') for x in sample_data_hex)
    two_bit_test_result = two_bit_test(sample_data)
    check_result(two_bit_test_result, 5.991, "two-bit test", two_bit_result_label)


def run_frequency_test():
    sample_data_hex = entry_field4.get()
    sample_data = ''.join(format(int(x, 16), '04b') for x in sample_data_hex)
    frequency_test_result = frequency_test(sample_data)
    check_result(frequency_test_result, 3.841, "frequency test", frequency_result_label)


def run_poker_test():
    sample_data_hex = entry_field4.get()
    sample_data = ''.join(format(int(x, 16), '04b') for x in sample_data_hex)
    poker_test_result = poker_test(sample_data)
    check_result(poker_test_result, 23.685, "poker test", poker_result_label)


def run_series_test():
    sample_data_hex = entry_field4.get()
    sample_data = ''.join(format(int(x, 16), '04b') for x in sample_data_hex)
    series_test_result = series_test(sample_data)
    check_result(series_test_result, 18.307, "run test", series_result_label)


def check_result(result, critical_value, test_name, result_label):
    result_label.config(state='normal')
    result_label.delete(0, "end")
    if result > critical_value:
        result_label.insert(0, f"Result {test_name}: {result}. Maximum value: {critical_value}. Test failed!")
    else:
        result_label.insert(0, f"Result {test_name}: {result}. Maximum value: {critical_value}. Test passed!")
    result_label.config(state='disabled')

def check_all_tests():
    test_results_label.config(state='normal')
    test_results_label.delete(0, "end")
    if ("Test passed!" in two_bit_result_label.get() and
            "Test passed!" in frequency_result_label.get() and
            "Test passed!" in poker_result_label.get() and
            "Test passed!" in series_result_label.get()):
        test_results_label.delete(0, tk.END)
        test_results_label.insert(tk.END, "All tests passed. The ciphertext is correct.")
    else:
        test_results_label.delete(0, tk.END)
        test_results_label.insert(tk.END, "Some tests did not pass. Check the results of individual tests.")
    test_results_label.config(state='disabled')
# Utwórz okno
root = tk.Tk()
root.title("Signing Algorithm ECDSA")
root.geometry("820x680")  # Zmieniona wysokość okna
root.resizable(False, False)

# Pole tekstowe do wyświetlania klucza prywatnego
label1 = tk.Label(root, text="Private Key:")
label1.place(x=10, y=10)
entry_field1 = tk.Entry(root, width=100)
entry_field1.place(x=10, y=30)

# Przycisk do generowania klucza prywatnego
button1 = tk.Button(root, text="Generate Private Key", command=private_key)
button1.place(x=650, y=25)

# Pole tekstowe do wyświetlania klucza publicznego
label2 = tk.Label(root, text="Public Key:")
label2.place(x=10, y=70)
entry_field2 = tk.Entry(root, width=100)
entry_field2.place(x=10, y=90)

# Przycisk do generowania klucza publicznego
button2 = tk.Button(root, text="Generate Public Key", command=public_key)
button2.place(x=650, y=85)

# Pole tekstowe do wprowadzania wiadomości do podpisania
label3 = tk.Label(root, text="Message to sign:")
label3.place(x=10, y=130)
entry_field3 = tk.Entry(root, width=100)
entry_field3.place(x=10, y=150)

# Przycisk do podpisywania wiadomości
button3 = tk.Button(root, text="Sign the message", command=sign)
button3.place(x=650, y=145)

# Pole tekstowe do wprowadzania podpisu
label4 = tk.Label(root, text="Signature:")
label4.place(x=10, y=190)
entry_field4 = tk.Entry(root, width=100)
entry_field4.place(x=10, y=210)

# Przycisk do sprawdzania podpisu
button4 = tk.Button(root, text="Verify the signature", command=check)
button4.place(x=650, y=205)

# Pole tekstowe do wyświetlania wyniku sprawdzenia podpisu
label5 = tk.Label(root, text="Signature verification:")
label5.place(x=10, y=250)
entry_field5 = tk.Entry(root, width=100)
entry_field5.place(x=10, y=270)

label6 = tk.Label(root, text="Two-bit test result:")
label6.place(x=10, y=310)
two_bit_result_label = tk.Entry(root, width=100)
two_bit_result_label.place(x=10, y=330)
two_bit_button = tk.Button(root, text="Two-bit test", command=run_two_bit_test)
two_bit_button.place(x=650, y=325)

label7 = tk.Label(root, text="Frequency test result:")
label7.place(x=10, y=370)
frequency_result_label = tk.Entry(root, width=100)
frequency_result_label.place(x=10, y=390)

frequency_button = tk.Button(root, text="Frequency test", command=run_frequency_test)
frequency_button.place(x=650, y=385)
label8 = tk.Label(root, text="Poker test result:")
label8.place(x=10, y=430)
poker_result_label = tk.Entry(root, width=100)
poker_result_label.place(x=10, y=450)
poker_button = tk.Button(root, text="Poker test", command=run_poker_test)
poker_button.place(x=650, y=445)

label9 = tk.Label(root, text="Run test result:")
label9.place(x=10, y=490)
series_result_label = tk.Entry(root, width=100)
series_result_label.place(x=10, y=510)
series_button = tk.Button(root, text="Run test", command=run_series_test)
series_button.place(x=650, y=505)
label9 = tk.Label(root, text="Summary:")
label9.place(x=10, y=550)
test_results_label = tk.Entry(root, width=100)
test_results_label.place(x=10, y=570)
check_all_tests_button = tk.Button(root, text="Summary", command=check_all_tests)
check_all_tests_button.place(x=650, y=565)
back_button = tk.Button(root, text="Back", command=back, width=10, height=2)
back_button.place(x=400, y=620)

# Uruchom pętlę główną
root.mainloop()
