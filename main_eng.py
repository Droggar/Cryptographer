import os
import tkinter as tk


def show_algorithms():
    button_algorithms.pack_forget()
    button_change_language.pack_forget()
    button_exit.pack_forget()
    new_button1 = tk.Button(root, text="ECDSA", command=show_edca, width=20, height=2)
    new_button2 = tk.Button(root, text="ECDH", command=show_ecdh, width=20, height=2)
    new_button1.place(x=230, y=140)
    new_button2.place(x=230, y=200)


def change_language():
    root.destroy()
    current_directory = os.path.dirname(__file__)
    file_path = os.path.join(current_directory, 'main.py')
    exec(open(file_path, encoding="utf-8").read(), globals())


def exit_application():
    exit()


def show_edca():
    root.destroy()
    current_directory = os.path.dirname(__file__)
    file_path = os.path.join(current_directory, 'ECDSA_eng.py')
    exec(open(file_path, encoding="utf-8").read(), globals())


def show_ecdh():
    root.destroy()
    current_directory = os.path.dirname(__file__)
    file_path = os.path.join(current_directory, 'ECDH_eng.py')
    exec(open(file_path, encoding="utf-8").read(), globals())


root = tk.Tk()
root.title("ECC")
root.resizable(False, False)
button_algorithms = tk.Button(root, text="Algorithms", command=show_algorithms, width=20, height=2)
button_change_language = tk.Button(root, text="Change language", command=change_language, width=20, height=2)
button_exit = tk.Button(root, text="Exit", command=exit_application, width=20, height=2)
label_ecc = tk.Label(root, text="ECC", font=('ARIAL', 45), fg='red')
label_ecc.place(x=235, y=50)
button_algorithms.place(x=230, y=140)
button_change_language.place(x=230, y=200)
button_exit.place(x=230, y=260)
root.geometry("600x400")
root.mainloop()
