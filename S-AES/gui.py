import tkinter as tk
from tkinter import ttk
import requests
from SAES import *
def encrypt_text():
    input_text = input_text_entry.get()
    input_key = input_key_entry.get()
    padding = padding_entry.get()
    url = "http://localhost:5000/work_mode/encryptText"
    data = {
        "inputText": input_text,
        "inputKey": input_key,
        "padding": padding
    }
    response = requests.post(url, json=data)
    result = response.json()["result"]
    padding = response.json()["padding"]

    result_label.config(text="Encrypted Text: " + result)
    padding_label.config(text="Padding: " + padding)

def decrypt_text():
    input_text = input_text_entry.get()
    input_key = input_key_entry.get()
    padding = padding_entry.get()
    url = "http://localhost:5000/work_mode/decryptText"
    data = {
        "inputText": input_text,
        "inputKey": input_key,
        "padding": padding
    }
    response = requests.post(url, json=data)
    result = response.text

    result_label.config(text="Decrypted Text: " + result)

def encrypt_message():
    form = form_combobox.get()
    message = message_entry.get()
    key = key_entry.get()
    url = "http://localhost:5000/test_mode/encryptMessage"
    data = {
        "form": form,
        "message": message,
        "key": key
    }
    response = requests.post(url, json=data)
    result = response.text

    result_label.config(text="Encrypted Message: " + result)

def decrypt_message():
    form = form_combobox.get()
    message = message_entry.get()
    key = key_entry.get()
    url = "http://localhost:5000/test_mode/decryptMessage"
    data = {
        "form": form,
        "message": message,
        "key": key
    }
    response = requests.post(url, json=data)
    result = response.text

    result_label.config(text="Decrypted Message: " + result)

def encrypt_multi():
    form = form_combobox.get()
    message = message_entry.get()
    key = key_entry.get()
    url = "http://localhost:5000/multi_mode/encryptMessage"
    data = {
        "form": form,
        "message": message,
        "key": key
    }
    response = requests.post(url, json=data)
    result = response.text

    result_label.config(text="Encrypted Message: " + result)

def decrypt_multi():
    form = form_combobox.get()
    message = message_entry.get()
    key = key_entry.get()
    url = "http://localhost:5000/multi_mode/decryptMessage"
    data = {
        "form": form,
        "message": message,
        "key": key
    }
    response = requests.post(url, json=data)
    result = response.text

    result_label.config(text="Decrypted Message: " + result)

root = tk.Tk()
root.title("Encryption/Decryption GUI")
notebook = ttk.Notebook(root)
notebook.pack(pady=10)
work_mode_frame = ttk.Frame(notebook, width=400, height=300)
test_mode_frame = ttk.Frame(notebook, width=400, height=300)
multi_mode_frame = ttk.Frame(notebook, width=400, height=300)
work_mode_frame.pack(fill="both", expand=1)
test_mode_frame.pack(fill="both", expand=1)
multi_mode_frame.pack(fill="both", expand=1)
notebook.add(work_mode_frame, text="Work Mode")
notebook.add(test_mode_frame, text="Test Mode")
notebook.add(multi_mode_frame, text="Multi Mode")

#Work Mode
work_mode_label = ttk.Label(work_mode_frame, text="Work Mode")
work_mode_label.pack(pady=10)
input_text_label = ttk.Label(work_mode_frame, text="Input Text:")
input_text_label.pack()
input_text_entry = ttk.Entry(work_mode_frame, width=30)
input_text_entry.pack()
input_key_label = ttk.Label(work_mode_frame, text="Input Key:")
input_key_label.pack()
input_key_entry = ttk.Entry(work_mode_frame, width=30)
input_key_entry.pack()
padding_label = ttk.Label(work_mode_frame, text="Padding:")
padding_label.pack()
padding_entry = ttk.Entry(work_mode_frame, width=30)
padding_entry.pack()
encrypt_button = ttk.Button(work_mode_frame, text="Encrypt", command=encrypt_text)
encrypt_button.pack(pady=10)
decrypt_button = ttk.Button(work_mode_frame, text="Decrypt", command=decrypt_text)
decrypt_button.pack(pady=10)
result_label = ttk.Label(work_mode_frame, text="")
result_label.pack(pady=10)

#Test Mode
test_mode_label = ttk.Label(test_mode_frame, text="Test Mode")
test_mode_label.pack(pady=10)
form_label = ttk.Label(test_mode_frame, text="Form:")
form_label.pack()
form_combobox = ttk.Combobox(test_mode_frame, values=["Binary", "ASCII", "Hexadecimal"])
form_combobox.pack()
message_label = ttk.Label(test_mode_frame, text="Message:")
message_label.pack()
message_entry = ttk.Entry(test_mode_frame, width=30)
message_entry.pack()
key_label = ttk.Label(test_mode_frame, text="Key:")
key_label.pack()
key_entry = ttk.Entry(test_mode_frame, width=30)
key_entry.pack()
encrypt_button = ttk.Button(test_mode_frame, text="Encrypt", command=encrypt_message)
encrypt_button.pack(pady=10)
decrypt_button = ttk.Button(test_mode_frame, text="Decrypt", command=decrypt_message)
decrypt_button.pack(pady=10)
result_label = ttk.Label(test_mode_frame, text="")
result_label.pack(pady=10)

#Multi Mode
multi_mode_label = ttk.Label(multi_mode_frame, text="Multi Mode")
multi_mode_label.pack(pady=10)
form_label = ttk.Label(multi_mode_frame, text="Form:")
form_label.pack()
form_combobox = ttk.Combobox(multi_mode_frame, values=["double", "triple"])
form_combobox.pack()
message_label = ttk.Label(multi_mode_frame, text="Message:")
message_label.pack()
message_entry = ttk.Entry(multi_mode_frame, width=30)
message_entry.pack()
key_label = ttk.Label(multi_mode_frame, text="Key:")
key_label.pack()
key_entry = ttk.Entry(multi_mode_frame, width=30)
key_entry.pack()
encrypt_button = ttk.Button(multi_mode_frame, text="Encrypt", command=encrypt_multi)
encrypt_button.pack(pady=10)
decrypt_button = ttk.Button(multi_mode_frame, text="Decrypt", command=decrypt_multi)
decrypt_button.pack(pady=10)
result_label = ttk.Label(multi_mode_frame, text="")
result_label.pack(pady=10)
root.mainloop()