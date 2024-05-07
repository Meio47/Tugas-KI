from tkinter import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import pyperclip

class CryptoApp:
    def __init__(self, master):
        self.master = master
        master.title("Aplikasi Enkripsi-Dekripsi")

        self.message_label = Label(master, text="Masukkan pesan:")
        self.message_label.grid(row=0, column=0, padx=10, pady=10)

        self.message_entry = Entry(master, width=50)
        self.message_entry.grid(row=0, column=1, padx=10, pady=10)

        self.key_label = Label(master, text="Masukkan kunci(Berisi 16 karakter):")
        self.key_label.grid(row=1, column=0, padx=10, pady=10)

        self.key_entry = Entry(master, show="*", width=50)
        self.key_entry.grid(row=1, column=1, padx=10, pady=10)

        self.encrypt_button = Button(master, text="Enkripsi", command=self.encrypt_text, width=20)
        self.encrypt_button.grid(row=2, column=0, padx=10, pady=10)

        self.decrypt_button = Button(master, text="Dekripsi", command=self.decrypt_text, width=20)
        self.decrypt_button.grid(row=2, column=1, padx=10, pady=10)

        self.result_label = Label(master, text="Hasil Enkripsi/Dekripsi:")
        self.result_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        self.copy_button = Button(master, text="Salin", command=self.copy_result, width=20)
        self.copy_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    def encrypt_text(self):
        message = self.message_entry.get()
        key = self.key_entry.get().encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        encrypted_text = iv + ct
        self.result_label.config(text="Hasil Enkripsi/Dekripsi: " + encrypted_text)

    def decrypt_text(self):
        ciphertext = self.message_entry.get()
        key = self.key_entry.get().encode('utf-8')
        iv = base64.b64decode(ciphertext[:24])
        ct = base64.b64decode(ciphertext[24:])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
        self.result_label.config(text="Hasil Enkripsi/Dekripsi: " + decrypted_text)

    def copy_result(self):
        result_text = self.result_label.cget("text").split(": ")[1]
        pyperclip.copy(result_text)

root = Tk()
root.geometry("700x300")  
app = CryptoApp(root)
root.mainloop()
