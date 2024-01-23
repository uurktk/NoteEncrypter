import tkinter
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def encryptFile():
    title = titleEntry.get()
    message = textEntry.get("1.0", "end")
    password = passwordEntry.get()

    if len(title) == 0 or len(message) == 0 or len(password) == 0:
        messagebox.showinfo(title="Error!", message="Enter valid values.")
    else:
        encMessage = encode(password, message)
        try:
            with open("SecretNotes.txt", "a") as encFile:
                encFile.write(f'\n{title}\n{encMessage}')
        except:
            with open("SecretNotes.txt", "w") as encFile:
                encFile.write(f"\n{title}\n{encMessage}")
        finally:
            titleEntry.delete(0, "end")
            passwordEntry.delete(0, "end")
            textEntry.delete("1.0", "end")

def encrypt():
    encMessage = textEntry.get("1.0", "end")
    password = passwordEntry.get()

    if len(password) == 0 or len(encMessage) == 0:
        messagebox.showinfo(title="Error!", message="Enter valid values.")
    else:
        try:
            decMessage = decode(password, encMessage)
            textEntry.delete("1.0", "end")
            textEntry.insert("1.0", decMessage)
        except:
            messagebox.showinfo(title="Error!", message="Make sure of encrypted info.")

def decrypt():
    encMessage = textEntry.get("1.0", "end")
    password = passwordEntry.get()

    if len(encMessage) == 0 or len(password) == 0:
        messagebox.showinfo(title="Error!", message="Enter valid values")
    else:
        try:
            decMessage = decode(password, encMessage)
            textEntry.delete("1.0", "end")
            textEntry.insert("1.0", decMessage)
        except:
            messagebox.showinfo(title="Error!", message="Make sure of encrypted info.")

# window
window = tkinter.Tk()
window.title("Note Encrypter")
window.config(padx=12, pady=12, bg="#F2BED1")
window.minsize(300, 500)
window.resizable(False, False)
window.geometry('%dx%d+%d+%d' % (300, 500, 533, 134))

FONT = ("Arial", 10, "bold")
ENTRY_FONT = ("Arial", 10, "normal")

titleLabel = tkinter.Label(text="Title", font=FONT, bg="#F2BED1", fg="#000000")
titleLabel.pack()
titleEntry = tkinter.Entry(width=15, bg="#F9F5F6", fg="#000000", font=ENTRY_FONT)
titleEntry.pack()

textLabel = tkinter.Label(text="Enter your secret note", font=FONT, bg="#F2BED1", fg="#000000")
textLabel.pack()
textEntry = tkinter.Text(height=18, bg="#F9F5F6", fg="#000000", font=ENTRY_FONT)
textEntry.pack()

passwordLabel = tkinter.Label(text="Password", font=FONT, bg="#F2BED1", fg="#000000")
passwordLabel.pack()
passwordEntry = tkinter.Entry(window, show="*", width=30, bg="#F9F5F6", fg="#000000")
passwordEntry.pack()

# buttons
encryptButton = tkinter.Button(text="Encrypt", command=encryptFile, padx=3, pady=3)
encryptButton.config(cursor="hand2", width=10, bg="#FDCEDF")
encryptButton.pack(pady=5)

decryptButton = tkinter.Button(text="Decrypt", command=decrypt, padx=3, pady=3)
decryptButton.config(cursor="hand2", width=10, bg="#FDCEDF")
decryptButton.pack()

window.mainloop()