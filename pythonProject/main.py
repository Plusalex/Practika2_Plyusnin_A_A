import hashlib
import itertools
import string
import threading

def calculate_sha256_hash(input_string):
    sha256 = hashlib.sha256()
    sha256.update(input_string.encode('utf-8'))
    return sha256.hexdigest()

def brute_force_passwords(target_hashes, password_length, alphabet, start, end, results):
    for combination in itertools.product(alphabet, repeat=password_length):
        password = ''.join(combination)
        hash_value = calculate_sha256_hash(password)

        if hash_value in target_hashes:
            results.append((password, hash_value))

def read_hashes_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def main():
    option = input("Выберите способ ввода хэш-значений (1 - консоль, 2 - файл): ")

    if option == '1':
        input_hashes = input("Введите хэш-значения, разделенные запятыми: ").split(',')
    elif option == '2':
        file_path = input("Укажите путь к файлу с хэш-значениями: ")
        input_hashes = read_hashes_from_file(file_path)
    else:
        print("Некорректный выбор.")
        return

    password_length = 5
    alphabet = string.ascii_lowercase
    num_threads = int(input("Укажите количество потоков: "))
    if not input_hashes:
        print("Нет хэш-значений для обработки.")
        return
    chunk_size = max(1, len(input_hashes) // num_threads)
    chunks = [input_hashes[i:i + chunk_size] for i in range(0, len(input_hashes), chunk_size)]
    num_threads = min(num_threads, len(chunks))
    results = []
    threads = []

    for i in range(num_threads):
        thread = threading.Thread(target=brute_force_passwords, args=(chunks[i], password_length, alphabet, 0, password_length, results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    for password, hash_value in results:
        print(f"Найден пароль: {password} (SHA-256 хэш: {hash_value})")

if __name__ == "__main__":
     main()