import rsa
import socket
import threading
import os
import ssl

# Генерация ключей клиента
public_key, private_key = rsa.newkeys(1024)
server_public_key = None
client_connected = True

# Создание SSL контекста
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False  # Отключаем проверку hostname
context.verify_mode = ssl.CERT_NONE  # Отключаем проверку сертификата

# Подключение к серверу с использованием SSL
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_ssl = context.wrap_socket(client, server_hostname="192.168.56.1")
client_ssl.connect(("192.168.56.1", 9999))

# Получение публичного ключа сервера
server_public_key = rsa.PublicKey.load_pkcs1(client_ssl.recv(2048))
client_ssl.send(public_key.save_pkcs1("PEM"))

def save_file_to_downloads(file_name, file_data):
    """
    Сохранение файла в папку загрузок.
    """
    try:
        # Путь к папке загрузок
        download_path = os.path.join(os.path.expanduser("~"), "Downloads", file_name)

        # Сохранение файла
        with open(download_path, "wb") as file:
            file.write(file_data)

        print(f"Файл '{file_name}' успешно сохранен в папке загрузок.")
    except Exception as e:
        print(f"Ошибка при сохранении файла: {e}")

def send_file(file_path):
    """
    Отправка файла на сервер.
    """
    try:
        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as file:
            file_data = file.read()

        # Отправка метаинформации о файле
        metadata = f"FILE:{file_name}:{len(file_data)}"
        client_ssl.send(rsa.encrypt(metadata.encode(), server_public_key))

        # Отправка содержимого файла
        client_ssl.sendall(file_data)
        print(f"Файл '{file_name}' успешно отправлен!")
    except Exception as e:
        print(f"Ошибка при отправке файла: {e}")

def receive_messages():
    """
    Получение сообщений и файлов от сервера.
    """
    global client_connected
    while client_connected:
        try:
            encrypted_message = client_ssl.recv(2048)
            if encrypted_message:
                message = rsa.decrypt(encrypted_message, private_key).decode()

                if message.startswith("FILE:"):
                    _, file_name, file_size = message.split(":")
                    file_size = int(file_size)
                    print(f"Скачивание файла: {file_name} ({file_size} байт)")

                    # Получение содержимого файла
                    received_data = b""
                    while len(received_data) < file_size:
                        chunk = client_ssl.recv(2048)
                        received_data += chunk

                    # Сохраняем файл в папке загрузок
                    save_file_to_downloads(file_name, received_data)
                else:
                    print(f"Сообщение: {message}")
        except Exception as e:
            print(f"Ошибка получения данных: {e}")
            break

def send_messages():
    """
    Отправка сообщений на сервер.
    """
    global client_connected
    while client_connected:
        try:
            message = input()
            if message == "/help":
                print("Доступные команды:")
                print("/sendFile - Отправить файл на сервер.")
                print("/exit - Выйти из чата.")
                print("/endChat - Завершить чат.")
                print("Просто введите текст, чтобы отправить сообщение.")
            elif message == "/sendFile":
                file_path = input("Введите путь к файлу: ").strip()
                send_file(file_path)
            elif message == "/exit":
                print("Выход из чата...")
                client_connected = False
                client_ssl.send(rsa.encrypt("/exit".encode(), server_public_key))
                break
            elif message == "/endChat":
                client_connected = False
                client_ssl.send(rsa.encrypt("/endChat".encode(), server_public_key))
                break
            else:
                client_ssl.send(rsa.encrypt(message.encode(), server_public_key))
        except Exception as e:
            print(f"Ошибка отправки сообщения: {e}")
            break

# Запуск потоков
threading.Thread(target=receive_messages, daemon=True).start()
send_messages()

# Закрытие соединения
client_ssl.close()