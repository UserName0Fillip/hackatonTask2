import socket
import threading
import rsa
import os
import ssl

# Генерация ключей сервера
server_public_key, server_private_key = rsa.newkeys(1024)

# Список подключённых клиентов
clients = []
client_keys = {}

# Настройка сервера
host = "192.168.56.1"  # Замените на ваш IP-адрес
port = 9999
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen(5)

# Оборачиваем серверный сокет в SSL для защищенного соединения
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.check_hostname = False  # Отключаем проверку hostname для self-signed сертификатов
context.load_cert_chain(certfile="public_cert.pem", keyfile="private_key.pem")  # Путь к сертификатам сервера

# Принятие подключений с SSL
ssl_server = context.wrap_socket(server, server_side=True)

print("Сервер запущен. Ожидание подключений...")

def broadcast_message(sender, message):
    """
    Отправка сообщения всем клиентам, кроме отправителя.
    """
    for client, client_address in clients:
        if client != sender:
            try:
                encrypted_message = rsa.encrypt(message.encode(), client_keys[client])
                client.send(encrypted_message)
            except Exception as e:
                print(f"Ошибка при отправке сообщения клиенту")
                client.close()
                clients.remove((client, client_address))

def send_file(receiver, sender, file_metadata, file_data):
    """
    Передача файла от одного клиента другому.
    """
    try:
        # Отправка метаинформации о файле
        receiver.send(rsa.encrypt(file_metadata.encode(), client_keys[receiver]))
        
        # Отправка содержимого файла
        receiver.sendall(file_data)
        print(f"Файл успешно отправлен.")
    except Exception as e:
        print(f"Ошибка при отправке файла: {e}")
        receiver.close()
        clients.remove((receiver, receiver.getpeername()))

def handle_client(client, address):
    """
    Обработка взаимодействия с клиентом.
    """
    print(f"Клиент подключён: {address}")
    try:
        # Отправка публичного ключа сервера
        client.send(server_public_key.save_pkcs1("PEM"))

        # Получение публичного ключа клиента
        client_public_key = rsa.PublicKey.load_pkcs1(client.recv(2048))
        client_keys[client] = client_public_key

        while True:
            try:
                encrypted_message = client.recv(2048)
                if encrypted_message:
                    message = rsa.decrypt(encrypted_message, server_private_key).decode()
                    
                    if message.startswith("FILE:"):
                        # Обработка передачи файла
                        _, file_name, file_size = message.split(":")
                        file_size = int(file_size)
                        print(f"Получен файл {file_name} ({file_size} байт)")

                        # Получение файла
                        received_data = b""
                        while len(received_data) < file_size:
                            chunk = client.recv(2048)
                            received_data += chunk

                        print(f"Файл {file_name} полностью получен.")
                        # Отправка файла другим клиентам
                        for receiver, _ in clients:
                            if receiver != client:
                                send_file(receiver, client, message, received_data)
                    elif message == "/endChat":
                        print(f"Клиент {address} завершил чат.")
                        clients.remove((client, address))
                        break
                    else:
                        print(f"{message}")
                        broadcast_message(client, f"Сообщение отправлено")
                else:
                    break
            except Exception as e:
                print(f"Ошибка обработки клиента {address}: {e}")
                break
    finally:
        client.close()
        print(f"Клиент {address} отключён.")
        if (client, address) in clients:
            clients.remove((client, address))

def accept_clients():
    """
    Прослушивание новых подключений.
    """
    while True:
        client, address = ssl_server.accept()  # Используем SSL-сокет для принятия подключений
        clients.append((client, address))
        threading.Thread(target=handle_client, args=(client, address), daemon=True).start()

# Запуск прослушивания подключений
accept_clients_thread = threading.Thread(target=accept_clients, daemon=True)
accept_clients_thread.start()

# Основной поток сервера, основной поток может выполнять другие задачи или просто ожидать завершения
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Сервер остановлен.")
finally:
    ssl_server.close()
    server.close()