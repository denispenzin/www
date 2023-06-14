import random
import hashlib

def ffs_scheme_calculation(P, Q, num_secrets, secrets, random_sign, random_number, random_sequence):
    # Шаг 1: Считаем N
    N = P * Q

    # Шаг 2: Рассчитать открытый ключ V
    V = pow(random_number, 2, N)

    commitments = []
    responses = []

    # Шаг 3: Рассчитываем обязательства для каждого секрета Si
    for i in range(num_secrets):
        commitment = pow(secrets[i], 2, N)
        commitment *= pow(V, random_sign, N)
        commitment %= N
        commitments.append(commitment)

    # Шаг 4: Генерируйем вызов E из случайной последовательности
    random_sequence_int = int(hashlib.sha256(random_sequence.encode()).hexdigest(), 16)  # Преобразовуем строку в целое число
    E = pow(random_sequence_int, 2, N)

    # Шаг 5: Рассчитываем ответы для каждого секрета Si
    for i in range(num_secrets):
        response = secrets[i]
        response *= pow(random_number, random_sign, N)
        response *= pow(V, E, N)
        response %= N
        responses.append(response)

    return commitments, responses

# Параметры
P = 569
Q = 113
num_secrets = 4
secrets = [12959, 30427, 14843, 31793]
random_sign = 1
random_number = 25035
random_sequence = '1110'

commitments, responses = ffs_scheme_calculation(P, Q, num_secrets, secrets, random_sign, random_number, random_sequence)

# Выводим обязательства и ответы
print("Commitments:")
for i, commitment in enumerate(commitments):
    print(f"C{i+1}: {commitment}")

print("\nResponses:")
for i, response in enumerate(responses):
    print(f"R{i+1}: {response}")
