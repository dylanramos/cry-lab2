import base64

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

rate = 15
cipher = AES.new(b"\x07" * 16, AES.MODE_ECB)


def permutation(b):
    return cipher.encrypt(b)


def pad(message, rate):
    missing = rate - len(message) % rate
    if missing == 0:
        missing = rate
    message += b"\x80" + b"\x00" * (missing - 1)
    return message


# Hashes the message to a specific output_size
def sponge(rate, message, output_size):
    # padding
    message = pad(message, rate)

    blocks = [message[rate * i:rate * (i + 1)] for i in range(len(message) // rate)]
    state = b"\x00" * 16
    # absorbing
    for b in blocks:
        state = strxor(state[:rate], b) + state[rate:]
        state = permutation(state)
    # squeezing
    hash = b""
    while len(hash) < output_size:
        hash += state[:rate]
        state = permutation(state)
    return hash[:output_size]


def main():
    hash = base64.b64decode(
        b"6+GDr39y52TbrvQBeM2cHw/gqCeFozZYY/W8SaQ8+RXPvKMsewoUx8uEWeilNYhvRthfPOpbwIyE67YnOLuqpA==")

    z0 = hash[:15]
    z1 = hash[15:30]

    c = b""
    for i in range(33, 127):
        c = chr(i).encode()
        new_z1 = permutation(z0 + c)
        if new_z1[:15] == z1:
            break

    second_block = cipher.decrypt(z0 + c)
    m1_after_xor = second_block[:15]
    c = second_block[15:16]
    known_start = b"FLAG{"

    for i in range(33, 127):
        char0 = chr(i).encode()
        for j in range(33, 127):
            char1 = chr(j).encode()
            for k in range(33, 127):
                char2 = chr(k).encode()
                first_block = strxor(m1_after_xor, char0 + char1 + char2 + b"}\x80" + b"\x00" * 10)
                first_block = cipher.decrypt(first_block + c)
                m0 = first_block[:15]

                if m0[:5] == known_start:
                    print(f"Found the flag: {m0.decode() + char0.decode() + char1.decode() + char2.decode()}}}")
                    return


if __name__ == "__main__":
    main()
