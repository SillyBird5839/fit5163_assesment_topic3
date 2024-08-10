import hashlib
import functools
import ecdsa
from ecdsa.util import randrange
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa import numbertheory


def map_to_curve(x, P=curve_secp256k1.p()):
    x -= 1
    y = 0
    found = False

    while not found:
        x += 1
        f_x = (x * x * x + 7) % P

        try:
            y = numbertheory.square_root_mod_prime(f_x, P)
            found = True
        except Exception as e:
            pass
    return ecdsa.ellipticcurve.Point(curve_secp256k1, x, y)

def H1(msg, hash_func=hashlib.sha256):
    return int('0x'+ hash_func(concat(msg)).hexdigest(), 16)
def H2(msg, hash_func=hashlib.sha256):
    return map_to_curve(H1(msg, hash_func=hash_func))
def concat(params):
    n = len(params)
    bytes_value = [0] * n

    for i in range(n):

        if type(params[i]) is int:
            bytes_value[i] = params[i].to_bytes(32, 'big')
        if type(params[i]) is list:
            bytes_value[i] = concat(params[i])
        if type(params[i]) is ecdsa.ellipticcurve.Point:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')
        if type(params[i]) is str:
            bytes_value[i] = params[i].encode()

        if bytes_value[i] == 0:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')

    return functools.reduce(lambda x, y: x + y, bytes_value)

def stringify_point(p):
    return '{},{}'.format(p.x(), p.y())



def ring_signature(SigningKey, key_idx, M, L, G=SECP256k1.generator, hash_func=hashlib.sha256):
    n = len(L)
    c = [0] * n
    s = [0] * n

    # STEP 1
    H = H2(L, hash_func=hash_func)
    Y =  H * SigningKey

    # STEP 2
    u = randrange(SECP256k1.order)
    c[(key_idx + 1) % n] = H1([L, Y, M, G * u, H * u], hash_func=hash_func)

    # STEP 3
    for i in [ i for i in range(key_idx + 1, n)] + [i for i in range(key_idx)]:

        s[i] = randrange(SECP256k1.order)

        z_1 = (G * s[i]) + (L[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        c[(i + 1) % n] = H1([L, Y, M, z_1, z_2], hash_func=hash_func)

    # STEP 4
    s[key_idx] = (u - SigningKey * c[key_idx]) % SECP256k1.order
    return (c[0], s, Y)




def verify_ring_signature(message, L, c_0, s, Y, G=SECP256k1.generator, hash_func=hashlib.sha256):

    n = len(L)
    c = [c_0] + [0] * (n - 1)

    H = H2(L, hash_func=hash_func)

    for i in range(n):
        z_1 = (G * s[i]) + (L[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = H1([L, Y, message, z_1, z_2], hash_func=hash_func)
        else:
            return c_0 == H1([L, Y, message, z_1, z_2], hash_func=hash_func)

    return False



def are_signatures_linked(signature1, signature2):
    # Check if the Y values (links) are the same
    return signature1[2] == signature2[2]

def check_culpability(SigningKey, L, signature_c1, hash_func=hashlib.sha256):
    H = H2(L, hash_func=hash_func)
    Y =  H * SigningKey
    return Y == signature_c1


def threshold_signature(signers, threshold, message, public_keys, G=SECP256k1.generator, hash_func=hashlib.sha256):
    """ Generate a threshold signature """
    assert len(signers) >= threshold, "Not enough signers to meet the threshold"
    signatures = [ring_signature(signers[i], i, message, public_keys, G, hash_func) for i in range(threshold)]
    return signatures
def verify_threshold_signature(signatures, message, public_keys, G=SECP256k1.generator, hash_func=hashlib.sha256):
    """ Verify a threshold signature """
    for signature in signatures:
        if not verify_ring_signature(message, public_keys, *signature, G, hash_func):
            return False
    return True
def are_signatures_threshold_linked(threshold_signatures1, threshold_signatures2):
    # Check if the Y values (links) are the same
    signatures_threshold_linked = True
    num = 0
    for threshold_signature1 in threshold_signatures1:
        num = num + 1
    for i in range(0, num):
        if threshold_signatures1[i][2] != threshold_signatures2[i][2]:
            signatures_threshold_linked = False

    return signatures_threshold_linked


def main():
    number_participants = 10

    # Generate private and public keys
    x = [randrange(SECP256k1.order) for i in range(number_participants)]
    L = list(map(lambda xi: SECP256k1.generator * xi, x))

    # Display generated keys and plot the curve with public keys
    print("Private keys (x):")
    for idx, key in enumerate(x):
        print("Key {}: {}".format(idx, key))
    print("\nPublic keys (L):")
    for idx, key in enumerate(L):
        print("Key {}: ({}, {})".format(idx, key.x(), key.y()))

    # Define a message
    message1 = "Every move we made was a kiss"
    message2 = "Different message for linkability test"

    # Choose a signer
    signer_index = 2
    signature1 = ring_signature(x[signer_index], signer_index, message1, L)
    signature2 = ring_signature(x[signer_index], signer_index, message2, L)  # Same signer, different message

    # Display the signatures
    print("\nGenerated Signature for Message 1:")
    print("c_0:", signature1[0])
    print("s (randomness vector):", signature1[1])
    print("Y (Link):", signature1[2])

    print("\nGenerated Signature for Message 2:")
    print("c_0:", signature2[0])
    print("s (randomness vector):", signature2[1])
    print("Y (Link):", signature2[2])

    # Verify the signatures
    verification_result1 = verify_ring_signature(message1, L, *signature1)
    verification_result2 = verify_ring_signature(message2, L, *signature2)
    print("\nVerification Result for Message 1:", verification_result1)
    print("Verification Result for Message 2:", verification_result2)

    # Verify the signatures
    verification_result3 = verify_ring_signature(message2, L, *signature1)
    print("\nVerification Result for Message 2 Using Signature 1:", verification_result3)

    # Check if signatures are linked
    linked = are_signatures_linked(signature1, signature2)
    print("\nLinkability Check:")
    print("Are signatures from the same signer linked? :", "Yes" if linked else "No")


    # Check  Culpability
    Culpability1 =  check_culpability(x[signer_index], L, signature1[2])
    print("\nCheck  Culpability:")
    print("Can the investigator conduct that the authorship of the signature belongs to user i.? :", "Yes" if Culpability1 else "No")


    threshold = 3  # 定义需要的阈值为3

    message1 = "Threshold test message 1"
    message2 = "Threshold test message 2"
    selected_signers = x[:threshold]

    # Generate and verify threshold signatures
    threshold_signatures1 = threshold_signature(selected_signers, threshold, message1, L)
    print("\nGenerated Threshold Signatures:")
    # print(threshold_signatures1)
    print("[", end="")
    q = 0
    for p in threshold_signatures1:
        print("(" + str(p[0]) + "," + str(p[1]) + "," + str(p[2]) + ")", end="")
        if q < threshold - 1:
            print(",", end="")
        q += 1
    print("]")

    threshold_signatures2 = threshold_signature(selected_signers, threshold, message2, L)
    print("\nGenerated Threshold Signatures:")
    # print(threshold_signatures2)
    print("[", end="")
    q = 0
    for p in threshold_signatures2:
        print("(" + str(p[0]) + "," + str(p[1]) + "," + str(p[2]) + ")", end="")
        if q < threshold - 1:
            print(",", end="")
        q += 1
    print("]")

    verification_result1 = verify_threshold_signature(threshold_signatures1, message1, L)
    print("\nVerification Result of Threshold Signature:", "Valid" if verification_result1 else "Invalid")

    verification_result2 = verify_threshold_signature(threshold_signatures2, message2, L)
    print("\nVerification Result of Threshold Signature:", "Valid" if verification_result2 else "Invalid")


    linked_threshold = are_signatures_threshold_linked(threshold_signatures1, threshold_signatures2)
    print("\nLinkability Check:")
    print("Are signatures from the same signer group linked? :", "Yes" if linked_threshold else "No")

if __name__ == '__main__':
    main()

