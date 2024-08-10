import hashlib
import functools
import ecdsa
from ecdsa.util import randrange
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa import numbertheory


def Map2Curve(x, P=curve_secp256k1.p()):
    """Map an integer x to a point on the SECP256k1 curve."""
    x -= 1
    found = False

    while not found:
        x += 1
        f_x = (x * x * x + 7) % P

        try:
            y = numbertheory.square_root_mod_prime(f_x, P)
            found = True
        except Exception:
            pass

    return ecdsa.ellipticcurve.Point(curve_secp256k1, x, y)

def H1(msg, hash_func=hashlib.sha256):
    """Hash the message and convert to an integer."""
    return int('0x' + hash_func(Concat(msg)).hexdigest(), 16)

def H2(msg, hash_func=hashlib.sha256):
    """Hash the message and map to a curve point."""
    return Map2Curve(H1(msg, hash_func=hash_func))

def Concat(params):
    """Concatenate various types of parameters into bytes."""
    bytes_value = []

    for param in params:
        if isinstance(param, int):
            bytes_value.append(param.to_bytes(32, 'big'))
        elif isinstance(param, list):
            bytes_value.append(Concat(param))
        elif isinstance(param, ecdsa.ellipticcurve.Point):
            bytes_value.append(param.x().to_bytes(32, 'big') + param.y().to_bytes(32, 'big'))
        elif isinstance(param, str):
            bytes_value.append(param.encode())
        else:
            # Fallback case (shouldn't be reached with current inputs)
            bytes_value.append(param.x().to_bytes(32, 'big') + param.y().to_bytes(32, 'big'))

    # Use functools.reduce to concatenate the list of byte values
    return functools.reduce(lambda x, y: x + y, bytes_value)

def StringifyPoint(p):
    """Convert an elliptic curve point to a string format."""
    return '{},{}'.format(p.x(), p.y())

def RingSignature(SigningKey, key_idx, M, L, G=SECP256k1.generator, hash_func=hashlib.sha256):
    """Generate a ring signature for a message using a signing key and a list of public keys."""
    n = len(L)
    c = [0] * n
    s = [0] * n

    # STEP 1: Compute the link (Y)
    H = H2(L, hash_func=hash_func)
    Y = H * SigningKey

    # STEP 2: Generate the first challenge
    u = randrange(SECP256k1.order)
    c[(key_idx + 1) % n] = H1([L, Y, M, G * u, H * u], hash_func=hash_func)

    # STEP 3: Generate the rest of the challenges and responses
    for i in range(key_idx + 1, key_idx + n):
        j = i % n
        s[j] = randrange(SECP256k1.order)

        z_1 = (G * s[j]) + (L[j] * c[j])
        z_2 = (H * s[j]) + (Y * c[j])

        c[(j + 1) % n] = H1([L, Y, M, z_1, z_2], hash_func=hash_func)

    # STEP 4: Compute the final response
    s[key_idx] = (u - SigningKey * c[key_idx]) % SECP256k1.order
    return c[0], s, Y

def VerifyRingSignature(message, L, c_0, s, Y, G=SECP256k1.generator, hash_func=hashlib.sha256):
    """Verify a ring signature for a message given the public keys and signature components."""
    n = len(L)
    c = [c_0] + [0] * (n - 1)

    H = H2(L, hash_func=hash_func)

    for i in range(n):
        z_1 = (G * s[i]) + (L[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        # Compute the next challenge or verify the final challenge
        next_c = H1([L, Y, message, z_1, z_2], hash_func=hash_func)
        if i < n - 1:
            c[i + 1] = next_c
        else:
            return c_0 == next_c

    return False

def SignaturesLinkability(signature1, signature2):
    """Check if two signatures are linked by comparing their Y values."""
    return signature1[2] == signature2[2]

def CheckCulpability(SigningKey, L, signature_c1, hash_func=hashlib.sha256):
    """Check if a given signing key is responsible for generating a specific link (Y)."""
    H = H2(L, hash_func=hash_func)
    Y = H * SigningKey
    return Y == signature_c1



def ThresholdSignature(signers, threshold, message, public_keys, G=SECP256k1.generator, hash_func=hashlib.sha256):
    """Generate a threshold signature using a subset of signers."""
    assert len(signers) >= threshold, "Not enough signers to meet the threshold"
    return [RingSignature(signers[i], i, message, public_keys, G, hash_func) for i in range(threshold)]

def VerifyThresholdSignature(signatures, message, public_keys, G=SECP256k1.generator, hash_func=hashlib.sha256):
    """Verify a threshold signature by checking all individual signatures."""
    return all(VerifyRingSignature(message, public_keys, *signature, G, hash_func) for signature in signatures)

def SignaturesThresholdLinked(ThresholdSignatures1, ThresholdSignatures2):
    """Check if two threshold signatures are linked by comparing their Y values."""
    return all(sig1[2] == sig2[2] for sig1, sig2 in zip(ThresholdSignatures1, ThresholdSignatures2))


def DisplayKeys(title, keys):
    """Display private or public keys."""
    print(f"\n{title}:")
    for idx, key in enumerate(keys):
        if hasattr(key, 'x') and hasattr(key, 'y'):
            print(f"Key {idx}: ({key.x()}, {key.y()})")
        else:
            print(f"Key {idx}: {key}")

def DisplaySignature(signature, message_num):
    """Display the details of the generated signature."""
    print(f"\nGenerated Signature for Message {message_num}:")
    print("c_0:", signature[0])
    print("s (randomness vector):", signature[1])
    print("Y (Link):", signature[2])

def VerifySignature(message, L, signature, message_num, signature_num=None):
    """Verify the signature and display the result."""
    result = VerifyRingSignature(message, L, *signature)
    if signature_num is not None:
        print(f"\nVerification Result for Message {message_num} Using Signature {signature_num}:", result)
    else:
        print(f"\nVerification Result for Message {message_num}:", result)
    return result

def DisplayThresholdSignatures(threshold_signatures, threshold):
    """Display the threshold signatures."""
    print("\nGenerated Threshold Signatures:")
    print("[", end="")
    for idx, p in enumerate(threshold_signatures):
        print(f"({p[0]}, {p[1]}, {p[2]})", end="")
        if idx < threshold - 1:
            print(",", end="")
    print("]")

def main():
    number_participants = 10

    # Generate private and public keys
    x = [randrange(SECP256k1.order) for i in range(number_participants)]
    L = [SECP256k1.generator * xi for xi in x]

    # Display generated keys
    DisplayKeys("Private keys (x)", x)
    DisplayKeys("Public keys (L)", L)

    # Define messages
    message1 = "Every move we made was a kiss"
    message2 = "Different message for linkability test"

    # Choose a signer
    signer_index = 2
    signature1 = RingSignature(x[signer_index], signer_index, message1, L)
    signature2 = RingSignature(x[signer_index], signer_index, message2, L)

    # Display the signatures
    DisplaySignature(signature1, 1)
    DisplaySignature(signature2, 2)

    # Verify the signatures
    VerifySignature(message1, L, signature1, 1)
    VerifySignature(message2, L, signature2, 2)
    VerifySignature(message2, L, signature1, 2, signature_num=1)

    # Check if signatures are linked
    linked = SignaturesLinkability(signature1, signature2)
    print("\nLinkability Check:")
    print("Are signatures from the same signer linked? :", "Yes" if linked else "No")

    # Check culpability
    culpability = CheckCulpability(x[signer_index], L, signature1[2])
    print("\nCheck Culpability:")
    print("Can the investigator conclude that the authorship of the signature belongs to user i? :", "Yes" if culpability else "No")

    threshold = 3  # Define the required threshold as 3

    # Define threshold messages
    message1 = "Threshold test message 1"
    message2 = "Threshold test message 2"
    selected_signers = x[:threshold]

    # Generate and verify threshold signatures
    threshold_signatures1 = ThresholdSignature(selected_signers, threshold, message1, L)
    DisplayThresholdSignatures(threshold_signatures1, threshold)

    threshold_signatures2 = ThresholdSignature(selected_signers, threshold, message2, L)
    DisplayThresholdSignatures(threshold_signatures2, threshold)

    verify_threshold1 = VerifyThresholdSignature(threshold_signatures1, message1, L)
    print("\nVerification Result of Threshold Signature:", "Valid" if verify_threshold1 else "Invalid")

    verify_threshold2 = VerifyThresholdSignature(threshold_signatures2, message2, L)
    print("\nVerification Result of Threshold Signature:", "Valid" if verify_threshold2 else "Invalid")

    linked_threshold = SignaturesThresholdLinked(threshold_signatures1, threshold_signatures2)
    print("\nLinkability Check:")
    print("Are signatures from the same signer group linked? :", "Yes" if linked_threshold else "No")

if __name__ == '__main__':
    main()

