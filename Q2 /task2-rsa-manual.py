"""
Q2: Manual RSA encryption and decryption of a student ID

LECTORIAL CODE REFERENCES
Lectorial 5 - rsa_file.py
    We only used one thing from this lectorial code
      - the BASE = os.path.dirname(os.path.abspath(__file__)) line, which
        makes the file paths work on all operating systems. All of our
        folder and file paths (input, keys and output) are built from BASE
        using os.path.join.

The rest of the program was written by us and does not come from the
lectorial code. This includes the prime number validation, calculating
n and phi(n), choosing e, calculating d with a modular inverse, and
the manual RSA encryption and decryption using pow().
"""
import os

# Making sure the file path is able to work on all os
BASE = os.path.dirname(os.path.abspath(__file__))

# Folder paths built from BASE so they work on any operating system
input_dir = os.path.join(BASE, 'input')
keys_dir = os.path.join(BASE, 'keys')
output_dir = os.path.join(BASE, 'output')

# Create each folder if it does not already exist
os.makedirs(input_dir, exist_ok=True)
os.makedirs(keys_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

# Determine if the current number is a prime
def is_prime(n):
    # Numbers less than 2 are not prime
    if n < 2:
        return False
    
    # Check numbers from 2 up to the square root of n
    for i in range(2, int(pow(n,0.5)) + 1):
        # If n divides evenly by i, it is not prime
        if n % i == 0:
            return False
        
    # No factors were found, so n is prime   
    return True

# Validating first prime value p, must be at least 5 digits
while True:
    try:
        # FOR TESTING PURPOSES PLEASE ENTER IN THIS NUMBER
        # 10007
        p = int(input("Enter a prime number p (5 or more digits): "))
        
        # If p is less than 5 digits then error message
        if len(str(p)) < 5:
            print("Error: The number must have at least 5 digits.")  
        # If p is not prime then error message  
        elif not is_prime(p):
            print("Error: The number is not prime.")
        # Print valid prime p
        else:
            print("Valid prime number:", p)
            break

    # Anything but a valid number then error message
    except ValueError:
        print("Error: Please enter a whole number.")

# Validating second prime value q, must be at least 5 digits
while True:
    try:
        # FOR TESTING PURPOSES PLEASE ENTER IN THIS NUMBER
        # 10009
        q = int(input("Enter prime number q (5 or more digits): "))

        # If q is less than 5 digits then error message
        if len(str(q)) < 5:
            print("Error: The number must have at least 5 digits.")  
        # If q is not prime then error message  
        elif not is_prime(q):
            print("Error: The number is not prime.")
        # Making sure p and q are not the same
        elif q == p:
            print("q must be different from p.")
        # Print valid prime q
        else:
            print("Valid prime number:", q)
            break

    # Anything but a valid number then error message
    except ValueError:
        print("Error: Please enter a whole number.")

# Showing final output of p and q
print("p =", p)
print("q =", q)

# Calculating modulus n and n-totient
n = p * q
ntotient = (p-1)*(q-1)

# Showing final n and n-totient:
print("n =", n)
print("phi(n) =", ntotient)

# Finding the greatest common divisor of two numbers
def gcd(a, b):
    while b != 0:
        remainder = a % b
        a = b
        b = remainder

    return a

def is_valid_e(e, ntotient):
    # Check if e is valid for the RSA key
    return 1 < e < ntotient and gcd(e, ntotient) == 1

# Validating public exponent e, must be between 1 and n-totient and share no factors with n-totient
while True:
    try:
        # FOR TESTING PURPOSES PLEASE ENTER IN THIS NUMBER
        # 65537
        e = int(input("Please enter a valid e: "))

        if is_valid_e(e, ntotient):
            print("Public exponent e:", e, "with gcd(e, phi(n)) = 1")
            break
        else:
            print("Invalid e. Must be 1 < e < phi(n) and gcd(e, phi(n)) = 1")

    # Anything but a valid number then error message
    except ValueError:
        print("Please enter a whole number.")

# Solving private exponent d, doing modular inverse multiplication 
def mod_inverse(e, ntotient):
    return pow(e, -1, ntotient)

d = mod_inverse(e, ntotient)
print("Private exponent d:", d)

# Must print 1 
print("Check: (e * d) mod phi(n) =", (e * d) % ntotient)

# Validating user plaintext, must be 7 digits of student ID without s
while True:
    try:
        # FOR TESTING PURPOSES PLEASE ENTER IN THIS NUMBER
        # STUDENT ID#1: 4167085 
        # STUDENT ID#2: 4169495
        user_input_msg = int(input("Enter valid student ID: "))

        if len(str(user_input_msg)) < 7:
            print("Student ID must have 7 or more digits.")
        elif user_input_msg >= n:
            print("Message must be smaller than n.")
        else:
            break

    except ValueError:
        print("Please enter a whole number.")

# Save the plaintext message to the input folder
with open(os.path.join(input_dir, 'task2_message.txt'), 'w') as f:
    f.write(str(user_input_msg))

# Save the public key (e, n) and private key (d, n) to separate files
with open(os.path.join(keys_dir, 'public_key.txt'), 'w') as f:
    f.write(f"e = {e}\nn = {n}\n")

with open(os.path.join(keys_dir, 'private_key.txt'), 'w') as f:
    f.write(f"d = {d}\nn = {n}\n")

# Displaying public and private keys
print("Public key (e, n) =", (e, n))
print("Private key (d, n) =", (d, n))

# Encrypt: c = m^e mod n
ciphertext = pow(user_input_msg, e, n)
print("Ciphertext =", ciphertext)

with open(os.path.join(output_dir, 'task2_ciphertext.txt'), 'w') as f:
    f.write(str(ciphertext))

# Decrypt: m = c^d mod n
recovered_plaintext = pow(ciphertext, d, n)
print("Recovered plaintext =", recovered_plaintext)

with open(os.path.join(output_dir, 'task2_decrypted.txt'), 'w') as f:
    f.write(str(recovered_plaintext))

# Confirming that the recovered plaintext is the same
print("Match:", recovered_plaintext == user_input_msg)