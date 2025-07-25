# Cryptography - Topics Overview

## Topic Explanation
Cryptography is the practice of securing communication and data through encoding techniques that allow only authorized parties to access information. This module covers symmetric and asymmetric encryption, digital signatures, hash functions, key management, cryptographic protocols, and common cryptographic attacks. Understanding cryptography is essential for implementing secure communications, protecting data integrity, and ensuring authentication and non-repudiation in cybersecurity applications.

## Articles for Further Reference
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Applied Cryptography by Bruce Schneier](https://www.schneier.com/books/applied-cryptography/)
- [Cryptography Engineering by Ferguson, Schneier, and Kohno](https://www.schneier.com/books/cryptography-engineering/)

## Reference Links
- [Cryptography.io Python Library](https://cryptography.io/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

## Available Tools for the Topic

### Tool Name: OpenSSL
**Description:** Robust, full-featured toolkit for general-purpose cryptography and secure communication.

**Example Usage:**
```bash
# Generate RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt/decrypt files
openssl rsautl -encrypt -pubin -inkey public.pem -in plaintext.txt -out ciphertext.bin
openssl rsautl -decrypt -inkey private.pem -in ciphertext.bin -out decrypted.txt

# Generate hash
echo "Hello World" | openssl dgst -sha256

# Create digital signature
openssl dgst -sha256 -sign private.pem -out signature.bin plaintext.txt
```

### Tool Name: John the Ripper
**Description:** Password cracking tool that can break various encryption and hashing algorithms.

**Example Usage:**
```bash
# Crack password hashes
john --wordlist=rockyou.txt hashes.txt

# Crack with specific format
john --format=MD5 hashes.txt

# Show cracked passwords
john --show hashes.txt
```

## All Possible Payloads for Manual Approach

### Cryptographic Attack Techniques
```python
# Caesar cipher implementation
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# Frequency analysis for substitution ciphers
def frequency_analysis(ciphertext):
    freq = {}
    for char in ciphertext.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    return sorted_freq

# Simple XOR encryption/decryption
def xor_encrypt_decrypt(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
```

### Hash Function Attacks
```python
import hashlib
import itertools

def hash_collision_attack(target_hash, charset="abcdefghijklmnopqrstuvwxyz", max_length=4):
    """Brute force hash collision attack"""
    for length in range(1, max_length + 1):
        for combination in itertools.product(charset, repeat=length):
            candidate = ''.join(combination)
            candidate_hash = hashlib.md5(candidate.encode()).hexdigest()
            
            if candidate_hash == target_hash:
                return candidate
    return None

def rainbow_table_attack(hash_list, precomputed_table):
    """Rainbow table attack simulation"""
    results = {}
    for hash_value in hash_list:
        if hash_value in precomputed_table:
            results[hash_value] = precomputed_table[hash_value]
    return results
```

## Example Payloads

### Comprehensive Cryptography Analysis Tool
```python
#!/usr/bin/env python3
import hashlib
import itertools
import string
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class CryptographyAnalyzer:
    def __init__(self):
        self.results = {}
    
    def analyze_hash(self, hash_value):
        """Analyze and attempt to crack hash"""
        print(f"Analyzing hash: {hash_value}")
        
        # Identify hash type
        hash_type = self.identify_hash_type(hash_value)
        print(f"Likely hash type: {hash_type}")
        
        # Attempt dictionary attack
        cracked = self.dictionary_attack(hash_value, hash_type)
        if cracked:
            print(f"Hash cracked: {cracked}")
            return cracked
        
        # Attempt brute force (limited)
        cracked = self.brute_force_attack(hash_value, hash_type, max_length=4)
        if cracked:
            print(f"Hash cracked via brute force: {cracked}")
            return cracked
        
        print("Hash not cracked")
        return None
    
    def identify_hash_type(self, hash_value):
        """Identify hash type based on length and format"""
        length = len(hash_value)
        
        if length == 32 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            return 'MD5'
        elif length == 40 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            return 'SHA1'
        elif length == 64 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            return 'SHA256'
        elif length == 128 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            return 'SHA512'
        else:
            return 'Unknown'
    
    def dictionary_attack(self, target_hash, hash_type):
        """Perform dictionary attack on hash"""
        common_passwords = [
            "password", "123456", "password123", "admin", "letmein",
            "welcome", "monkey", "1234567890", "qwerty", "abc123"
        ]
        
        hash_func = self.get_hash_function(hash_type)
        if not hash_func:
            return None
        
        for password in common_passwords:
            computed_hash = hash_func(password.encode()).hexdigest()
            if computed_hash.lower() == target_hash.lower():
                return password
        
        return None
    
    def brute_force_attack(self, target_hash, hash_type, max_length=4):
        """Perform limited brute force attack"""
        hash_func = self.get_hash_function(hash_type)
        if not hash_func:
            return None
        
        charset = string.ascii_lowercase + string.digits
        
        for length in range(1, max_length + 1):
            for combination in itertools.product(charset, repeat=length):
                candidate = ''.join(combination)
                computed_hash = hash_func(candidate.encode()).hexdigest()
                
                if computed_hash.lower() == target_hash.lower():
                    return candidate
        
        return None
    
    def get_hash_function(self, hash_type):
        """Get hash function based on type"""
        hash_functions = {
            'MD5': hashlib.md5,
            'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256,
            'SHA512': hashlib.sha512
        }
        return hash_functions.get(hash_type)
    
    def analyze_cipher(self, ciphertext):
        """Analyze unknown cipher"""
        print(f"Analyzing cipher: {ciphertext[:50]}...")
        
        # Check for Base64 encoding
        if self.is_base64(ciphertext):
            decoded = base64.b64decode(ciphertext)
            print(f"Base64 decoded: {decoded}")
        
        # Check for simple substitution cipher
        if ciphertext.isalpha():
            freq_analysis = self.frequency_analysis(ciphertext)
            print(f"Frequency analysis: {freq_analysis[:5]}")
            
            # Try Caesar cipher
            for shift in range(26):
                decrypted = self.caesar_decrypt(ciphertext, shift)
                if self.looks_like_english(decrypted):
                    print(f"Possible Caesar cipher (shift {shift}): {decrypted}")
        
        # Check for XOR cipher
        self.analyze_xor_cipher(ciphertext)
    
    def is_base64(self, text):
        """Check if text is Base64 encoded"""
        try:
            decoded = base64.b64decode(text)
            reencoded = base64.b64encode(decoded).decode()
            return reencoded == text
        except:
            return False
    
    def frequency_analysis(self, text):
        """Perform frequency analysis on text"""
        freq = {}
        for char in text.upper():
            if char.isalpha():
                freq[char] = freq.get(char, 0) + 1
        
        total = sum(freq.values())
        freq_percent = {char: (count/total)*100 for char, count in freq.items()}
        
        return sorted(freq_percent.items(), key=lambda x: x[1], reverse=True)
    
    def caesar_decrypt(self, ciphertext, shift):
        """Decrypt Caesar cipher with given shift"""
        result = ""
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def looks_like_english(self, text):
        """Simple heuristic to check if text looks like English"""
        common_words = ['THE', 'AND', 'TO', 'OF', 'A', 'IN', 'IS', 'IT', 'YOU', 'THAT']
        text_upper = text.upper()
        
        word_count = sum(1 for word in common_words if word in text_upper)
        return word_count >= 2
    
    def analyze_xor_cipher(self, ciphertext):
        """Analyze potential XOR cipher"""
        if all(c in '0123456789abcdefABCDEF' for c in ciphertext):
            # Hex encoded ciphertext
            try:
                cipher_bytes = bytes.fromhex(ciphertext)
                
                # Try common single-byte XOR keys
                for key in range(256):
                    decrypted = bytes([b ^ key for b in cipher_bytes])
                    try:
                        decoded_text = decrypted.decode('ascii')
                        if self.looks_like_english(decoded_text):
                            print(f"Possible XOR key {key}: {decoded_text}")
                    except:
                        pass
            except:
                pass
    
    def rsa_attack_simulation(self, n, e, ciphertext):
        """Simulate basic RSA attacks"""
        print(f"RSA Attack - n: {n}, e: {e}")
        
        # Check for small factors (toy example)
        factors = self.trial_division(n, 1000)
        if len(factors) > 1:
            print(f"Small factors found: {factors}")
            p, q = factors[0], factors[1]
            
            # Calculate private key
            phi_n = (p - 1) * (q - 1)
            d = self.mod_inverse(e, phi_n)
            
            # Decrypt
            plaintext = pow(ciphertext, d, n)
            print(f"Decrypted: {plaintext}")
            return plaintext
        
        print("No small factors found")
        return None
    
    def trial_division(self, n, limit):
        """Trial division factorization"""
        factors = []
        d = 2
        
        while d * d <= n and d <= limit:
            while n % d == 0:
                factors.append(d)
                n //= d
            d += 1
        
        if n > 1:
            factors.append(n)
        
        return factors
    
    def mod_inverse(self, a, m):
        """Calculate modular inverse using extended Euclidean algorithm"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            return None
        return (x % m + m) % m
    
    def generate_report(self):
        """Generate cryptography analysis report"""
        print("\n" + "="*60)
        print("CRYPTOGRAPHY ANALYSIS REPORT")
        print("="*60)
        
        if self.results:
            for analysis_type, result in self.results.items():
                print(f"{analysis_type}: {result}")
        
        print("\nCryptography Security Recommendations:")
        recommendations = [
            "Use strong, modern encryption algorithms (AES-256, RSA-2048+)",
            "Implement proper key management practices",
            "Use secure random number generation",
            "Avoid deprecated algorithms (MD5, SHA1, DES)",
            "Implement proper salt for password hashing",
            "Use authenticated encryption modes",
            "Regular cryptographic security assessments",
            "Keep cryptographic libraries updated"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")

# Example usage
analyzer = CryptographyAnalyzer()

# Analyze hash
hash_to_crack = "5d41402abc4b2a76b9719d911017c592"  # MD5 hash of "hello"
analyzer.analyze_hash(hash_to_crack)

# Analyze cipher
cipher_text = "KHOOR ZRUOG"  # Caesar cipher
analyzer.analyze_cipher(cipher_text)

# Base64 analysis
b64_text = "SGVsbG8gV29ybGQ="  # "Hello World" in Base64
analyzer.analyze_cipher(b64_text)

analyzer.generate_report()
```