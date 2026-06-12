def encrypt(text, shift):
    """Encrypt text using Caesar cipher with the given shift."""
    normalized_shift = shift % 26  # Normalize shift to 0-25 range
    result = []
    
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - ord('A') + normalized_shift) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + normalized_shift) % 26 + ord('a')))
        else:
            result.append(char)
    
    return ''.join(result)


def decrypt(text, shift):
    """Decrypt text by reversing the Caesar shift."""
    normalized_shift = shift % 26
    # Decryption shift = (26 - normalized_shift) % 26, which is the inverse
    return encrypt(text, 26 - normalized_shift if normalized_shift != 0 else 0)


def main():
    print("=== Caesar Cipher Encryption & Decryption ===\n")
    
    while True:
        print("Options:")
        print("  1. Encrypt text")
        print("  2. Decrypt text")
        print("  3. Exit")
        
        choice = input("\nEnter your choice (1/2/3): ").strip()
        
        if choice == '3':
            print("Goodbye!")
            break
        
        if choice not in ('1', '2'):
            print("Invalid choice. Please enter 1, 2, or 3.\n")
            continue
        
        text = input("Enter the text: ")
        if not text:
            print("No text entered. Please try again.\n")
            continue
        
        try:
            shift = int(input("Enter shift value (integer): "))
        except ValueError:
            print("Invalid shift value. Using default shift of 3.\n")
            shift = 3
        
        if choice == '1':
            encrypted = encrypt(text, shift)
            print(f"\nOriginal:  {text}")
            print(f"Encrypted: {encrypted}\n")
        else:
            decrypted = decrypt(text, shift)
            print(f"\nEncrypted:  {text}")
            print(f"Decrypted:  {decrypted}\n")


if __name__ == "__main__":
    main()