from PIL import Image
import numpy as np

print("------------- Image Encryption Tool --------------")

def encrypt_image(image_path, key):
    # Opening the image
    original_image = Image.open(image_path)

    # Converting the image to a NumPy array
    image_array = np.array(original_image)

    # Applying a more complex mathematical operation to each pixel using the key
    encrypted_image_array = (image_array * key) // (key + 1)

    # Creating a new image from the encrypted NumPy array
    encrypted_image = Image.fromarray(np.uint8(encrypted_image_array))

    # Saving the encrypted image
    encrypted_image_path = "encrypted_image.png"
    encrypted_image.save(encrypted_image_path)
    print(f"Image encrypted successfully. Encrypted image saved at: {encrypted_image_path}")
    exit()
import re
import getpass

print("---------------- Password Complexity Checking Tool -----------------")

def assess_password_strength(password):
    # Checking criteria
    has_numbers = any(char.isdigit() for char in password)
    has_upper_lower_case = any(char.isupper() or char.islower() for char in password)
    meets_length_requirement = len(password) >= 8
    has_special_characters = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

    # Counts the number of met criteria
    met_criteria_count = sum([has_numbers, has_upper_lower_case, meets_length_requirement, has_special_characters])

    # Classifies the password based on the number of met criteria
    if met_criteria_count == 4:
        return "Password Strength Level: Very Strong (All criteria are met)."
    elif met_criteria_count == 3:
        return "Password Strength Level: Moderately Strong (Any 3 criteria are met)."
    elif met_criteria_count == 2:
        return "Password Strength Level: Strong (Any 2 criteria are met)."
    else:
        return "Password Strength Level: Weak (None or only one criterion is met)."

# Gets user input for the password without displaying it on the screen
password_input = getpass.getpass("Enter your password: ")

# Displayed characters as '#' except for the first and last character
masked_password = password_input[0] + '#' * (len(password_input) - 2) + password_input[-1]

# Assesses the password strength
result = assess_password_strength(password_input)

# Provides more specific feedback to the user
print("Entered Password: {}".format(masked_password))
print("")
print(result)
print("")
tips = [
    "Here are some quick tips for creating a secure password:",
    "1. Length: Aim for at least 12 characters.",
    "2. Mix Characters: Use a combination of uppercase, lowercase, numbers, and symbols.",
    "3. Avoid Common Words: Don't use easily guessable information.",
    "4. No Personal Info: Avoid using names, birthdays, or personal details.",
    "5. Use Passphrases: Consider combining multiple words or a sentence.",
    "6. Unique for Each Account: Don't reuse passwords across multiple accounts.",
    "7. Regular Updates: Change passwords periodically.",
    "8. Enable 2FA: Use Two-Factor Authentication where possible.",
    "9. Be Wary of Phishing: Avoid entering passwords on suspicious sites.",
    "10. Password Manager: Consider using one for secure and unique passwords."
]

# Displays the tips
for tip in tips:
    print(tip)

def decrypt_image(encrypted_image_path, key):
    # Opening the encrypted image
    encrypted_image = Image.open(encrypted_image_path)

    # Converting the image to a NumPy array
    encrypted_image_array = np.array(encrypted_image)

    # Reversing the more complex encryption using the key
    decrypted_image_array = (encrypted_image_array * (key + 1)) // key

    # Clipping values to ensure they are in the valid pixel value range
    decrypted_image_array = np.clip(decrypted_image_array, 0, 255)

    # Creating a new image from the decrypted NumPy array
    decrypted_image = Image.fromarray(np.uint8(decrypted_image_array))

    # Saving the decrypted image
    decrypted_image_path = "decrypted_image.png"
    decrypted_image.save(decrypted_image_path)
    print(f"Image decrypted successfully. Decrypted image saved at: {decrypted_image_path}")
    exit()

def main():
    while True:
        print("Select an option:")
        print("e - Encrypt image")
        print("d - Decrypt image")
        print("q - Quit")
        choice = input("Your choice: ")

        if choice == 'e':
            encrypt_choice()
        elif choice == 'd':
            decrypt_choice()
        elif choice == 'q':
            print("Exitting the program.")
            exit()
        else:
            print("Invalid choice. Please choose 'e' for encryption, 'd' for decryption, or 'q' to quit.")

def encrypt_choice():
    key = int(input("Enter encryption key: "))
    image_location = input("Enter the location or URL of the image: ")

    try:
        encrypt_image(image_location, key)
    except FileNotFoundError:
        print("Invalid location. Image not found. Please try again.")
        encrypt_choice()

def decrypt_choice():
    key = int(input("Enter decryption key: "))
    encrypted_image_location = input("Enter the location of the encrypted image: ")

    try:
        decrypt_image(encrypted_image_location, key)
    except FileNotFoundError:
        print("Invalid location. Encrypted image not found. Please try again.")
        decrypt_choice()

if __name__ == "__main__":
    main()
