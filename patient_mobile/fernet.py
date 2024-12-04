from cryptography.fernet import Fernet

# Generate a secret key
secret_key = Fernet.generate_key()

# Print the generated key
print(f"Your generated secret key is: {secret_key}")

# b'603zgLcePQ9gH7Ja7y4IvuyTKbLNEgC3KqHv4IVFNlw='