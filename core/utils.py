def format_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1048576:
        return f"{size / 1024:.2f} KB"
    elif size < 1073741824:
        return f"{size / 1048576:.2f} MB"
    else:
        return f"{size / 1073741824:.2f} GB"
    
    
    
    
    

import os
from cryptography.fernet import InvalidToken, Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets


class Encryptor:
    """
    A secure file encryption/decryption utility using Fernet symmetric cryptography.

    Features:
    - File encryption/decryption with Fernet
    - Secure key management with master key encryption
    - PBKDF2 key derivation for additional security
    - Automatic key generation

    Typical usage:
    1. Initialize with or without a key
    2. Generate keys if needed (generate_secure_key())
    3. Encrypt/decrypt files as needed
    """

    def __init__(self, key=None, master_key=None):
        """
        Initialize the encryptor with optional existing keys.

        Args:
            key (str, optional): Either a raw Fernet key or an encrypted key
            master_key (str, optional): Master key for decrypting the encryption key.
                                        If not provided, will be fetched from Django settings.
        """
        self.master_key = master_key or self._get_master_key()
        # Ensure master_key is bytes
        if isinstance(self.master_key, str):
            self.master_key = self.master_key.encode()

        # Initialize key storage
        self.raw_key = None
        self.encrypted_key = None

        if key:
            if master_key:
                # Provided key is encrypted - decrypt and store both
                self.encrypted_key = key
                self.raw_key = self._decrypt_key(key)
            else:
                # Provided key is raw - store only raw key
                self.raw_key = key
                self.encrypted_key = None

    def _get_master_key(self):
        """
        Retrieve the master encryption key from Django settings.

        Returns:
            bytes: The master key

        Raises:
            ValueError: If master key is not configured
        """
        from django.conf import settings

        master_key = getattr(settings, "ENCRYPTION_MASTER_KEY", None)
        if not master_key:
            raise ValueError("Master key not configured in settings")
        return master_key.encode() if isinstance(master_key, str) else master_key

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """
        Derive a secure encryption key from a password using PBKDF2.

        Args:
            password (bytes): The master password
            salt (bytes): Random salt for key derivation

        Returns:
            bytes: Derived key in URL-safe base64
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Security parameter - high iteration count
            backend=default_backend(),
        )
        return urlsafe_b64encode(kdf.derive(password))

    def _encrypt_key(self, key: str) -> str:
        """
        Encrypt a Fernet key with the master key using PBKDF2 derivation.

        Args:
            key (str): Raw Fernet key to encrypt

        Returns:
            str: Encrypted key in format "salt:encrypted_key"
        """
        salt = secrets.token_bytes(16)  # Generate secure random salt
        derived_key = self._derive_key(self.master_key, salt)
        fernet = Fernet(derived_key)
        encrypted_key = fernet.encrypt(key.encode())
        return f"{urlsafe_b64encode(salt).decode()}:{encrypted_key.decode()}"

    def _decrypt_key(self, encrypted_key: str) -> str:
        """
        Decrypt an encrypted Fernet key using the master key.

        Args:
            encrypted_key (str): Key in "salt:encrypted_key" format

        Returns:
            str: Decrypted raw Fernet key

        Raises:
            InvalidToken: If decryption fails (wrong key or corrupted data)
        """
        try:
            salt, key = encrypted_key.split(":")
            salt = urlsafe_b64decode(salt.encode())
            derived_key = self._derive_key(self.master_key, salt)
            fernet = Fernet(derived_key)
            return fernet.decrypt(key.encode()).decode()
        except (ValueError, InvalidToken) as e:
            raise InvalidToken(f"Failed to decrypt key: {e}") from e

    def generate_secure_key(self) -> tuple:
        """
        Generate a new secure Fernet key pair.

        Returns:
            tuple: (raw_key, encrypted_key) where:
                - raw_key: The direct Fernet key
                - encrypted_key: Master-key encrypted version of raw_key
        """
        self.raw_key = Fernet.generate_key().decode()
        self.encrypted_key = self._encrypt_key(self.raw_key)
        return self.raw_key, self.encrypted_key

    def encrypt_file(self, file_name, output_file=None):
        """
        Encrypt a file using the current encryption key.

        Args:
            file_name (str): Path to file to encrypt
            output_file (str, optional): Output path. Defaults to input file + '.sealed'

        Returns:
            str: Path to the encrypted file

        Raises:
            KeyError: If no encryption key is available
            FileNotFoundError: If input file doesn't exist
        """
        if not self.raw_key:
            raise KeyError("No encryption key available")

        if not os.path.exists(file_name):
            raise FileNotFoundError(f"File not found: {file_name}")

        with open(file_name, "rb") as file:
            file_data = file.read()

        try:
            fernet = Fernet(self.raw_key.encode())
            encrypted_data = fernet.encrypt(file_data)
        except InvalidToken as e:
            raise KeyError(f"Invalid key: {e}") from e

        output_file = output_file or f"{file_name}.sealed"
        with open(output_file, "wb") as file:
            file.write(encrypted_data)

        return output_file

    def decrypt_file(self, file_name, output_file=None):
        """
        Decrypt a file using the current encryption key.

        Args:
            file_name (str): Path to encrypted file
            output_file (str, optional): Output path. Defaults to input file without extension

        Returns:
            bytes: The decrypted file data

        Raises:
            KeyError: If no decryption key is available
            FileNotFoundError: If input file doesn't exist
            InvalidToken: If decryption fails (wrong key or corrupted data)
        """
        if not self.raw_key:
            raise KeyError("No encryption key available")

        if not os.path.exists(file_name):
            raise FileNotFoundError(f"File not found: {file_name}")

        with open(file_name, "rb") as file:
            encrypted_data = file.read()

        try:
            fernet = Fernet(self.raw_key.encode())
            decrypted_data = fernet.decrypt(encrypted_data)
        except InvalidToken as e:
            raise InvalidToken(f"Invalid key: {e}") from e

        output_file = output_file or os.path.splitext(file_name)[0]
        with open(output_file, "wb") as file:
            file.write(decrypted_data)

        return decrypted_data

