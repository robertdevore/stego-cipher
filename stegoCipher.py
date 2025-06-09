#!/usr/bin/env python3
"""
Custom Steganographic Cipher with Image Embedding
A tool for hiding secret messages within scrambled quotes and images.
"""

import random
import re
import sys
import os
from typing import List, Tuple

# Image processing (install with: pip install Pillow)
try:
    from PIL import Image
    IMAGE_SUPPORT = True
except ImportError:
    IMAGE_SUPPORT = False


class StegoCipher:
    """
    A steganographic cipher that hides secret messages within scrambled quotes
    and can embed the encrypted text into images.
    """
    
    def __init__(self):
        self.symbols = "!@#$%^&*()_+-={}[]:;,./?<>~`"
    
    def encrypt(self, quote: str, secret: str, with_symbols: bool = True) -> str:
        """Hide a secret message within a scrambled quote."""
        if not quote or not secret:
            raise ValueError("Both quote and secret message are required")
        
        words = self._clean_quote(quote)
        
        if len(secret) > len(words):
            raise ValueError(
                f"Secret message too long! Maximum {len(words)} characters "
                f"for this quote (you have {len(secret)})"
            )
        
        # Build the cipher
        cipher_parts = []
        for i, word in enumerate(words):
            # Add scrambled word
            scrambled = ''.join(random.sample(word, len(word)))
            cipher_parts.append(scrambled)
            
            # Add random symbols for obfuscation
            if with_symbols:
                symbol_count = random.randint(1, 3)
                symbols = ''.join(random.choices(self.symbols, k=symbol_count))
                cipher_parts.append(symbols)
            
            # Add secret character
            if i < len(secret):
                cipher_parts.append(secret[i])
        
        # Join and apply random capitalization
        cipher = ''.join(cipher_parts)
        return self._randomize_caps(cipher)
    
    def decrypt(self, cipher: str, original_quote: str, with_symbols: bool = True) -> str:
        """Extract the hidden message from a cipher."""
        words = self._clean_quote(original_quote)
        word_lengths = [len(word) for word in words]
        
        # Clean the cipher
        clean_cipher = cipher.lower()
        if with_symbols:
            clean_cipher = ''.join(c for c in clean_cipher if c not in self.symbols)
        
        # Extract secret characters
        secret_chars = []
        pos = 0
        
        for word_len in word_lengths:
            pos += word_len  # Skip the scrambled word
            if pos < len(clean_cipher):
                secret_chars.append(clean_cipher[pos])
                pos += 1
        
        return ''.join(secret_chars)
    
    def embed_in_image(self, image_path: str, cipher_text: str, output_path: str, debug: bool = False) -> None:
        """Embed cipher text into an image using LSB steganography."""
        if not IMAGE_SUPPORT:
            raise ImportError("PIL (Pillow) is required for image operations. Install with: pip install Pillow")
        
        # Check input format
        input_format = os.path.splitext(image_path)[1].lower()
        output_format = os.path.splitext(output_path)[1].lower()
        
        if debug:
            print(f"Input format: {input_format}")
            print(f"Output format: {output_format}")
        
        # Warn about lossy formats
        lossy_formats = ['.jpg', '.jpeg', '.webp']
        if input_format in lossy_formats or output_format in lossy_formats:
            print(f"⚠️  WARNING: {input_format}/{output_format} can be lossy and may corrupt hidden data!")
            print("   Recommended: Use PNG format for both input and output")
        
        # Open and convert image to RGB
        img = Image.open(image_path)
        img = img.convert('RGB')
        
        if debug:
            print(f"Image size: {img.width}x{img.height}")
            print(f"Cipher text: '{cipher_text}'")
            print(f"Cipher length: {len(cipher_text)} characters")
        
        # Convert cipher text to binary with header
        header = "STEGO:"  # Simple header to identify our data
        full_message = header + cipher_text
        binary_message = ''.join(format(ord(char), '08b') for char in full_message)
        binary_message += '1111111111111110'  # End delimiter
        
        if debug:
            print(f"Binary message length: {len(binary_message)} bits")
        
        # Check if image is large enough
        max_bits = img.width * img.height * 3  # 3 channels (RGB)
        if len(binary_message) > max_bits:
            raise ValueError(f"Image too small! Need {len(binary_message)} bits, but image only has {max_bits}")
        
        # Get pixel data
        pixels = list(img.getdata())
        new_pixels = []
        
        bit_index = 0
        for pixel in pixels:
            if bit_index < len(binary_message):
                # Modify each color channel's LSB
                new_pixel = []
                for channel in pixel:
                    if bit_index < len(binary_message):
                        # Clear LSB and set to message bit
                        new_channel = (channel & 0xFE) | int(binary_message[bit_index])
                        new_pixel.append(new_channel)
                        bit_index += 1
                    else:
                        new_pixel.append(channel)
                new_pixels.append(tuple(new_pixel))
            else:
                new_pixels.append(pixel)
        
        # Create and save new image - force PNG for lossless storage
        new_img = Image.new('RGB', img.size)
        new_img.putdata(new_pixels)
        
        # Force PNG extension if not already
        if not output_path.lower().endswith('.png'):
            output_path = os.path.splitext(output_path)[0] + '.png'
            print(f"💡 Auto-changed output to PNG format: {output_path}")
        
        new_img.save(output_path, 'PNG')
        
        if debug:
            print(f"Image saved successfully to {output_path}")
    
    def extract_from_image(self, image_path: str, debug: bool = False) -> str:
        """Extract hidden cipher text from an image."""
        if not IMAGE_SUPPORT:
            raise ImportError("PIL (Pillow) is required for image operations. Install with: pip install Pillow")
        
        img = Image.open(image_path)
        img = img.convert('RGB')
        
        if debug:
            print(f"Extracting from image: {image_path}")
            print(f"Image size: {img.width}x{img.height}")
        
        # Extract LSBs from all pixels
        binary_message = ""
        pixels = list(img.getdata())
        
        for pixel in pixels:
            for channel in pixel:
                binary_message += str(channel & 1)  # Get LSB
        
        if debug:
            print(f"Extracted {len(binary_message)} bits")
        
        # Find the delimiter and extract message
        delimiter = '1111111111111110'
        end_index = binary_message.find(delimiter)
        
        if end_index == -1:
            raise ValueError("No hidden message found in image (no end delimiter)")
        
        message_binary = binary_message[:end_index]
        
        if debug:
            print(f"Message binary length: {len(message_binary)} bits")
        
        # Convert binary to text
        if len(message_binary) % 8 != 0:
            # Pad with zeros if needed
            padding = 8 - (len(message_binary) % 8)
            message_binary = message_binary + '0' * padding
            if debug:
                print(f"Added {padding} padding bits")
        
        extracted_text = ""
        for i in range(0, len(message_binary), 8):
            byte = message_binary[i:i+8]
            try:
                char = chr(int(byte, 2))
                extracted_text += char
            except ValueError:
                if debug:
                    print(f"Invalid byte at position {i}: {byte}")
                continue
        
        if debug:
            print(f"Extracted text: '{extracted_text}'")
        
        # Check for our header
        header = "STEGO:"
        if extracted_text.startswith(header):
            cipher_text = extracted_text[len(header):]
            if debug:
                print(f"Header found, cipher text: '{cipher_text}'")
            return cipher_text
        else:
            # Try without header (backwards compatibility)
            if debug:
                print("No header found, returning full extracted text")
            return extracted_text
    
    def _clean_quote(self, quote: str) -> List[str]:
        """Extract clean words from quote."""
        words = []
        for word in quote.lower().split():
            clean_word = re.sub(r'[^a-z0-9]', '', word)
            if clean_word:
                words.append(clean_word)
        return words
    
    def _randomize_caps(self, text: str) -> str:
        """Apply random capitalization."""
        result = []
        for i, char in enumerate(text):
            if char.isalpha():
                if i == 0:
                    result.append(char.upper())
                else:
                    result.append(char.upper() if random.randint(0, 1) else char.lower())
            else:
                result.append(char)
        return ''.join(result)


def main():
    """Command-line interface for the cipher."""
    cipher = StegoCipher()
    
    print("🔐 Steganographic Cipher Tool with Image Embedding")
    print("=" * 55)
    
    if not IMAGE_SUPPORT:
        print("⚠️  Image features disabled. Install Pillow with: pip install Pillow")
    
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")  
        print("3. Example/Demo")
        if IMAGE_SUPPORT:
            print("4. Hide cipher in image")
            print("5. Extract cipher from image")
            print("6. Debug image extraction")
            print("7. Exit")
        else:
            print("4. Exit")
        
        max_choice = 7 if IMAGE_SUPPORT else 4
        choice = input(f"\nEnter choice (1-{max_choice}): ").strip()
        
        if choice == '1':
            encrypt_message(cipher)
        elif choice == '2':
            decrypt_message(cipher)
        elif choice == '3':
            show_demo(cipher)
        elif choice == '4' and IMAGE_SUPPORT:
            embed_in_image(cipher)
        elif choice == '5' and IMAGE_SUPPORT:
            extract_from_image(cipher)
        elif choice == '6' and IMAGE_SUPPORT:
            debug_image_extraction(cipher)
        elif choice == str(max_choice):
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please try again.")


def encrypt_message(cipher):
    """Handle message encryption."""
    print("\n📝 ENCRYPT A MESSAGE")
    print("-" * 20)
    
    quote = input("Enter cover quote: ").strip()
    if not quote:
        print("❌ Quote cannot be empty!")
        return
    
    secret = input("Enter secret message: ").strip()
    if not secret:
        print("❌ Secret message cannot be empty!")
        return
    
    symbols = input("Use random symbols for extra obfuscation? (y/n): ").strip().lower()
    use_symbols = symbols in ['y', 'yes']
    
    try:
        encrypted = cipher.encrypt(quote, secret, with_symbols=use_symbols)
        
        print(f"\n✅ SUCCESS!")
        print(f"📄 Original quote: {quote}")
        print(f"🔒 Secret message: {secret}")
        print(f"🎭 Encrypted cipher:")
        print(f"    {encrypted}")
        print(f"\n💡 Share the encrypted text above. Keep the original quote secret!")
        
    except ValueError as e:
        print(f"❌ Error: {e}")


def decrypt_message(cipher):
    """Handle message decryption."""
    print("\n🔓 DECRYPT A MESSAGE")
    print("-" * 20)
    
    encrypted = input("Enter encrypted cipher: ").strip()
    if not encrypted:
        print("❌ Encrypted text cannot be empty!")
        return
    
    quote = input("Enter original quote: ").strip()
    if not quote:
        print("❌ Original quote cannot be empty!")
        return
    
    symbols = input("Were symbols used during encryption? (y/n): ").strip().lower()
    used_symbols = symbols in ['y', 'yes']
    
    try:
        decrypted = cipher.decrypt(encrypted, quote, with_symbols=used_symbols)
        print(f"\n✅ SUCCESS!")
        print(f"🔓 Decrypted message: {decrypted}")
        
    except Exception as e:
        print(f"❌ Error during decryption: {e}")


def embed_in_image(cipher):
    """Handle embedding cipher in image."""
    print("\n🖼️  HIDE CIPHER IN IMAGE")
    print("-" * 25)
    
    cipher_text = input("Enter encrypted cipher text: ").strip()
    if not cipher_text:
        print("❌ Cipher text cannot be empty!")
        return
    
    input_image = input("Enter input image filename (in same folder): ").strip()
    if not input_image:
        print("❌ Image filename cannot be empty!")
        return
    
    if not os.path.exists(input_image):
        print(f"❌ Image file '{input_image}' not found!")
        return
    
    output_image = input("Enter output image filename (will be saved as PNG): ").strip()
    if not output_image:
        print("❌ Output filename cannot be empty!")
        return
    
    try:
        cipher.embed_in_image(input_image, cipher_text, output_image, debug=True)
        print(f"\n✅ SUCCESS!")
        print(f"🖼️  Cipher hidden in: {output_image}")
        print(f"💡 The image looks identical but contains your hidden cipher!")
        
    except Exception as e:
        print(f"❌ Error: {e}")


def extract_from_image(cipher):
    """Handle extracting cipher from image."""
    print("\n🔍 EXTRACT CIPHER FROM IMAGE")
    print("-" * 30)
    
    image_file = input("Enter image filename containing hidden cipher: ").strip()
    if not image_file:
        print("❌ Image filename cannot be empty!")
        return
    
    if not os.path.exists(image_file):
        print(f"❌ Image file '{image_file}' not found!")
        return
    
    try:
        extracted_cipher = cipher.extract_from_image(image_file, debug=False)
        print(f"\n✅ SUCCESS!")
        print(f"🔍 Extracted cipher text:")
        print(f"    {extracted_cipher}")
        print(f"\n💡 Now use option 2 to decrypt this cipher with the original quote!")
        
    except Exception as e:
        print(f"❌ Error: {e}")


def debug_image_extraction(cipher):
    """Debug mode for image extraction."""
    print("\n🐛 DEBUG IMAGE EXTRACTION")
    print("-" * 28)
    
    image_file = input("Enter image filename to debug: ").strip()
    if not image_file:
        print("❌ Image filename cannot be empty!")
        return
    
    if not os.path.exists(image_file):
        print(f"❌ Image file '{image_file}' not found!")
        return
    
    try:
        print("\nRunning extraction with debug output...")
        extracted_cipher = cipher.extract_from_image(image_file, debug=True)
        print(f"\n✅ EXTRACTED: '{extracted_cipher}'")
        
    except Exception as e:
        print(f"❌ Error: {e}")


def show_demo(cipher):
    """Show a working example."""
    print("\n🎬 DEMO - How It Works")
    print("-" * 25)
    
    quote = "The quick brown fox jumps over the lazy dog"
    secret = "hello world"
    
    print(f"📄 Cover Quote: {quote}")
    print(f"🔒 Secret Message: {secret}")
    
    # Encrypt
    random.seed(42)  # For consistent demo
    encrypted = cipher.encrypt(quote, secret, with_symbols=True)
    
    print(f"\n🎭 Encrypted Result:")
    print(f"    {encrypted}")
    print(f"    ^ This looks like random gibberish!")
    
    # Decrypt
    decrypted = cipher.decrypt(encrypted, quote, with_symbols=True)
    
    print(f"\n🔓 Decrypted Message: {decrypted}")
    print(f"✅ Perfect match: {secret == decrypted}")
    
    print(f"\n💡 How it works:")
    print(f"   • Each word from the quote gets scrambled")
    print(f"   • Letters from your secret are inserted between words")  
    print(f"   • Random symbols and capitalization add camouflage")
    print(f"   • Only someone with the original quote can decode it!")
    
    if IMAGE_SUPPORT:
        print(f"\n🖼️  Image Steganography:")
        print(f"   • Hide the encrypted cipher inside any image file")
        print(f"   • IMPORTANT: Use PNG format to avoid data corruption!")
        print(f"   • WebP/JPEG are lossy and may corrupt hidden data")
        print(f"   • Extract the cipher later from the image")
        print(f"   • Double-layer security: image + quote required!")


if __name__ == "__main__":
    main()
