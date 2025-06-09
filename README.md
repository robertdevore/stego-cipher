# 🔐 StegoCipher: A Steganographic Cipher + Image Hider in Python

StegoCipher is a custom steganographic tool that hides secret messages inside scrambled quotes and optionally embeds the result into images using LSB (Least Significant Bit) steganography. It's part encryption, part steganography - with a DIY spy-thriller twist.

## 🚀 Features

- **Quote-Based Cipher** - Hides your secret message inside a scrambled quote.
- **Obfuscation Layer** - Adds random symbols and capitalization to make detection harder.
- **Decrypt with Context** - Requires the original quote to decode the hidden message.
- **Image Embedding (Optional)** - Embed encrypted messages into PNG images for stealth storage.
- **Lossless Recovery** - Extract messages with full fidelity using LSB decoding.

## 🖼️ Use Case Example

You want to send a hidden message to a friend:

- Choose a famous quote like: `"The quick brown fox jumps over the lazy dog"`
- Hide your secret: `"meet at dawn"`
- Share the resulting cipher string with your friend
- Later, extract it from an image or decrypt it with the quote

## 🛠️ Installation

1. **Clone this repo**
    
```bash
git clone https://github.com/your-username/stego-cipher.git
cd stego-cipher
```

2. **Install dependencies**  
This script optionally uses Pillow for image embedding:
```bash
pip install Pillow
```

## 🧪 Demo (No Setup Required)

Just run:

```bash
python3 stegocipher.py
```

Then choose option **3** from the menu:

> `3. Example/Demo`

You'll see how a quote hides a secret, and how to decrypt it back. Magic.

## 📜 CLI Options

After running `python3 stegocipher.py`, you'll get a menu with:

| Option | Description | 
| ---- | ----  |
| 1 | Encrypt a message with a cover quote | 
| 2 | Decrypt a message using the original quote | 
| 3 | View a demo with preset inputs | 
| 4 | Hide cipher in image (PNG recommended) | 
| 5 | Extract cipher from image | 
| 6 | Debug image extraction process | 
| 7 | Exit | 

> Options 4-6 appear only if `Pillow` is installed.

## 🔍 How It Works

### Text Cipher

- Scrambles each word from your quote
- Inserts characters from your secret between scrambled words
- Obfuscates with optional random symbols
- Randomizes capitalization

### Image Steganography

- Embeds cipher string inside the LSBs of a PNG image
- Uses a header (`STEGO:`) and a binary end delimiter to separate hidden data
- Extracts and decodes binary from the image to retrieve the message

## ✅ Requirements

- Python 3.6+
- [Pillow](https://pypi.org/project/Pillow/) (for image features)

```bash
pip install Pillow
```

## ⚠️ Important Notes

- **Use PNG Images**: JPEG/WebP may corrupt your hidden data due to compression.
- **Quote Length**: Your quote must be as long or longer than your secret message (in words).
- **Lossless Only**: Embedding is designed for lossless image formats.

## 🔓 Decryption Safety

Only someone who:

1. Has the cipher text **and**
2. Knows the original quote

... can decode the hidden message.

This makes brute-forcing or accidental discovery highly unlikely if used correctly.

## 🧠 Behind the Scenes

### Encryption

- Each quote word is cleaned and scrambled
- A character from the secret message is injected after each word
- Optional symbols and casing are added for noise

### Decryption

- Reconstructs the word lengths from the original quote
- Skips scrambled words and symbols to extract the true message

### Image Embedding

- Converts cipher to binary (with header + delimiter)
- Writes binary into LSBs of the image RGB channels

## 🐛 Troubleshooting

- **"No hidden message found"**: Ensure you're using the correct image, and it was saved as PNG.
- **"Secret message too long"**: Your quote must have equal or more words than the secret has characters.
- **"Image too small"**: Use higher resolution PNGs to hide longer ciphers.

## 🔓 License

This project is open-source and released under the MIT License. Use it, modify it, break it, make it better.

Just don't pretend you made it from scratch - that's my itch 😂
