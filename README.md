# W-MBus AES-128 Decryption (OMS Mode 5/7)

### 📖 Overview
This project decrypts a Wireless M-Bus (W-MBus) telegram according to the **OMS Volume 2** specification using **AES-128**.  
It reads an encrypted telegram and an AES-128 key, constructs the proper Initialization Vector (IV), and outputs the decrypted payload in human-readable format.

---

### ⚙️ Requirements
- **C++17**
- **OpenSSL library**
- Works on **Windows (MSYS2 MinGW64)**, **Linux**, or **ESP32** with minor changes.

---

### 🧩 Input
1. **AES-128 Key:**  
   ```
   4255794d3dccfd46953146e701b7db68
   ```

2. **Encrypted Telegram:**  
   (stored in `msg.txt`)
   ```
   a144c5142785895070078c20607a9d00902537ca231fa2da5889Be8df3673ec136aeBfB80d4ce395Ba98f6B3844a115e4Be1B1c9f0a2d5ffBB92906aa388deaa82c929310e9e5c4c0922a784df89cf0ded833Be8da996eB5885409B6c9867978dea24001d68c603408d758a1e2B91c42eBad86a9B9d287880083BB0702850574d7B51e9c209ed68e0374e9B01feBfd92B4cB9410fdeaf7fB526B742dc9a8d0682653
   ```

3. **Initialization Vector (IV):**
   - For **Mode 7 (ephemeral key):**  
     ```
     00000000000000000000000000000000
     ```
   - For **Mode 5 (persistent key):**  
     Constructed from telegram fields  
     Example:
     ```
     IV = [ManufacturerID][DeviceID][Version][DeviceType][AccessNumber][Padding...]
     ```
     Example IV used:
     ```
     14c52785895070072000000000000000
     ```

---

### 🧠 Decryption Details
- AES-128 in **CBC mode** (per OMS Volume 2 §9.3.5–9.3.6).
- Key length: 16 bytes.
- IV length: 16 bytes.
- PKCS#7 padding (default OpenSSL behavior).

---

### 🚀 Build & Run (Windows + VS Code + MSYS2)
1. Install MSYS2 and OpenSSL:
   ```bash
   pacman -Syu
   pacman -S --noconfirm mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl
   ```
2. Build:
   ```bash
   g++ wmbus_decrypt.cpp -o wmbus_decrypt.exe -I /mingw64/include -L /mingw64/lib -lssl -lcrypto
   ```
3. Run:
   ```bash
   msghex=$(tr -d ' \n\r\t' < msg.txt)
   ./wmbus_decrypt.exe --key 4255794d3dccfd46953146e701b7db68 --msg "$msghex" --iv 14c52785895070072000000000000000
   ```

---

### 🧾 Example Output
```
Decryption successful.

HEX:
2f4458475f01020304...

ASCII/UTF-8 (printable):
/DXG_.......
```

---

### 🧰 Files
| File | Description |
|------|--------------|
| `wmbus_decrypt.cpp` | Source code for decryption logic |
| `msg.txt` | Sample encrypted telegram |
| `README.md` | Documentation (this file) |
| `.vscode/tasks.json` | VS Code build task configuration |

---

### 🔍 Verification (Optional)
To confirm your decrypted result:
1. Visit **[https://wmbusmeters.org](https://wmbusmeters.org)**
2. Use the **Test / Decode Tool** section.
3. Paste your encrypted telegram and AES key.
4. Compare your decrypted output with the website’s decoded result — they should match.

---

### 🧩 References
- **OMS Specification Volume 2, Primary Communication (v5.01)**  
- **EN 13757-7:2018** (Transport Layer security)  
- **wmbusmeters.org** – for validation of decryption results

---

### 🏁 Author
**Abhijit Sonawane**
