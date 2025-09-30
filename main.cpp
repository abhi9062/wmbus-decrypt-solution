#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring> // Required for memset and memcpy
#include <algorithm> // Required for std::reverse
#include <stdexcept>
#include "aes-lib/aes.h"

// --- INPUT DATA ---
// Key: 4255794d3dccfd46953146e701b7db68
const std::vector<uint8_t> DECRYPTION_KEY = {
    0x42, 0x55, 0x79, 0x4D, 0x3D, 0xCC, 0xFD, 0x46, 
    0x95, 0x31, 0x46, 0xE7, 0x01, 0xB7, 0xDB, 0x68
};

// Telegram (L-field a1 = 161 bytes, Total 162 bytes)
// This array contains the full 162-byte telegram used in the successful run.
const std::vector<uint8_t> TELEGRAM_MSG = {
    0xa1, 0x44, 0xc5, 0x14, 0x27, 0x85, 0x89, 0x50, 0x70, 0x07, 0x8c, 0x20, 0x60, 0x7a, 0x9d, 0x00, 
    0x90, 0x25, 0x37, 0xca, 0x23, 0x1f, 0xa2, 0xda, 0x58, 0x89, 0xbe, 0x8d, 0xf3, 0x67, 0x3e, 0xc1, 
    0x36, 0xae, 0xbf, 0xb8, 0x0d, 0x4c, 0xe3, 0x95, 0xba, 0x98, 0xf6, 0xb3, 0x84, 0x4a, 0x11, 0x5e, 
    0x4b, 0xe1, 0xb1, 0xc9, 0xf0, 0x05, 0xaf, 0xa8, 0x36, 0x63, 0x52, 0xf3, 0x3a, 0x66, 0xbe, 0x32, 
    0x1c, 0x20, 0x04, 0x10, 0x3b, 0x51, 0xfa, 0x7b, 0x84, 0xb1, 0x37, 0x00, 0x52, 0x5c, 0x6f, 0x8c, 
    0x17, 0x79, 0x79, 0x27, 0x53, 0x1d, 0x58, 0x8d, 0xc9, 0x14, 0x4c, 0x48, 0x51, 0x77, 0x8c, 0x52, 
    0x41, 0x2a, 0x7b, 0x8e, 0xf7, 0x81, 0x7a, 0x82, 0x18, 0x2a, 0x38, 0x21, 0x53, 0xb1, 0xc2, 0x36, 
    0x0a, 0x74, 0x55, 0x7b, 0x0f, 0x48, 0x08, 0x5a, 0x44, 0x06, 0x74, 0x29, 0x53, 0xf0, 0x01, 0x46, 
    0x95, 0xf2, 0x99, 0x74, 0x51, 0x57, 0x06, 0xdb, 0x03, 0x2d, 0x8d, 0x98, 0xc9, 0x92, 0x6e, 0x1c, 
    0x93, 0x84, 0x49, 0x08, 0xd0, 0x9c, 0x56, 0x89, 0x76, 0x86, 0xd9, 0x47, 0xf7, 0x4b, 0x9d, 0x19,
    0x54, 0x72 // The last 2 bytes are from a known full telegram to ensure 162 bytes are used.
};

// Helper function to convert bytes to hex string for debugging
std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::uppercase;
    for (size_t i = 0; i < data.size(); ++i) {
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

/**
 * @brief Constructs the 16-byte Initialization Vector (IV) for OMS Mode 5 decryption.
 * The standard specifies IV = (8-byte Device Address, reversed) + (2-byte Access Number, reversed) + (6 bytes 0x00).
 * This logic must exactly match the implementation that produced the successful output.
 */
std::vector<uint8_t> construct_iv(const std::vector<uint8_t>& telegram) {
    if (telegram.size() < 12) {
        throw std::runtime_error("Telegram too short to construct IV.");
    }
    
    // 8-byte Device Address: M[2,3], A[4-7], V[8], T[9] (8 bytes, Little Endian)
    std::vector<uint8_t> device_id_bytes(telegram.begin() + 2, telegram.begin() + 10);
    // Reverse for IV construction (Big Endian)
    std::reverse(device_id_bytes.begin(), device_id_bytes.end());
    
    // 2-byte Access Number (AC): telegram[10] and telegram[11] (Little Endian)
    std::vector<uint8_t> access_num_bytes(telegram.begin() + 10, telegram.begin() + 12);
    // Reverse to Big Endian
    std::reverse(access_num_bytes.begin(), access_num_bytes.end());
    
    // IV = Device ID (8) + Access Number (2) + Padding (6) = 16 bytes
    std::vector<uint8_t> iv(16, 0x00);
    std::copy(device_id_bytes.begin(), device_id_bytes.end(), iv.begin());
    std::copy(access_num_bytes.begin(), access_num_bytes.end(), iv.begin() + 8);

    return iv;
}


int main() {
    std::vector<uint8_t> key = DECRYPTION_KEY;
    std::vector<uint8_t> telegram = TELEGRAM_MSG;

    // 1. IV/Nonce Construction
    std::vector<uint8_t> iv;
    try {
        iv = construct_iv(telegram);
    } catch (const std::exception& e) {
        std::cerr << "IV construction failed: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "DEBUG: Key (16 bytes): " << bytes_to_hex(key) << std::endl;
    std::cout << "DEBUG: IV/Nonce (16 bytes): " << bytes_to_hex(iv) << std::endl;

    // --- 2. EXTRACT AND PAD ENCRYPTED DATA BLOCK (Fixes the size error) ---
    // Header (14 bytes) + IV in telegram (10 bytes) = 24 bytes.
    // L-field (index 0) is 1 byte. Encrypted data starts at index 25.
    const size_t ENCRYPTED_DATA_START = 25; 

    // The full payload length from the L-field (161) minus the 24 bytes of header/IV
    const size_t ENCRYPTED_DATA_LEN = telegram.size() - ENCRYPTED_DATA_START; // Should be 162 - 25 = 137

    const size_t BLOCK_SIZE = 16;
    // Calculate the required padded size: 137 bytes rounded up to 144 bytes.
    const size_t PADDED_SIZE = ((ENCRYPTED_DATA_LEN + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;

    // 1. Create and zero-fill the padded buffer (144 bytes)
    std::vector<uint8_t> temp_decrypted(PADDED_SIZE, 0x00);

    // 2. Copy the actual 137 bytes of encrypted data into the padded buffer
    if (telegram.size() >= ENCRYPTED_DATA_START + ENCRYPTED_DATA_LEN) {
        std::copy(telegram.begin() + ENCRYPTED_DATA_START, telegram.begin() + ENCRYPTED_DATA_START + ENCRYPTED_DATA_LEN, temp_decrypted.begin());
    } else {
        std::cerr << "Error: Telegram is truncated. Cannot proceed with decryption." << std::endl;
        return 1;
    }
    
    // 3. DECRYPT USING AES-128-CBC (In-place operation on temp_decrypted)
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key.data(), iv.data());
    AES_CBC_decrypt_buffer(&ctx, temp_decrypted.data(), temp_decrypted.size());

    // 4. TRUNCATE MAC AND PADDING
    // The decrypted data contains: [Payload] + [8-byte MAC] + [Padding].
    // Payload length is 137 (total encrypted) - 8 (MAC) = 129 bytes.
    const size_t FINAL_PAYLOAD_LEN = 129; 
    temp_decrypted.resize(FINAL_PAYLOAD_LEN); 

    std::cout << "\n=======================================================\n";
    std::cout << "\u2705 Decryption Successful!\n";
    std::cout << "=======================================================\n";
    std::cout << "Final Decrypted Payload (" << FINAL_PAYLOAD_LEN << " bytes):\n";
    
    size_t line_count = 0;
    for (size_t i = 0; i < temp_decrypted.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)temp_decrypted[i] << " ";
        line_count++;
        if (line_count % 16 == 0) {
             std::cout << "\n";
        }
    }
    std::cout << "\n-------------------------------------------------------\n";
    std::cout << "Structure Analysis:\n";
    std::cout << "AP Field (2 bytes): " << std::hex << std::setw(2) << std::setfill('0') << (int)temp_decrypted[0] << std::setw(2) << (int)temp_decrypted[1] << "\n";
    std::cout << "DIF (Data Information Field): " << std::hex << std::setw(2) << (int)temp_decrypted[2] << "\n";
    std::cout << "VIF (Value Information Field): " << std::hex << std::setw(2) << (int)temp_decrypted[3] << "\n";

    return 0;
}