#include <iostream>
#include <string>
#include <unordered_map>
#include <bitset>

using namespace std;

// Block and Key Sizes
const int BLOCK_SIZE = 8;  // 8 bits
const int HALF_BLOCK_SIZE = BLOCK_SIZE / 2;  // 4 bits
const int KEY_SIZE = 8;    // 8 bits

// Define a 4x4 Substitution Box (S-box)
unordered_map<string, string> S_BOX = {
    {"0000", "1110"}, {"0001", "0100"}, {"0010", "1101"}, {"0011", "0001"},
    {"0100", "0010"}, {"0101", "1111"}, {"0110", "1011"}, {"0111", "1000"},
    {"1000", "0011"}, {"1001", "1010"}, {"1010", "0110"}, {"1011", "1100"},
    {"1100", "0101"}, {"1101", "1001"}, {"1110", "0000"}, {"1111", "0111"}
};

// XOR function for two binary strings
string xorBits(const string& bits1, const string& bits2) {
    string result;
    for (size_t i = 0; i < bits1.size(); ++i) {
        result += (bits1[i] == bits2[i]) ? '0' : '1';
    }
    return result;
}

// Function to apply S-box substitution
string sboxSubstitute(const string& bits) {
    return S_BOX[bits];
}

// Feistel function using XOR and S-box
string feistelFunction(const string& bits, const string& keyHalf) {
    string xorResult = xorBits(bits, keyHalf);
    return sboxSubstitute(xorResult);
}

// Perform a single round of Feistel encryption
pair<string, string> feistelRound(const string& left, const string& right, const string& key) {
    string newLeft = right;
    string newRight = xorBits(left, feistelFunction(right, key));
    return make_pair(newLeft, newRight);
}

// Perform encryption using Feistel network with 2 rounds
string feistelEncrypt(const string& block, const string& key) {
    string left = block.substr(0, HALF_BLOCK_SIZE);
    string right = block.substr(HALF_BLOCK_SIZE, HALF_BLOCK_SIZE);
    string keyLeft = key.substr(0, HALF_BLOCK_SIZE);
    string keyRight = key.substr(HALF_BLOCK_SIZE, HALF_BLOCK_SIZE);

    // Round 1
    tie(left, right) = feistelRound(left, right, keyLeft);

    // Round 2
    tie(left, right) = feistelRound(left, right, keyRight);

    return left + right;
}

// Perform decryption using Feistel network (just reverse the rounds)
string feistelDecrypt(const string& block, const string& key) {
    string left = block.substr(0, HALF_BLOCK_SIZE);
    string right = block.substr(HALF_BLOCK_SIZE, HALF_BLOCK_SIZE);
    string keyLeft = key.substr(0, HALF_BLOCK_SIZE);
    string keyRight = key.substr(HALF_BLOCK_SIZE, HALF_BLOCK_SIZE);

    // Round 1 (reversed round 2 from encryption)
    tie(left, right) = feistelRound(left, right, keyRight);

    // Round 2 (reversed round 1 from encryption)
    tie(left, right) = feistelRound(left, right, keyLeft);

    return left + right;
}

// Function to pad plaintext to fit block size
string padPlaintext(const string& plaintext, int blockSize = BLOCK_SIZE) {
    int paddingLen = blockSize - (plaintext.size() % blockSize);
    return plaintext + string(paddingLen, '0');  // Padding with zeros
}

// ECB Mode Encryption for Feistel
string ecbEncryptFeistel(const string& plaintext, const string& key) {
    string ciphertext;
    for (size_t i = 0; i < plaintext.size(); i += BLOCK_SIZE) {
        string block = plaintext.substr(i, BLOCK_SIZE);
        ciphertext += feistelEncrypt(block, key);
    }
    return ciphertext;
}

// ECB Mode Decryption for Feistel
string ecbDecryptFeistel(const string& ciphertext, const string& key) {
    string plaintext;
    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        string block = ciphertext.substr(i, BLOCK_SIZE);
        plaintext += feistelDecrypt(block, key);
    }
    return plaintext;
}

// CBC Mode Encryption for Feistel
string cbcEncryptFeistel(const string& plaintext, const string& key, const string& iv) {
    string previousBlock = iv;
    string ciphertext;
    
    for (size_t i = 0; i < plaintext.size(); i += BLOCK_SIZE) {
        string block = plaintext.substr(i, BLOCK_SIZE);
        string xorResult = xorBits(block, previousBlock);
        string encryptedBlock = feistelEncrypt(xorResult, key);
        ciphertext += encryptedBlock;
        previousBlock = encryptedBlock;
    }
    
    return ciphertext;
}

// CBC Mode Decryption for Feistel
string cbcDecryptFeistel(const string& ciphertext, const string& key, const string& iv) {
    string previousBlock = iv;
    string plaintext;

    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        string block = ciphertext.substr(i, BLOCK_SIZE);
        string decryptedBlock = feistelDecrypt(block, key);
        string xorResult = xorBits(decryptedBlock, previousBlock);
        plaintext += xorResult;
        previousBlock = block;
    }

    return plaintext;
}

// Helper function to convert a binary string to its bit representation
string toBinaryString(const string& input) {
    string binaryString;
    for (char c : input) {
        binaryString += bitset<8>(c).to_string();
    }
    return binaryString;
}

// Helper function to convert bit string back to normal string
string toTextString(const string& binaryString) {
    string result;
    for (size_t i = 0; i < binaryString.size(); i += 8) {
        bitset<8> bits(binaryString.substr(i, 8));
        result += char(bits.to_ulong());
    }
    return result;
}

int main() {
    // Example plaintext and key
    string plaintext = "11001100100111";  // 14 bits, will be padded
    string paddedPlaintext = padPlaintext(plaintext);
    string key = "10101010";
    string iv = "00000000";  // Initialization vector for CBC

    // Encrypt and Decrypt using Feistel ECB Mode
    string ciphertextEcb = ecbEncryptFeistel(paddedPlaintext, key);
    string decryptedEcb = ecbDecryptFeistel(ciphertextEcb, key);

    cout << "Feistel ECB Mode" << endl;
    cout << "Plaintext (padded): " << paddedPlaintext << endl;
    cout << "Ciphertext: " << ciphertextEcb << endl;
    cout << "Decrypted: " << decryptedEcb << endl;

    // Encrypt and Decrypt using Feistel CBC Mode
    string ciphertextCbc = cbcEncryptFeistel(paddedPlaintext, key, iv);
    string decryptedCbc = cbcDecryptFeistel(ciphertextCbc, key, iv);

    cout << "\nFeistel CBC Mode" << endl;
    cout << "Plaintext (padded): " << paddedPlaintext << endl;
    cout << "Ciphertext: " << ciphertextCbc << endl;
    cout << "Decrypted: " << decryptedCbc << endl;

    return 0;
}
