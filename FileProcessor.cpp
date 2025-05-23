#include "FileProcessor.h"
#include <QFile>
#include <QCryptographicHash>
#include <openssl/evp.h>
#include <openssl/rand.h>

FileProcessor::FileProcessor(const QVector<QString> &files, const QByteArray &key, bool encrypt, QObject *parent)
    : QObject(parent), m_files(files), m_key(key), m_encrypt(encrypt)
{
}

void FileProcessor::processFiles()
{
    int total = m_files.size();
//reading file as a binary blob(QBYteArray)
    for (int i = 0; i < total; ++i) {
        const QString &filePath = m_files[i];

        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            emit error(filePath, "Failed to open file");
            continue;
        }

        QByteArray fileData = file.readAll();
        file.close();
//encryption path
//for encryption we use openssl (16 byte random iv)
        if (m_encrypt) {
            QByteArray iv(16, 0);
            RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), iv.size());
//encrypt data using AES-256
            QByteArray ciphertext = aesEncrypt(fileData, m_key, iv);

            //writing IV + encrypt data to new .enc file
            QString outFile = filePath + ".enc";
            QFile out(outFile);
            if (out.open(QIODevice::WriteOnly)) {
                out.write(iv);
                out.write(ciphertext);
                out.close();
            } else {
                emit error(outFile, "Failed to write encrypted file");
            }
        } else {
            if (fileData.size() < 16) {
                emit error(filePath, "File too small to contain valid IV");
                continue;
            }
//Decrypt part
            //Extract IV (first 16 bytes) and encrypted body.
            QByteArray iv = fileData.left(16);
            QByteArray ciphertext = fileData.mid(16);

            QByteArray plaintext = aesDecrypt(ciphertext, m_key, iv);
//error show krega
            if (plaintext.isEmpty()) {
                emit error(filePath, "Decryption failed (possible wrong password or corrupted file)");
                continue;  // Skip writing output on error
            }
//decrypt file store krne k liye .dec
            QString outFile;
            if (filePath.endsWith(".enc"))
                outFile = filePath.left(filePath.size() - 4) + ".dec";
            else
                outFile = filePath + ".dec";

            QFile out(outFile);
            if (out.open(QIODevice::WriteOnly)) {
                out.write(plaintext);
                out.close();
            } else {
                emit error(outFile, "Failed to write decrypted file");
            }
        }
//for progress checking
        int progressPercent = static_cast<int>((i + 1) * 100 / total);
        emit progress(progressPercent);
    }

    emit finished();
}

QByteArray FileProcessor::aesEncrypt(const QByteArray &plaintext, const QByteArray &key, QByteArray &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();

    int outlen1, outlen2;
    QByteArray ciphertext;
    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       reinterpret_cast<const unsigned char*>(key.data()),
                       reinterpret_cast<const unsigned char*>(iv.data()));

    EVP_EncryptUpdate(ctx,
                      reinterpret_cast<unsigned char*>(ciphertext.data()), &outlen1,
                      reinterpret_cast<const unsigned char*>(plaintext.data()),
                      plaintext.size());

    EVP_EncryptFinal_ex(ctx,
                        reinterpret_cast<unsigned char*>(ciphertext.data()) + outlen1, &outlen2);

    ciphertext.resize(outlen1 + outlen2);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

QByteArray FileProcessor::aesDecrypt(const QByteArray &ciphertext, const QByteArray &key, const QByteArray &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();

    int outlen1, outlen2;
    QByteArray plaintext;
    plaintext.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       reinterpret_cast<const unsigned char*>(key.data()),
                       reinterpret_cast<const unsigned char*>(iv.data()));

    if (1 != EVP_DecryptUpdate(ctx,
                               reinterpret_cast<unsigned char*>(plaintext.data()), &outlen1,
                               reinterpret_cast<const unsigned char*>(ciphertext.data()),
                               ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    if (1 != EVP_DecryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char*>(plaintext.data()) + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    plaintext.resize(outlen1 + outlen2);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
