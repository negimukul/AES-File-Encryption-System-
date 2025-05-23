#ifndef FILEPROCESSOR_H
#define FILEPROCESSOR_H

#include <QObject>
#include <QString>
#include <QVector>
#include <QByteArray>

class FileProcessor : public QObject
{
    Q_OBJECT
public:
    explicit FileProcessor(const QVector<QString> &files, const QByteArray &key, bool encrypt, QObject *parent = nullptr);

signals:
    void progress(int percent);
    void finished();
    void error(const QString &filePath, const QString &message);  // New error signal

public slots:
    void processFiles();

private:
    QVector<QString> m_files;
    QByteArray m_key;
    bool m_encrypt;

    QByteArray aesEncrypt(const QByteArray &plaintext, const QByteArray &key, QByteArray &iv);
    QByteArray aesDecrypt(const QByteArray &ciphertext, const QByteArray &key, const QByteArray &iv);
};

#endif // FILEPROCESSOR_H
