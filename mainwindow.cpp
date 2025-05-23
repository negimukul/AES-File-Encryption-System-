#include "mainwindow.h"
#include "FileProcessor.h"
#include <QCryptographicHash>
#include <QMenuBar>
#include <QMenu>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QDragEnterEvent>
#include <QMimeData>
#include <QThread>
//gui logic  and control
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{

    //drag and drop krne k liye
    setAcceptDrops(true);

    resize(600, 150);

    // Menu
    QMenu *fileMenu = menuBar()->addMenu("&File");
    QAction *openAction = fileMenu->addAction("&Open Files");
    connect(openAction, &QAction::triggered, this, &MainWindow::openFiles);

    // Buttons
    encryptButton = new QPushButton("Encrypt", this);
    encryptButton->setGeometry(100, 70, 100, 30);
    connect(encryptButton, &QPushButton::clicked, this, &MainWindow::encryptFiles);

    decryptButton = new QPushButton("Decrypt", this);
    decryptButton->setGeometry(250, 70, 100, 30);
    connect(decryptButton, &QPushButton::clicked, this, &MainWindow::decryptFiles);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setGeometry(100, 110, 350, 20);
    progressBar->setRange(0, 100);
    progressBar->setValue(0);

    // Status label
    statusLabel = new QLabel("Select files to encrypt or decrypt", this);
    statusLabel->setGeometry(100, 30, 400, 30);
}
//open file  dialog and save selected paths
void MainWindow::openFiles()
{
    QStringList fileNames = QFileDialog::getOpenFileNames(this, "Select Files to Encrypt/Decrypt");
    if (!fileNames.isEmpty()) {
        files.clear();
        for (const QString &f : fileNames) {
            files.append(f);
        }
        statusLabel->setText(QString("%1 files selected").arg(files.size()));
        progressBar->setValue(0);
    }
}
//password input
bool MainWindow::getPasswordFromUser()
{
    bool ok;
    QString password = QInputDialog::getText(this, "Password", "Enter password for AES key:", QLineEdit::Password, "", &ok);
    if (!ok || password.isEmpty()) {
        return false;
    }
    // Derive 256-bit key using SHA256
    aesKey = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256);
    return true;
}

void MainWindow::encryptFiles()
{
    if (files.isEmpty()) {
        QMessageBox::warning(this, "No files", "Please select files first.");
        return;
    }

    if (!getPasswordFromUser())
        return;

    encryptButton->setEnabled(false);
    decryptButton->setEnabled(false);
    statusLabel->setText("Encrypting files...");
    progressBar->setValue(0);

    workerThread = new QThread();
    worker = new FileProcessor(files, aesKey, true);
    worker->moveToThread(workerThread);

    connect(workerThread, &QThread::started, worker, &FileProcessor::processFiles);
    connect(worker, &FileProcessor::progress, progressBar, &QProgressBar::setValue);
    connect(worker, &FileProcessor::finished, this, [=]() {
        statusLabel->setText("Encryption completed!");
        encryptButton->setEnabled(true);
        decryptButton->setEnabled(true);
        workerThread->quit();
    });
    connect(workerThread, &QThread::finished, worker, &QObject::deleteLater);
    connect(workerThread, &QThread::finished, workerThread, &QObject::deleteLater);

    workerThread->start();
}
// Inside your decryptFiles() function (replace your existing decryptFiles with this):

void MainWindow::decryptFiles()
{
    if (files.isEmpty()) {
        QMessageBox::warning(this, "No files", "Please select files first.");
        return;
    }

    if (!getPasswordFromUser())
        return;

    encryptButton->setEnabled(false);
    decryptButton->setEnabled(false);
    statusLabel->setText("Decrypting files...");
    progressBar->setValue(0);

    workerThread = new QThread();
    worker = new FileProcessor(files, aesKey, false);
    worker->moveToThread(workerThread);

    connect(workerThread, &QThread::started, worker, &FileProcessor::processFiles);
    connect(worker, &FileProcessor::progress, progressBar, &QProgressBar::setValue);

    connect(worker, &FileProcessor::error, this, [this](const QString &filePath, const QString &message){
        QMessageBox::warning(this, "Decryption Error",
                             QString("Error decrypting file:\n%1\n\n%2").arg(filePath, message));
    });

    connect(worker, &FileProcessor::finished, this, [=]() {
        statusLabel->setText("Decryption completed!");
        encryptButton->setEnabled(true);
        decryptButton->setEnabled(true);
        workerThread->quit();
    });
    connect(workerThread, &QThread::finished, worker, &QObject::deleteLater);
    connect(workerThread, &QThread::finished, workerThread, &QObject::deleteLater);

    workerThread->start();
}


void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event)
{
    QList<QUrl> urls = event->mimeData()->urls();
    if (urls.isEmpty())
        return;

    files.clear();
    for (const QUrl &url : urls) {
        files.append(url.toLocalFile());
    }
    statusLabel->setText(QString("%1 files selected via drag & drop").arg(files.size()));
    progressBar->setValue(0);
}

MainWindow::~MainWindow() {
    // Cleanup if needed
}
