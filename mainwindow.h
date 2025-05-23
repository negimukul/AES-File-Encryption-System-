#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
#include <QString>
#include <QByteArray>
#include <QProgressBar>
#include <QPushButton>
#include <QLabel>
#include <QThread>
#include "FileProcessor.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private slots:
    void openFiles();
    void encryptFiles();
    void decryptFiles();
    bool getPasswordFromUser();

private:
    QVector<QString> files;
    QByteArray aesKey;

    QPushButton *encryptButton;
    QPushButton *decryptButton;
    QProgressBar *progressBar;
    QLabel *statusLabel;

    QThread *workerThread = nullptr;
    FileProcessor *worker = nullptr;
};

#endif // MAINWINDOW_H
