QT       += core gui widgets
CONFIG   += c++11

TEMPLATE = app
TARGET   = AES_Encryptor

SOURCES += main.cpp \
           mainwindow.cpp \
           FileProcessor.cpp

HEADERS += mainwindow.h \
           FileProcessor.h

INCLUDEPATH += "C:/MSYS2/mingw64/include"
LIBS += -L"C:/MSYS2/mingw64/lib" -lcrypto -lssl

