#ifndef SECONDMAINWINDOW_H
#define SECONDMAINWINDOW_H

#include <QDialog>
#include "packetworker.h"

namespace Ui {
class SecondMainWindow;
}

class SecondMainWindow : public QDialog
{
    Q_OBJECT

public:
    explicit SecondMainWindow(QWidget *parent = nullptr);
    ~SecondMainWindow();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

    void on_pushButton_4_clicked();

    void on_pushButton_3_clicked();

private:
    Ui::SecondMainWindow *ui;
    QThread* thread;
    PacketWorker* worker;
};

#endif // SECONDMAINWINDOW_H
