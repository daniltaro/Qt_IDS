#ifndef SECONDMAINWINDOW_H
#define SECONDMAINWINDOW_H

#include "../packetHandlers/packetworker.h"

#include <QDialog>
#include <QVector>

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
    void insertPacket(const PacketData&);

    void linkError();

    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

    void on_pushButton_4_clicked();

    void on_pushButton_3_clicked();

    void on_tableWidget_cellClicked(int row, int column);

    void on_lineEdit_textChanged(const QString &arg1);

    void on_radioButton_clicked(bool checked);

private:
    Ui::SecondMainWindow *ui;
    QThread* thread;
    PacketWorker* worker;
    QVector<QString> packHex;
};

#endif // SECONDMAINWINDOW_H
