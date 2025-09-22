#include "secondmainwindow.h"
#include "ui_secondmainwindow.h"
#include "packetworker.h"

#include <QLabel>
#include <QLineEdit>
#include <QRadioButton>
#include <QPushButton>
#include <QThread>
#include <QMessageBox>
#include <QFileDialog>

extern std::string selected_dev;
extern bool all;
extern bool tcp;
extern bool udp;
extern bool icmp;
std::string save_buf;

SecondMainWindow::SecondMainWindow(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::SecondMainWindow)
{
    ui->setupUi(this);
    ui->label->setText("Running " + QString::fromStdString(selected_dev));

    worker = new PacketWorker(selected_dev, tcp, icmp, udp, all);
    thread = new QThread(this);

    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &PacketWorker::startCapture);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    connect(worker, &PacketWorker::finished, thread, &QThread::quit);
    connect(worker, &PacketWorker::finished, worker, &PacketWorker::deleteLater); 
    connect(worker, &PacketWorker::packetCaptured, this, &SecondMainWindow::insertPacket);
    connect(worker, &PacketWorker::statReady, this, [&](const QString& stat){
        ui->textEdit->setText(stat);
    });
    connect(worker, &PacketWorker::linkTypeError, this, &SecondMainWindow::linkError);

    ui->pushButton_4->setDisabled(true);
    ui->pushButton_2->setDisabled(true);
    ui->pushButton->setEnabled(true);
    ui->lineEdit->setDisabled(true);
    ui->radioButton->setDisabled(true);

    thread->start();

}

SecondMainWindow::~SecondMainWindow()
{
    delete ui;
}


void SecondMainWindow::insertPacket(const PacketData& packData)
{
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());

    ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 0, new QTableWidgetItem(packData.protocol));
    ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 1, new QTableWidgetItem(packData.type));
    ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 2, new QTableWidgetItem(packData.srcDst));
    qDebug() << "Row inserted:" << packData.protocol << packData.srcDst;

    packHex.push_back(packData.hex);
}


void SecondMainWindow::linkError()
{
    QMessageBox mes(this);
    mes.setIcon(QMessageBox::Critical);
    mes.setText("Error");
    mes.setInformativeText(QString::fromStdString(selected_dev) + " is not supported");
    mes.setStandardButtons(QMessageBox::Ok);
    int ret = mes.exec();
    if(ret == QMessageBox::Ok) on_pushButton_3_clicked();
}

void SecondMainWindow::on_pushButton_clicked()
{
    if(worker){
        worker->stopCapture();
        worker->deleteLater();
        worker = nullptr;
        qDebug("worker deleted");
    }

    if(thread){
        if(thread->isRunning()){
            thread->quit();
            thread->wait();
            qDebug("thread ended");
        }
        thread->deleteLater();
        thread = nullptr;
        qDebug("thread deleted");
    }

    ui->pushButton_4->setEnabled(true);
    ui->pushButton_2->setEnabled(true);
    ui->pushButton->setDisabled(true);
    ui->lineEdit->setEnabled(true);
    ui->radioButton->setEnabled(true);
    ui->label->setText("Stoped " + QString::fromStdString(selected_dev));

}


void SecondMainWindow::on_pushButton_2_clicked()
{
    QMessageBox msgBox(this);
    msgBox.setText("Statistic will not be saved");
    msgBox.setInformativeText("Do you want to save your changes?");
    msgBox.setStandardButtons(QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Save);
    int ret = msgBox.exec();

    ui->radioButton->setChecked(false);
    ui->lineEdit->clear();

    if(ret == QMessageBox::Save){
        on_pushButton_4_clicked();
    }else if(ret == QMessageBox::Cancel){
        return;
    }else if(ret == QMessageBox::Discard){
    }

    ui->tableWidget->setRowCount(0);
    ui->textEdit->clear();
    ui->textEdit_2->clear();
    packHex.clear();
    save_buf = "";

    thread = new QThread(this);
    worker = new PacketWorker(selected_dev, tcp, icmp, udp, all);
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &PacketWorker::startCapture);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    connect(worker, &PacketWorker::finished, thread, &QThread::quit);
    connect(worker, &PacketWorker::finished, worker, &PacketWorker::deleteLater);
    connect(worker, &PacketWorker::packetCaptured, this, &SecondMainWindow::insertPacket);
    connect(worker, &PacketWorker::statReady, this, [&](const QString& stat){
        ui->textEdit->setText(stat);
    });
    connect(worker, &PacketWorker::linkTypeError, this, &SecondMainWindow::linkError);

    thread->start();

    ui->pushButton_4->setDisabled(true);
    ui->pushButton_2->setDisabled(true);
    ui->pushButton->setEnabled(true);
    ui->lineEdit->setDisabled(true);
    ui->radioButton->setDisabled(true);
    ui->label->setText("Running " + QString::fromStdString(selected_dev));

}


void SecondMainWindow::on_pushButton_4_clicked()
{
    QString curPath = QDir::currentPath() + "/data.json";
    std::string json_file_name = QFileDialog::getSaveFileName(this, tr("Select json file"),
    curPath, tr("JSON Files (*.json);;All Files (*)")).toStdString();


    std::fstream out(json_file_name, std::ios::out);
    out << save_buf;
    out.close();
}


void SecondMainWindow::on_pushButton_3_clicked()
{
    save_buf = "";
    close();

    if(worker){
        worker->stopCapture();
        worker->deleteLater();
        worker = nullptr;
        qDebug("worker deleted");
    }

    if(thread){
        if(thread->isRunning()){
            thread->quit();
            thread->wait();
            qDebug("thread ended");
        }
        thread->deleteLater();
        thread = nullptr;
        qDebug("thread deleted");
    }

    if(parentWidget()){
        parentWidget()->show();
    }
}


void SecondMainWindow::on_tableWidget_cellClicked(int row, int column)
{
    ui->textEdit_2->setText(packHex[row]);
}


void SecondMainWindow::on_lineEdit_textChanged(const QString &arg1)
{
    for(int i = 0; i < ui->tableWidget->rowCount(); ++i){
        bool match = false;
        for(int j = 0; j < ui->tableWidget->columnCount(); ++j){
            if(ui->tableWidget->item(i, j) && ui->tableWidget->item(i, j)->text().contains
                                               (arg1, Qt::CaseInsensitive)){
                match = true;
                break;
            }
        }
        ui->tableWidget->setRowHidden(i, !match);
    }
}


void SecondMainWindow::on_radioButton_clicked(bool checked)
{
    ui->lineEdit->setText("");
    if(!checked){
        ui->lineEdit->setEnabled(true);
        for(int i = 0; i < ui->tableWidget->rowCount(); ++i){
            ui->tableWidget->setRowHidden(i, false);
        }
        return;
    }

    ui->lineEdit->setDisabled(true);
    for(int i = 0; i < ui->tableWidget->rowCount(); ++i){
        bool match = false;
        for(int j = 0; j < ui->tableWidget->columnCount(); ++j){
            if(ui->tableWidget->item(i, j)&& ui->tableWidget->item(i, j)->text().contains
                                                ("[", Qt::CaseInsensitive)){
                match = true;
                break;
            }
        }
        ui->tableWidget->setRowHidden(i, !match);
    }
}


