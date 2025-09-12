#include "secondmainwindow.h"
#include "ui_secondmainwindow.h"
#include "packetworker.h"

#include <QLabel>
#include <QPushButton>
#include <QThread>
#include <QMessageBox>
#include <QFileDialog>

extern char ebuf[PCAP_ERRBUF_SIZE];
extern std::string selected_dev;
extern std::string json_file_name;
extern std::string save_buf;
extern bool all;
extern bool tcp;
extern bool udp;
extern bool icmp;

SecondMainWindow::SecondMainWindow(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::SecondMainWindow)
{
    ui->setupUi(this);

    worker = new PacketWorker(selected_dev, tcp, icmp, udp, all, json_file_name);
    thread = new QThread(this);

    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &PacketWorker::startCapture);
    connect(worker, &PacketWorker::finished, thread, &QThread::quit);
    connect(worker, &PacketWorker::finished, worker, &PacketWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    connect(worker, &PacketWorker::packetCaptured, this, [&](PacketData packData){
        ui->tableWidget->insertRow(ui->tableWidget->rowCount());

        ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 0, new QTableWidgetItem(packData.protocol));
        ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 1, new QTableWidgetItem(packData.type));
        ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 2, new QTableWidgetItem(packData.srcDst));
        qDebug() << "Row inserted:" << packData.protocol << packData.srcDst;

    });

    connect(worker, &PacketWorker::statReady, this, [&](QString stat){
        ui->textEdit->setText(stat);
    });

    thread->start();

}

SecondMainWindow::~SecondMainWindow()
{
    delete ui;
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

    ui->pushButton_2->setDisabled(false);
    ui->pushButton->setDisabled(true);
    ui->label->setText("Stoped");

}


void SecondMainWindow::on_pushButton_2_clicked()
{
    QMessageBox msgBox(this);
    msgBox.setText("Statistic will be not saved");
    msgBox.setInformativeText("Do you want to save your changes?");
    msgBox.setStandardButtons(QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Save);
    int ret = msgBox.exec();

    if(ret == QMessageBox::Save){
        emit on_pushButton_4_clicked();
    }else if(ret == QMessageBox::Cancel){
        return;
    }else if(ret == QMessageBox::Discard){
    }

    ui->tableWidget->setRowCount(0);
    ui->textEdit->clear();
    save_buf = "";

    thread = new QThread(this);
    worker = new PacketWorker(selected_dev, tcp, icmp, udp, all, json_file_name);
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &PacketWorker::startCapture);
    connect(worker, &PacketWorker::finished, thread, &QThread::quit);
    connect(worker, &PacketWorker::finished, worker, &PacketWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    connect(worker, &PacketWorker::packetCaptured, this, [&](PacketData packData){
        ui->tableWidget->insertRow(ui->tableWidget->rowCount());

        ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 0, new QTableWidgetItem(packData.protocol));
        ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 1, new QTableWidgetItem(packData.type));
        ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 2, new QTableWidgetItem(packData.srcDst));
        qDebug() << "Row inserted:" << packData.protocol << packData.srcDst;

    });

    connect(worker, &PacketWorker::statReady, this, [&](QString stat){
        ui->textEdit->setText(stat);
    });

    thread->start();

    ui->pushButton_2->setDisabled(true);
    ui->pushButton->setDisabled(false);
    ui->label->setText("Running");

}


void SecondMainWindow::on_pushButton_4_clicked()
{
    QString curPath = QDir::currentPath() + "/data.json";
    json_file_name = QFileDialog::getSaveFileName(this, tr("Select json file"),
    curPath, tr("JSON Files (*.json);;All Files (*)")).toStdString();


    std::fstream out(json_file_name, std::ios::out);
    out << save_buf;
    out.close();
}


void SecondMainWindow::on_pushButton_3_clicked()
{
    close();
    if(parentWidget()){
        parentWidget()->show();
    }
}

