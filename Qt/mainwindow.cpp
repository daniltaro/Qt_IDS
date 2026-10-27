#include <QDebug>
#include <QFileDialog>
#include <QMessageBox>
#include <QListWidget>
#include <QPropertyAnimation>
#include <QGraphicsDropShadowEffect>

#include "mainwindow.h"
#include "anim.h"
#include "./ui_mainwindow.h"

#include <fstream>
#include <pcap.h>
#include <iostream>
#include <string>
#include <thread>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QObject::connect(ui->pushButton, &QPushButton::pressed, [&](){anim::animateButton(ui->pushButton);});
    QObject::connect(ui->checkBox_ICMP, &QCheckBox::pressed, [&](){
        anim::animateCheckBox(ui->checkBox_ICMP);
    });
    QObject::connect(ui->checkBox_UDP, &QCheckBox::pressed, [&](){
        anim::animateCheckBox(ui->checkBox_UDP);
    });
    QObject::connect(ui->checkBox_TCP, &QCheckBox::pressed, [&](){
        anim::animateCheckBox(ui->checkBox_TCP);
    });
    QObject::connect(ui->radioButton_ALL, &QRadioButton::pressed, [&](){
        anim::animateRadioButton(ui->radioButton_ALL);
    });

    //devs output
    char ebuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t *devs;

    if (pcap_findalldevs(&devs, ebuf) == -1) {
        throw std::runtime_error("pcap_findalldevs");
    }

    pcap_if_t *temp = devs;

    while (temp != nullptr) {
        ui->listWidget->addItem(temp->name);
        temp = temp->next;
    }
    pcap_freealldevs(devs);

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    const std::string selected_dev = ui->listWidget->currentItem()->text().toStdString();
    if(!ui->listWidget->currentItem()->isSelected()){
        ui->statusbar->showMessage("Choose dev");
        return;
    }

    CaptureSettings settings;
    settings.device = selected_dev;
    settings.tcp = ui->checkBox_TCP->isChecked();
    settings.udp = ui->checkBox_UDP->isChecked();
    settings.icmp = ui->checkBox_ICMP->isChecked();

    if(!settings.tcp && !settings.udp && !settings.icmp){
        ui->statusbar->showMessage("Choose protocol");
        return;
    }

    auto *sec = new SecondMainWindow(settings, this);
    connect(sec, &QDialog::finished, this, &QWidget::show);
    connect(sec, &QDialog::finished, sec, &QObject::deleteLater);
    hide();
    sec->show();
}


void MainWindow::on_radioButton_ALL_pressed()
{
    if(!ui->radioButton_ALL->isChecked()){
        ui->checkBox_TCP->setCheckState(Qt::Checked);
        ui->checkBox_UDP->setCheckState(Qt::Checked);
        ui->checkBox_ICMP->setCheckState(Qt::Checked);
    }else{
        ui->checkBox_TCP->setCheckState(Qt::Unchecked);
        ui->checkBox_UDP->setCheckState(Qt::Unchecked);
        ui->checkBox_ICMP->setCheckState(Qt::Unchecked);
    }
}


void MainWindow::on_checkBox_ICMP_pressed()
{
    if(ui->checkBox_ICMP->checkState() == Qt::Checked){
        ui->radioButton_ALL->setChecked(false);
    }

}


void MainWindow::on_checkBox_UDP_pressed()
{
    if(ui->checkBox_UDP->checkState() == Qt::Checked){
        ui->radioButton_ALL->setChecked(false);
    }
}


void MainWindow::on_checkBox_TCP_pressed()
{
    if(ui->checkBox_TCP->checkState() == Qt::Checked){
        ui->radioButton_ALL->setChecked(false);
    }
}


void MainWindow::on_listWidget_itemDoubleClicked(QListWidgetItem *item)
{
    const std::string selected_dev = item->text().toStdString();
    if(!ui->listWidget->currentItem()->isSelected()){
        ui->statusbar->showMessage("Choose dev");
        return;
    }

    CaptureSettings settings;
    settings.device = selected_dev;
    settings.tcp = ui->checkBox_TCP->isChecked();
    settings.udp = ui->checkBox_UDP->isChecked();
    settings.icmp = ui->checkBox_ICMP->isChecked();

    if(!settings.tcp && !settings.udp && !settings.icmp){
        ui->statusbar->showMessage("Choose protocol");
        return;
    }

    auto *sec = new SecondMainWindow(settings, this);
    connect(sec, &QDialog::finished, this, &QWidget::show);
    connect(sec, &QDialog::finished, sec, &QObject::deleteLater);
    hide();
    sec->show();
}





