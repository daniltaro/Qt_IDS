#include <QDebug>
#include <QFileDialog>
#include <QMessageBox>
#include <QListWidget>
#include <QPropertyAnimation>
#include <QGraphicsDropShadowEffect>

#include "basehandler.h"
#include "ethernethandler.h"
#include "loopbackhandler.h"
#include "mainwindow.h"
#include "anim.h"
#include "./ui_mainwindow.h"

#include <fstream>
#include <pcap.h>
#include <iostream>
#include <string>
#include <thread>

char ebuf[PCAP_ERRBUF_SIZE];
std::string selected_dev;
bool all = false;
bool tcp = false;
bool udp = false;
bool icmp = false;

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
    selected_dev = ui->listWidget->currentItem()->text().toStdString();
    if(!ui->listWidget->currentItem()->isSelected()){
        ui->statusbar->showMessage("Choose dev");
        return;
    }

    if(!ui->radioButton_ALL->isChecked()){
        if(ui->checkBox_TCP->checkState() == Qt::Checked) tcp = true;
        if(ui->checkBox_UDP->checkState() == Qt::Checked) udp = true;
        if(ui->checkBox_ICMP->checkState() == Qt::Checked) icmp = true;
    }else all = true;

    if(all == false && tcp == false && udp == false && icmp == false){
        ui->statusbar->showMessage("Choose protocol");
        return;
    }

    hide();
    sec = new SecondMainWindow(this);
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
    selected_dev = item->text().toStdString();
    if(!ui->listWidget->currentItem()->isSelected()){
        ui->statusbar->showMessage("Choose dev");
        return;
    }

    if(!ui->radioButton_ALL->isChecked()){
        if(ui->checkBox_TCP->checkState() == Qt::Checked) tcp = true;
        if(ui->checkBox_UDP->checkState() == Qt::Checked) udp = true;
        if(ui->checkBox_ICMP->checkState() == Qt::Checked) icmp = true;
    }else all = true;

    if(all == false && tcp == false && udp == false && icmp == false){
        ui->statusbar->showMessage("Choose protocol");
        return;
    }

    hide();
    sec = new SecondMainWindow(this);
    sec->show();
}





