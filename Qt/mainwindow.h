#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QList>
#include <QMainWindow>

class QCheckBox;

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Start button and double click on a device
    void startCapture();

    // ALL checks or unchecks every protocol
    void selectAllProtocols(bool checked);

    // keeps ALL checked only while every protocol is checked
    void syncAllButton();

private:
    void loadDevices();

    QList<QCheckBox *> protocolBoxes() const;

    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
