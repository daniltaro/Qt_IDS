#ifndef ANIM_H
#define ANIM_H

#include <QPushButton>
#include <QPropertyAnimation>
#include <QCheckBox>
#include <QRadioButton>

namespace anim {

    inline void animateButton(QPushButton* btn) {

        static bool spam_flag = false;
        if(spam_flag) return;
        spam_flag = true;

        auto* anim = new QPropertyAnimation(btn, "geometry");
        QRect start_end = btn->geometry();
        QRect middle = start_end.adjusted(-2, -2, 4, 4);
        anim->setDuration(150);
        anim->setKeyValueAt(0, start_end);
        anim->setKeyValueAt(0.5, middle);
        anim->setKeyValueAt(1, start_end);
        anim->setEasingCurve(QEasingCurve::OutQuad);

        QObject::connect(anim, &QPropertyAnimation::finished, [&]() { spam_flag = false; });
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    }

    inline void animateCheckBox(QCheckBox* chk){

        static bool spam_flag = false;
        if(spam_flag) return;
        spam_flag = true;

        bool checked = false;
        if(chk->checkState() == Qt::Checked) checked = true;

        auto* anim = new QPropertyAnimation(chk, "geometry");
        QRect start_end = chk->geometry();
        QRect up = start_end.adjusted(0, -2, 0, -2);
        anim->setDuration(150);
        anim->setKeyValueAt(0, start_end);
        anim->setKeyValueAt(0.5, up);
        anim->setKeyValueAt(1, start_end);
        anim->setEasingCurve(QEasingCurve::OutQuad);

        QObject::connect(anim, &QPropertyAnimation::finished, [&](){spam_flag = false;});
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    }

    inline void animateRadioButton(QRadioButton* rd){

        static bool spam_flag = false;
        if(spam_flag) return;
        spam_flag = true;

        bool checked = false;
        if(rd->isChecked()) checked = true;

        auto* anim = new QPropertyAnimation(rd, "geometry");
        QRect start_end = rd->geometry();
        QRect up = start_end.adjusted(0, 0, 4, 4);
        anim->setDuration(150);
        anim->setKeyValueAt(0, start_end);
        anim->setKeyValueAt(0.5, up);
        anim->setKeyValueAt(1, start_end);
        anim->setEasingCurve(QEasingCurve::OutQuad);

        QObject::connect(anim, &QPropertyAnimation::finished, [&](){spam_flag = false;});
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    }
}
#endif // ANIM_H
