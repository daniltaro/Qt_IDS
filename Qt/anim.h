#ifndef ANIM_H
#define ANIM_H

#include <QPushButton>
#include <QPropertyAnimation>
#include <QCheckBox>
#include <QRadioButton>
#include <QWidget>

namespace anim {

    namespace detail {
        // short "bounce" of the widget geometry through middle and back
        inline void bounce(QWidget* widget, const QRect& middle) {

            // one animation per widget at a time, other widgets can still animate
            if(widget->property("animating").toBool()) return;
            widget->setProperty("animating", true);

            auto* anim = new QPropertyAnimation(widget, "geometry");
            const QRect start_end = widget->geometry();
            anim->setDuration(150);
            anim->setKeyValueAt(0, start_end);
            anim->setKeyValueAt(0.5, middle);
            anim->setKeyValueAt(1, start_end);
            anim->setEasingCurve(QEasingCurve::OutQuad);

            QObject::connect(anim, &QPropertyAnimation::finished, widget, [widget]() {
                widget->setProperty("animating", false);
            });
            anim->start(QAbstractAnimation::DeleteWhenStopped);
        }
    }

    inline void animateButton(QPushButton* btn) {
        detail::bounce(btn, btn->geometry().adjusted(-2, -2, 4, 4));
    }

    inline void animateCheckBox(QCheckBox* chk) {
        detail::bounce(chk, chk->geometry().adjusted(0, -2, 0, -2));
    }

    inline void animateRadioButton(QRadioButton* rd) {
        detail::bounce(rd, rd->geometry().adjusted(0, 0, 4, 4));
    }
}
#endif // ANIM_H
