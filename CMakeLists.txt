cmake_minimum_required(VERSION 3.16)

project(my_IDS VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)
find_library(PCAP_LIB pcap  REQUIRED)
find_package(nlohmann_json REQUIRED)
message(STATUS "PCAP_LIB - "${PCAP_LIB})

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)

qt_add_executable(my_IDS
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        secondmainwindow.h secondmainwindow.cpp secondmainwindow.ui
        threatdetector.h threatdetector.cpp
        basehandler.h basehandler.cpp
        ethernethandler.h ethernethandler.cpp
        loopbackhandler.h loopbackhandler.cpp
        ethernetheader.h ethernetheader.cpp
        icmpheader.h icmpheader.cpp
        ipv4header.h ipv4header.cpp
        tcpheader.h tcpheader.cpp
        udpheader.h udpheader.cpp
        packetworker.h packetworker.cpp
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET my_IDS APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(my_IDS SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(my_IDS
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(my_IDS PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    ${PCAP_LIB}
    nlohmann_json::nlohmann_json
)
target_include_directories(my_IDS PRIVATE ${CMAKE_SOURCE_DIR}/external/termcolor)


# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.my_IDS)
endif()
set_target_properties(my_IDS PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS my_IDS
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(my_IDS)
endif()
