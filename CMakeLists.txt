cmake_minimum_required(VERSION 3.18)

project(Qt_IDS VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 REQUIRED COMPONENTS Widgets Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Core)
find_library(PCAP_LIB pcap REQUIRED)
find_package(nlohmann_json REQUIRED)
message(STATUS "PCAP_LIB - "${PCAP_LIB})

# packet parsing and threat detection, shared by the app and the tests
add_library(qt_ids_core STATIC
        headers/ethernetheader.h
        headers/ethernetheader.cpp
        headers/icmpheader.h
        headers/icmpheader.cpp
        headers/ipv4header.h
        headers/ipv4header.cpp
        headers/tcpheader.h
        headers/tcpheader.cpp
        headers/udpheader.h
        headers/udpheader.cpp
        threatDetector/threatdetector.h
        threatDetector/threatdetector.cpp
        packetHandlers/packethandler.h
        packetHandlers/packethandler.cpp
)

target_link_libraries(qt_ids_core PUBLIC
    Qt${QT_VERSION_MAJOR}::Core
    ${PCAP_LIB}
    nlohmann_json::nlohmann_json
)

set(PROJECT_SOURCES
        main.cpp
        Qt/mainwindow.cpp
        Qt/mainwindow.h
        Qt/mainwindow.ui
        Qt/secondmainwindow.h
        Qt/secondmainwindow.cpp
        Qt/secondmainwindow.ui
        Qt/anim.h
        packetHandlers/packetworker.h
        packetHandlers/packetworker.cpp
)

qt_add_executable(Qt_IDS
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
)

target_link_libraries(Qt_IDS PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    qt_ids_core
)

set_target_properties(Qt_IDS PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER com.example.my_IDS
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
)

include(GNUInstallDirs)
install(TARGETS Qt_IDS
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

qt_finalize_executable(Qt_IDS)
