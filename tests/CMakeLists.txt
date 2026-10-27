find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test)

foreach(test_name tst_headers tst_threatdetector tst_packethandler)
    add_executable(${test_name} ${test_name}.cpp packetbuilder.h)
    target_link_libraries(${test_name} PRIVATE
        qt_ids_core
        Qt${QT_VERSION_MAJOR}::Test
    )
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
