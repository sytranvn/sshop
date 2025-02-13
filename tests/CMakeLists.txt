if (UNIT_TESTING)
    find_package(CMocka REQUIRED)
endif ()

enable_testing()
include(CTest)

foreach(_UNIT_TEST ${LIBSSH_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES}
    )

    set_property(TEST ${_UNIT_TEST}
                 PROPERTY
                     ENVIRONMENT ${TORTURE_UNIT_ENVIRONMENT})
endforeach()
