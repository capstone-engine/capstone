# Copyright © 2024 Andrew Quijano <andrewquijano92@gmail.com>
# SPDX-License-Identifier: MIT

# Used to dynamically set the package file name based on the generator
foreach(generator ${CPACK_GENERATOR})
    if("${generator}" STREQUAL "DEB")
        set(CPACK_PACKAGE_FILE_NAME ${CPACK_DEBIAN_PACKAGE_FILE_NAME})
    elseif("${generator}" STREQUAL "RPM")
        set(CPACK_PACKAGE_FILE_NAME ${CPACK_RPM_PACKAGE_FILE_NAME})
    elseif("${generator}" STREQUAL "NSIS")
        set(CPACK_PACKAGE_FILE_NAME ${CPACK_NSIS_PACKAGE_FILE_NAME})
    elseif("${generator}" STREQUAL "DragNDrop")
        set(CPACK_PACKAGE_FILE_NAME ${CPACK_DMG_PACKAGE_FILE_NAME})
    elseif("${generator}" STREQUAL "TGZ")
        set(CPACK_PACKAGE_FILE_NAME ${CPACK_TGZ_PACKAGE_FILE_NAME})
    else()
        set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-unknown")
    endif()
    message(STATUS "Generating package for ${generator} with file name ${CPACK_PACKAGE_FILE_NAME}")
endforeach()
