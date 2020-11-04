#
# Copyright (C) 2015 Cybernetica
#
# Research/Commercial License Usage
# Licensees holding a valid Research License or Commercial License
# for the Software may use this file according to the written
# agreement between you and Cybernetica.
#
# GNU General Public License Usage
# Alternatively, this file may be used under the terms of the GNU
# General Public License version 3.0 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.  Please review the following information to
# ensure the GNU General Public License version 3.0 requirements will be
# met: http://www.gnu.org/copyleft/gpl-3.0.html.
#
# For further information, please contact us at sharemind@cyber.ee.
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.0)
PROJECT(SharemindModAbyEmu VERSION 1.1.3 LANGUAGES CXX)

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers 1.6 REQUIRED)

FIND_PACKAGE(Boost 1.62 REQUIRED)
FIND_PACKAGE(LogHard 0.5.0 REQUIRED)
FIND_PACKAGE(SharemindCHeaders 1.3.0 REQUIRED)
FIND_PACKAGE(SharemindCxxHeaders 0.8.0 REQUIRED)
FIND_PACKAGE(SharemindLibConfiguration 0.5.0 REQUIRED)
FIND_PACKAGE(SharemindLibEmulatorProtocols 0.2.0 REQUIRED)
FIND_PACKAGE(SharemindLibExecutionModelEvaluator 0.3.0 REQUIRED)
FIND_PACKAGE(SharemindLibExecutionProfiler 0.4.0 REQUIRED)
FIND_PACKAGE(SharemindModuleApis 1.1.0 REQUIRED)
FIND_PACKAGE(SharemindPdkHeaders 0.5.0 REQUIRED)


SharemindSetCxx14CompileOptions()
IF(SHAREMIND_NETWORK_STATISTICS)
    SharemindNewList(SharemindModAbyEmu_EXTRA_DEFINITIONS
        "SHAREMIND_NETWORK_STATISTICS_ENABLE"
    )
ELSE()
    SharemindNewList(SharemindModAbyEmu_EXTRA_DEFINITIONS)
ENDIF()
FILE(GLOB_RECURSE SharemindModAbyEmu_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
FILE(GLOB_RECURSE SharemindModAbyEmu_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
SharemindAddSharedLibrary(ModAbyEmu
    MODULE
    OUTPUT_NAME "sharemind_mod_aby_emu"
    SOURCES
        ${SharemindModAbyEmu_SOURCES}
        ${SharemindModAbyEmu_HEADERS}
)
TARGET_LINK_LIBRARIES(ModAbyEmu
    PRIVATE
        Boost::boost
        LogHard::LogHard
        Sharemind::CHeaders
        Sharemind::CxxHeaders
        Sharemind::LibConfiguration
        Sharemind::LibEmulatorProtocols
        Sharemind::LibExecutionModelEvaluator
        Sharemind::LibExecutionProfiler
        Sharemind::ModuleApis
        Sharemind::PdkHeaders
    )

FILE(GLOB_RECURSE SharemindModAbyEmu_DEBUG_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/debug_files/*.cfg")
ADD_CUSTOM_TARGET("include_SharemindModAbyEmu_DEBUG_FILES_in_IDE" SOURCES
                  ${SharemindModAbyEmu_DEBUG_FILES})
IF(NOT (CMAKE_BUILD_TYPE STREQUAL "Release"))
    INSTALL(FILES ${SharemindModAbyEmu_DEBUG_FILES}
            DESTINATION "bin"
            COMPONENT "debugconf")
ENDIF()

# Configuration files:
INSTALL(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/packaging/configs/sharemind/"
        DESTINATION "/etc/sharemind/"
        COMPONENT "lib"
        EXCLUDE_FROM_ALL)

# Packaging:
SharemindSetupPackaging()
SharemindAddComponentPackage("lib"
    NAME "libsharemind-mod-aby-emu"
    DESCRIPTION "Sharemind ABY emulation module"
    DEB_SECTION "libs"
    DEB_DEPENDS
        "libloghard (>= 0.5.0)"
        "libsharemind-configuration (>= 0.5.0)"
        "libsharemind-executionmodelevaluator (>= 0.3.0)"
        "libsharemind-executionprofiler (>= 0.4.0)"
        "libstdc++6 (>= 4.8.0)"
        "libc6 (>= 2.19)"
    DEB_EXTRA_CONTROL_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/conffiles"
)
SharemindAddComponentPackage("debug"
    NAME "libsharemind-mod-aby-emu-dbg"
    DESCRIPTION "Sharemind ABY emulation module debug symbols"
    DEB_SECTION "debug"
    DEB_DEPENDS
        "libsharemind-mod-aby-emu (= ${SharemindModAbyEmu_DEB_lib_PACKAGE_VERSION})"
)
SharemindPackagingFinalize()
