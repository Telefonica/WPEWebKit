# - Try to find nxclient
#
# Copyright (C) Telefónica S.A.
# Author: Álvaro Peña <alvaropg@gmail.com>

find_package(PkgConfig)
pkg_check_modules(PC_NXCLIENT REQUIRED nxclient)

if(PC_NXCLIENT_FOUND)
  set(NXCLIENT_INCLUDE_DIRS ${PC_NXCLIENT_INCLUDE_DIRS})
  set(NXCLIENT_LIBRARIES ${PC_NXCLIENT_LDFLAGS})
  set(NXCLIENT_VERSION ${PC_NXCLIENT_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(nxclient
  REQUIRED_VARS NXCLIENT_INCLUDE_DIRS NXCLIENT_LIBRARIES
  VERSION_VAR NXCLIENT_VERSION)

mark_as_advanced(
  NXCLIENT_INCLUDE_DIRS
  NXCLIENT_LIBRARIES
  )
