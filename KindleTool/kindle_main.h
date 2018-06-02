/*
**  KindleTool, kindle_main.h
**
**  Copyright (C) 2011-2012  Yifan Lu
**  Copyright (C) 2012-2018  NiLuJe
**  Concept based on an original Python implementation by Igor Skochinsky & Jean-Yves Avenard,
**    cf., http://www.mobileread.com/forums/showthread.php?t=63225
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __KINDLETOOL_MAIN_H
#define __KINDLETOOL_MAIN_H

#include "kindle_tool.h"

// Ugly globals.
unsigned int kt_with_unknown_devcodes;
char         kt_tempdir[PATH_MAX];

static int kindle_print_help(const char*);
static int kindle_print_version(const char*);
static int kindle_deobfuscate_main(int, char**);
static int kindle_obfuscate_main(int, char**);
static int kindle_info_main(int, char**);

#endif
