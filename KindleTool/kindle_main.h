//
//  kindle_main.h
//  KindleTool
//
//  Copyright (C) 2011-2015  Yifan Lu
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#ifndef KINDLEMAIN
#define KINDLEMAIN

// Ugly global.
unsigned int kt_with_unknown_devcodes;

static int kindle_print_help(const char *);
static int kindle_print_version(const char *);
static int kindle_deobfuscate_main(int, char **);
static int kindle_obfuscate_main(int, char **);
static int kindle_info_main(int, char **);

#endif

// kate: indent-mode cstyle; indent-width 4; replace-tabs on;
