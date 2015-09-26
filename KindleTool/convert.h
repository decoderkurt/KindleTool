//
//  convert.h
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

#ifndef KINDLECONVERT
#define KINDLECONVERT

static const char *convert_magic_number(char *);

static char *to_base(int64_t, unsigned int);

static int kindle_read_bundle_header(UpdateHeader *, FILE *);
static int kindle_convert(FILE *, FILE *, FILE *, const unsigned int, const unsigned int, FILE *, char *);
static int kindle_convert_ota_update_v2(FILE *, FILE *, const unsigned int, char *);
static int kindle_convert_signature(UpdateHeader *, FILE *, FILE *);
static int kindle_convert_ota_update(UpdateHeader *, FILE *, FILE *, const unsigned int, char *);
static int kindle_convert_recovery(UpdateHeader *, FILE *, FILE *, const unsigned int, char *);
static int kindle_convert_recovery_v2(FILE *, FILE *, const unsigned int, char *);

static int libarchive_extract(const char *, const char *);

#endif

// kate: indent-mode cstyle; indent-width 4; replace-tabs on;
