#!/bin/sh

# Build a header file with our version tag, from git & gcc (Heavily inspired from mplayer's version.sh)

# Get the GCC version number, if we passed one
if [[ -n "$1" ]] ; then
	gcc_ver=" (GCC ${1})"
fi

# If we have a VERSION file, just use that (that's useful for package managers)
if [[ -f "VERSION" ]] ; then
	version="$(< VERSION)"
fi

# Otherwise, use git!
if [[ -z "${version}" ]] ; then
	git_rev="$(git describe --always HEAD 2>/dev/null)"
	# If that didn't work, well, tough luck.
	[[ -z "${git_rev}" ]] && git_rev="git"

	version="${git_rev}"
fi

REVISION="#define KT_REV \"${version}${gcc_ver}\""

# Build our header file
echo "${REVISION}" > version.h
