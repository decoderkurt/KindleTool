#!/bin/bash

# Build a make include with, among other things, our version tag, straight from git (Heavily inspired from git's GIT-VERSION-GEN)
VER_FILE="version-inc"

# Fallback version
FALLBACK_VER="v1.5.0-GIT"

# Apparently, bsdmake hates me, so, get uname's output from here
UNAME="$(uname -s)"

# Used to add a Linux like user@host compile-time tag
COMPILE_BY="$(whoami | sed 's/\\/\\\\/')"

case "${UNAME}" in
	CYGWIN* )
		# Cygwin's version of hostname doesn't handle the -s flag...
		COMPILE_HOST="$(hostname)"
	;;
	* )
		# Use short hostname, OS X defaults to fqdn...
		COMPILE_HOST="$(hostname -s)"
	;;
esac

# On Linux, check libarchive's version and get the proper CPP/LDFLAGS via pkg-config, to make sure we pickup the correct libarchive version
if [[ "${UNAME}" == "Linux" ]] ; then
	if pkg-config --atleast-version=3.0.3 libarchive ; then
		HAS_PC_LIBARCHIVE="true"
		PC_LIBARCHIVE_CPPFLAGS="$(pkg-config --cflags-only-I libarchive)"
		PC_LIBARCHIVE_LDFLAGS="$(pkg-config --libs-only-L libarchive)"
	else
		HAS_PC_LIBARCHIVE="false"
		PC_LIBARCHIVE_CPPFLAGS=""
		PC_LIBARCHIVE_LDFLAGS=""
		echo "**!** @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ **!**"
		echo "**!** pkg-config didn't find libarchive >= 3.0.3, don't be surprised if the build fails! **!**"
		echo "**!** @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ **!**"
	fi

	# Also check the distro name, we'll use pkg-config's cflags in the Makefile on every distro out there except Gentoo, in order
	# to link against the correct libarchive version on distros where libarchive-2 and libarchive-3 can coexist (Debian/Ubuntu, for example).
	# NOTE: I'm fully aware that lsb_release is not installed/properly setup by default on every distro,
	# but the only distro on which the Makefile expects this to be accurate is Gentoo, so that should cover it ;).
	if [[ -f /etc/lsb-release ]] ; then
		. /etc/lsb-release
	else
		if [[ -f /etc/gentoo-release ]] ; then
			# Make sure we detect Gentoo, even if sys-apps/lsb-release isn't installed
			DISTRIB_ID="Gentoo"
		else
			DISTRIB_ID="Unknown"
		fi
	fi
fi

# If we don't have git installed (Why, oh why would you do that? :D), just use the fallback
if ! git help &>/dev/null ; then
	echo "${FALLBACK_VER}" > VERSION
fi

# If we have a VERSION file, just use that (that's useful for package managers)
# Otherwise, and if we have a proper git repo, use git!
if [[ -f "VERSION" ]] ; then
	VER="$(< VERSION)"
elif [[ -z "${VER}" && -d "../.git" || -f ".git" ]] ; then
	# Get a properly formatted version string from our latest tag
	VER="$(git describe --match "v[0-9]*" HEAD 2>/dev/null)"
	# Or from the first commit (provided we manually tagged $(git rev-list --max-parents=0 HEAD) as TAIL, which we did)
	#VER="$(git describe --match TAIL 2>/dev/null)"
	case "$VER" in
		v[0-9]*)
			# Check if our working directory is dirty
			git update-index -q --refresh
			[[ -z "$(git diff-index --name-only HEAD --)" ]] || VER="${VER}-dirty"
			# - => .
			#VER=${VER//-/.}
		;;
		TAIL*)
			git update-index -q --refresh
			[[ -z "$(git diff-index --name-only HEAD --)" ]] || VER="${VER}-dirty"
			# - => .
			#VER=${VER//-/.}
			# TAIL- => r (ala SVN)
			VER="${VER//TAIL-/r}"
			# Technically, we get the number of commits *after* TAIL, so, effectively, TAIL is r0, not r1 like in SVN.
			# Tweak the output some more to fake that :).
			# Strip everything after the first dash
			REV="${VER%%-*}"
			# Strip the first char (r)
			REV="${REV:1}"
			# Fake our rev number
			FREV="$(( REV + 1))"
			# NOTE: In our case, another cheap way to get this commit count would be via $(git rev-list HEAD | wc -l)
			# Switch the rev number in our final output
			VER="${VER/r${REV}/r${FREV}}"
		;;
		*)
			VER="${FALLBACK_VER}"
	esac
else
	VER="${FALLBACK_VER}"
fi

# Strip the leading 'v'
#VER=${VER#v*}

# Get current version from include file
if [[ -r "${VER_FILE}" ]] ; then
	VER_CURRENT="$(cat ${VER_FILE} | head -n 1)"
	# Strip var assignment
	VER_CURRENT="${VER_CURRENT/KT_VERSION = /}"
else
	VER_CURRENT="unset"
fi

# Update our include file, if need be
if [[ "${VER}" != "${VER_CURRENT}" ]] ; then
	echo >&2 "KT_VERSION = ${VER}"
	echo "KT_VERSION = ${VER}" > ${VER_FILE}
	echo "OSTYPE = ${UNAME}" >> ${VER_FILE}
	echo "COMPILE_BY = ${COMPILE_BY}" >> ${VER_FILE}
	echo "COMPILE_HOST = ${COMPILE_HOST}" >> ${VER_FILE}
	if [[ "${UNAME}" == "Linux" ]] ; then
		echo "HAS_PC_LIBARCHIVE = ${HAS_PC_LIBARCHIVE}" >> ${VER_FILE}
		echo "PC_LIBARCHIVE_CPPFLAGS = ${PC_LIBARCHIVE_CPPFLAGS}" >> ${VER_FILE}
		echo "PC_LIBARCHIVE_LDFLAGS = ${PC_LIBARCHIVE_LDFLAGS}" >> ${VER_FILE}
		echo "DISTRIB_ID = ${DISTRIB_ID}" >> ${VER_FILE}
	fi
fi

# Build a proper VERSION file (PMS)
if [[ "${1}" == "PMS" ]] ; then
	echo "${VER}" > VERSION
fi
