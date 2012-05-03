#!/bin/sh

# Build a make include with our version tag, from git & gcc (Heavily inspired from git's GIT-VERSION-GEN)
VER_FILE="version-inc"

# Fallback version
FALLBACK_VER="v0.5-GIT"

# Get the GCC version number, if we passed one
if [[ -n "$1" ]] ; then
	VER_GCC=" (GCC ${1})"
fi

# If we have a VERSION file, just use that (that's useful for package managers)
# Otherwise, and if we have a proper git repo, use git!
if [[ -f "VERSION" ]] ; then
	VER="$(< VERSION)"
elif [ -z "${VER}" -a -d "../.git" -o -f ".git" ] ; then
	# Get a properly formatted version string from our latest tag
	VER="$(git describe --match "v[0-9]*" HEAD 2>/dev/null)"
	case "$VER" in
		v[0-9]*)
			# Check if our working directory is dirty
			git update-index -q --refresh
			[[ -z "$(git diff-index --name-only HEAD --)" ]] || VER="${VER}-dirty"
			# - => .
			#VER=${VER//-/.}
		;;
		*)
			VER="${FALLBACK_VER}"
	esac
else
	VER="${FALLBACK_VER}"
fi

# Add the GCC Version
VER="${VER}${VER_GCC}"

# Strip the leading 'v'
#VER=${VER#v*}

# Get current version from include file
if [[ -r "${VER_FILE}" ]] ; then
	VER_CURRENT="$(sed -e 's/^KT_VERSION = //' <${VER_FILE})"
else
	VER_CURRENT="unset"
fi

# Update our include file, if need be
if [[ "${VER}" != "${VER_CURRENT}" ]] ; then
	echo >&2 "KT_VERSION = ${VER}"
	echo "KT_VERSION = ${VER}" >${VER_FILE}
fi

# Build a proper VERSION file (PMS)
if [[ "${2}" == "PMS" ]] ; then
	echo "${VER}" > VERSION
fi
