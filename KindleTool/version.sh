#!/bin/bash

# Build a make include with our version tag, from git & gcc (Heavily inspired from git's GIT-VERSION-GEN)
VER_FILE="version-inc"

# Fallback version
FALLBACK_VER="v1.2-GIT"

# Apparently, bsdmake hates me, so, get uname's output from here
UNAME="$(uname -s)"

# Used to add a Linux like user@host compile-time tag
COMPILE_BY="$(whoami | sed 's/\\/\\\\/')"
COMPILE_HOST="$(hostname)"

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
	#VER="$(git describe --match "v[0-9]*" HEAD 2>/dev/null)"
	# Or from the first commit (Provided we manually tagged $(git rev-list --max-parents=0 HEAD) as TAIL, which we did)
	VER="$(git describe --match TAIL 2>/dev/null)"
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
	VER_CURRENT="$(<${VER_FILE})"
	# Strip var assignment
	VER_CURRENT="${VER_CURRENT/KT_VERSION = /}"
else
	VER_CURRENT="unset"
fi

# Update our include file, if need be
if [[ "${VER}" != "${VER_CURRENT}" ]] ; then
	echo >&2 "KT_VERSION = ${VER}"
	echo "KT_VERSION = ${VER}" > ${VER_FILE}
	#echo >&2 "OSTYPE = ${UNAME}"
	echo "OSTYPE = ${UNAME}" >> ${VER_FILE}
	echo "COMPILE_BY = ${COMPILE_BY}" >> ${VER_FILE}
	echo "COMPILE_HOST = ${COMPILE_HOST}" >> ${VER_FILE}
fi

# Build a proper VERSION file (PMS)
if [[ "${1}" == "PMS" ]] ; then
	echo "${VER}" > VERSION
fi
