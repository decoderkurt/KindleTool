# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header$

EAPI="4"

inherit base vcs-snapshot

MY_PN="KindleTool"

DESCRIPTION="Tool for creating/extracting Kindle updates and more"
HOMEPAGE="https://github.com/NiLuJe/${MY_PN}"
SRC_URI="https://github.com/NiLuJe/${MY_PN}/tarball/v${PV} -> ${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="amd64 arm x86 x64-macos x86-macos x86-winnt"
IUSE="debug"

RDEPEND=""
DEPEND="${RDEPEND}
	dev-libs/openssl
	app-arch/libarchive[zlib]"

DOCS=( "README.md" )

src_configure() {
	einfo "Nothing to configure."
}

src_compile() {
	if use debug; then
		emake DEBUG="true" || die "failed to build ${PN}"
	else
		emake || die "failed to build ${PN}"
	fi
}
