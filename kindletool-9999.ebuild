# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header$

EAPI="4"

inherit git-2

MY_PN="KindleTool"

DESCRIPTION="Tool for creating/extracting Kindle updates and more"
#HOMEPAGE="https://github.com/yifanlu/${MY_PN}"
HOMEPAGE="https://github.com/NiLuJe/${MY_PN}"
SRC_URI=""

#EGIT_REPO_URI="https://github.com/yifanlu/${MY_PN}.git"
EGIT_REPO_URI="https://github.com/NiLuJe/${MY_PN}.git"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="debug"

RDEPEND=""
DEPEND="${RDEPEND}
	dev-libs/openssl
	app-arch/libarchive[zlib]"

DOCS=( "README" )

S="${WORKDIR}/${MY_PN}"

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

src_install() {
	local outdir
	if use debug; then
		outdir="Debug"
	else
		outdir="Release"
	fi

	dobin ${MY_PN}/${outdir}/${PN} || die "failed to install ${PN} binary"

	doman ${MY_PN}/${PN}.1 || die "failed to install ${PN} manpage"

	dodoc README || die "failed to install ${PN} doc"
}
