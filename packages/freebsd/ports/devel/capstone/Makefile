# $FreeBSD$

PORTNAME=	capstone
PORTVERSION=	2.0
CATEGORIES=	devel
MASTER_SITES=	http://capstone-engine.org/download/2.0/

MAINTAINER=	oliver.pntr@gmail.com
COMMENT=	multi-platform, multi-architecture disassembly framework

LICENSE=	BSD

USES=		gmake

MAKE_ENV=	INSTALL_DATA="${INSTALL_DATA}"
MAKE_ENV+=	INSTALL_LIBRARY="${INSTALL_DATA}"

pre-install:
	@${REINPLACE_CMD} -e '/libdir/s|/usr/ports/devel/capstone/work/stage||g' ${WRKSRC}/capstone.pc

.include <bsd.port.mk>

