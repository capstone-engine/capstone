# $FreeBSD$

PORTNAME=	capstone
PORTVERSION=	4.0.0
CATEGORIES=	devel
MASTER_SITES=	http://capstone-engine.org/download/${PORTVERSION}/

MAINTAINER=	oliver.pntr@gmail.com
COMMENT=	Multi-platform, multi-architecture disassembly framework

LICENSE=	BSD3CLAUSE

USES=		gmake
USE_LDCONFIG=	yes

MAKE_ENV+=	INSTALL_LIB="${INSTALL_LIB}" \
		INSTALL_DATA="${INSTALL_DATA}"

post-build:
	# The pkgconfig file is generated and points to stagedir
	${REINPLACE_CMD} -e '/libdir/s|\(libdir=\)\(.*\)\(devel/capstone/work/stage\)|\1|g' ${WRKSRC}/capstone.pc

.include <bsd.port.mk>
