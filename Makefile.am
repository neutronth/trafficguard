AM_CPPFLAGS = -I$(top_srcdir)/lib/atscppapi/src/include \
  -Wno-unused-variable \
  -std=c++11
target = TrafficGuard.so
pkglibdir = ${pkglibexecdir}
pkglib_LTLIBRARIES = TrafficGuard.la

TrafficGuard_la_SOURCES = \
  TrafficGuard.cc \
  Blacklist.h \
  Blacklist.cc

TrafficGuard_la_LDFLAGS = -module -avoid-version -shared \
  -L/usr/lib/trafficserver/ -latscppapi \
  -lpthread \
  -lpcrecpp \
  -ljsoncpp

all:
	ln -sf .libs/$(target)

clean-local:
	rm -f $(target)
