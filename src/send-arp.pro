TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
	arp_utils.cpp \
	arphdr.cpp \
	ethhdr.cpp \
	interface_util.cpp \
	ip.cpp \
	mac.cpp \
	main.cpp \
	relay.cpp

HEADERS += \
	arp_utils.h \
	arphdr.h \
	ethhdr.h \
	interface_utils.h \
	ip.h \
	mac.h \
	relay.h \
	session.h
