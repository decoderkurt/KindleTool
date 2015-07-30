#!/usr/bin/env python2

from operator import itemgetter

model_tuples = [
	('Kindle1', 0x01, 'ATVPDKIKX0DER'),
	('Kindle2US', 0x02, 'A3UN6WX5RRO2AG'),
	('Kindle2International', 0x03, 'A1F83G8C2ARO7P'),
	('KindleDXUS', 0x04, 'A1PA6795UKMFR9'),
	('KindleDXInternational', 0x05, 'A13V1IB3VIYZZH'),
	('ValidKindleUnknown_0x07', 0x07, 'A2EUQ1WTGCTBG2'),
	('Kindle3Wifi3G', 0x06, 'A1VC38T7YXB528'),
	('Kindle3Wifi', 0x08, 'A3AEGXETSR30VB'),
	('KindleDXGraphite', 0x09, 'A3P5ROKL5A1OLE'),
	('Kindle3Wifi3GEurope', 0x0A, 'A3JWKAKR8XB7XF'),
	('ValidKindleUnknown_0x0B', 0x0B, 'A1X6FK5RDHNB96'),
	('ValidKindleUnknown_0x0C', 0x0C, 'AN1VRQENFRJN5'),
	('ValidKindleUnknown_0x0D', 0x0D, 'A3DWYIK6Y9EEQB'),
	('Kindle4NonTouch', 0x0E, 'A3R76HOPU0Z2CB'),
	('Kindle5TouchWifi3G', 0x0F, 'A1IM4EOPHS76S7'),
	('Kindle5TouchWifi3GEurope', 0x10, 'A138L1TOL8PIJT'),
	('Kindle5TouchWifi', 0x11, 'A3T4TT2Z381HKD'),
	('Kindle5TouchUnknown', 0x12, 'A3LJ5WMKNRFKQS'),
	('KindlePaperWhiteWifi3G', 0x1B, 'A1JYRMDPD0WRC1'),
	('KindlePaperWhiteWifi3GCanada', 0x1C, 'A1U5RCOVU0NYF2'),
	('KindlePaperWhiteWifi3GEurope', 0x1D, 'A1I7TFXKDRQDZL'),
	('KindlePaperWhiteWifi3GJapan', 0x1F, 'A1K21FY43GMZF8'),
	('KindlePaperWhiteWifi3GBrazil', 0x20, 'A3RN7G7QC5MWSZ'),
	('Kindle4NonTouchBlack', 0x23),
	('KindlePaperWhiteWifi', 0x24, 'A3VSAZHKW7EWVH'),
	('KindlePaperWhite2WifiJapan', 0x5A, 'A1XFE4LQM16OSW'),
	('KindlePaperWhite2Wifi', 0xD4, 'A2X1JOFWQIYV75'),
	('KindlePaperWhite2Wifi3G', 0xD5, 'A2LTUGSV2JQ93O'),
	('KindlePaperWhite2Wifi3GCanada', 0xD6, 'A3CG2RMGG8NQEJ'),
	('KindlePaperWhite2Wifi3GEurope', 0xD7, 'A2RWEQK36M6DUE'),
	('KindlePaperWhite2Wifi3GRussia', 0xD8, 'A3DM9ZTSZGUSMW'),
	('KindlePaperWhite2Wifi3GJapan', 0xF2, 'A36L7QE2V0XKCZ'),
	('KindlePaperWhite2Wifi4GBInternational', 0x17, 'A3I3CR3NPZFVHY'),
	('KindlePaperWhite2Wifi3G4GBCanada', 0x5F, 'A16EMENY0O3Z2H'),
	('KindlePaperWhite2Wifi3G4GBEurope', 0x60, 'A3D1N3J5SXSYPF'),
	('KindlePaperWhite2Unknown_0x61', 0x61, 'A3NRQ2KXEO33BF'),
	('KindlePaperWhite2Wifi3G4GB', 0x62, 'A3QT0UFVNUDPAE'),
	('KindlePaperWhite2Unknown_0xF4', 0xF4),
	('KindlePaperWhite2Unknown_0xF9', 0xF9),
	('KindleVoyageWifi', 0x13, 'A3FE7AD5N5R11'),
	('KindleVoyageWifi3G', 0x54, 'A1VHVRSIVA49BF'),
	('KindleVoyageUnknown_0x2A', 0x2A, 'A2KSI370ME58SV'),
	('KindleVoyageUnknown_0x4F', 0x4F, 'AEK24W3B90XSI'),
	('KindleVoyageUnknown_0x52', 0x52, 'A66ZTOXC8UWFP'),
	('KindleVoyageWifi3GEurope', 0x53, 'A26JMGYIXWMKGL'),
	('KindleBasic', 0xC6, 'A2TNPB8EVLW5FA'),
	('ValidKindleUnknown_0x99', 0x99, 'A2I96HKA5TK143'),
	('KindleBasicUnknown_0xDD', 0xDD, 'A9N06WOIL49CA'),
	('ValidKindleUnknown_0x16', 0x16),
	('ValidKindleUnknown_0x21', 0x21),
	('KindlePaperWhite3', 0x90),
	('KindleUnknown', 0x00)
]
# FIXME: PW3 is inaccurate, the device id potentially moved 2 chars to the right? First char (?) often seems to be 9? Might we sometime find our good old B there, too?
#('KindlePaperWhite3Wifi_0x0G1', 0x?0G1, 'A21RY355YUXQAF')
#('KindlePaperWhite3Unknown_0x0G2', 0x?0G2, 'A6S0KGW65V1TV')
#('KindlePaperWhite3Unknown_0x0G4', 0x?0G4, 'A3P87LH4DLAKE2')
#('KindlePaperWhite3Unknown_0x0G5', 0x?0G5, 'A3OLIINW419WLP')
#('KindlePaperWhite3Unknown_0x0G6', 0x?0G6, 'AOPKCG97868D2')
#('KindlePaperWhite3Unknown_0x0G7', 0x?0G7, 'A3MTNJ7FDYZOPO')


print 'Kindle models sorted by device code\n'
for t in sorted(model_tuples, key=itemgetter(1)):
	print "{:<40} {:02X} {:10} {:<14}".format(t[0], t[1], '', t[2] if len(t) == 3 else '')

print '\nKindle models >= KindleVoyageUnknown_0x2A\n'
cutoff_id = 0
for i, v in enumerate(model_tuples):
	if v[0] == 'KindleVoyageUnknown_0x2A':
		cutoff_id = v[1]

for t in model_tuples:
	if t[1] >= cutoff_id:
		print "{:<40} {:02X}".format(t[0], t[1])
