#!/usr/bin/env python2

from operator import itemgetter
import pprint

model_tuples = [
	('Kindle1', 0x01),
	('Kindle2US', 0x02),
	('Kindle2International', 0x03),
	('KindleDXUS', 0x04),
	('KindleDXInternational', 0x05),
	('KindleDXGraphite', 0x09),
	('Kindle3Wifi', 0x08),
	('Kindle3Wifi3G', 0x06),
	('Kindle3Wifi3GEurope', 0x0A),
	('Kindle4NonTouch', 0x0E),
	('Kindle5TouchWifi3G', 0x0F),
	('Kindle5TouchWifi', 0x11),
	('Kindle5TouchWifi3GEurope', 0x10),
	('Kindle5TouchUnknown', 0x12),
	('Kindle4NonTouchBlack', 0x23),
	('KindlePaperWhiteWifi', 0x24),
	('KindlePaperWhiteWifi3G', 0x1B),
	('KindlePaperWhiteWifi3GCanada', 0x1C),
	('KindlePaperWhiteWifi3GEurope', 0x1D),
	('KindlePaperWhiteWifi3GJapan', 0x1F),
	('KindlePaperWhiteWifi3GBrazil', 0x20),
	('KindlePaperWhite2Wifi', 0xD4),
	('KindlePaperWhite2WifiJapan', 0x5A),
	('KindlePaperWhite2Wifi3G', 0xD5),
	('KindlePaperWhite2Wifi3GCanada', 0xD6),
	('KindlePaperWhite2Wifi3GEurope', 0xD7),
	('KindlePaperWhite2Wifi3GRussia', 0xD8),
	('KindlePaperWhite2Wifi3GJapan', 0xF2),
	('KindlePaperWhite2Wifi4GBInternational', 0x17),
	('KindlePaperWhite2Wifi3G4GBEurope', 0x60),
	('KindlePaperWhite2Unknown_0xF4', 0xF4),
	('KindlePaperWhite2Unknown_0xF9', 0xF9),
	('KindlePaperWhite2Wifi3G4GB', 0x62),
	('KindlePaperWhite2Unknown_0x61', 0x61),
	('KindlePaperWhite2Unknown_0x5F', 0x5F),
	('KindleBasic', 0xC6),
	('ValidKindleIcewine_0x13', 0x13),
	('ValidKindleUnknown_0x16', 0x16),
	('ValidKindleUnknown_0x21', 0x21),
	('ValidKindleIcewine_0x54', 0x54),
	('ValidKindleIcewine_0x2A', 0x2A),
	('ValidKindleIcewine_0x4F', 0x4F),
	('ValidKindleIcewine_0x52', 0x52),
	('ValidKindleIcewine_0x53', 0x53),
	('KindleUnknown', 0x00)
]

print 'Kindle models sorted by device code\n'
pp = pprint.PrettyPrinter(indent=4)
pp.pprint(sorted(model_tuples, key=itemgetter(1)))

print '\nKindle models >= KindlePaperWhite2WifiJapan\n'
cutoff_id = [v for i, v in enumerate(model_tuples) if v[0] == 'KindlePaperWhite2WifiJapan']
for t in model_tuples:
	# Print anything greater or equal than KindlePaperWhite2WifiJapan
	if t[1] >= cutoff_id[0][1]:
		print t
