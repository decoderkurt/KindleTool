#!/usr/bin/env python2

from operator import itemgetter

# NOTE: Pilfered from https://code.activestate.com/recipes/65212/
# FIXME: Crockford's Base32, but with the "L" & "U" re-added in?
def baseN(num, base, numerals="0123456789ABCDEFGHJKLMNPQRSTUVWX"):
	if num == 0:
		return "0"

	if num < 0:
		return '-' + baseN((-1) * num, base, numerals)

	if not 2 <= base <= len(numerals):
		raise ValueError('Base must be between 2 and %d' % len(numerals))

	left_digits = num // base
	if left_digits == 0:
		return numerals[num % base]
	else:
		return baseN(left_digits, base, numerals) + numerals[num % base]

# NOTE: Pilfered from https://stackoverflow.com/questions/1119722/
BASE_LIST = tuple("0123456789ABCDEFGHJKLMNPQRSTUVWX")
BASE_DICT = dict((c, v) for v, c in enumerate(BASE_LIST))
BASE_LEN = len(BASE_LIST)

def devCode(str):
    num = 0
    for char in str:
        num = num * BASE_LEN + BASE_DICT[char]
    return num


model_tuples = [
	('Kindle1', 0x01, 'ATVPDKIKX0DER'),
	('Kindle2US', 0x02, 'A3UN6WX5RRO2AG'),
	('Kindle2International', 0x03, 'A1F83G8C2ARO7P'),
	('KindleDXUS', 0x04, 'A1PA6795UKMFR9'),
	('KindleDXInternational', 0x05, 'A13V1IB3VIYZZH'),
	('ValidKindleUnknown_0x07', 0x07, 'A2EUQ1WTGCTBG2'),
	('Kindle3WiFi3G', 0x06, 'A1VC38T7YXB528'),
	('Kindle3WiFi', 0x08, 'A3AEGXETSR30VB'),
	('KindleDXGraphite', 0x09, 'A3P5ROKL5A1OLE'),
	('Kindle3WiFi3GEurope', 0x0A, 'A3JWKAKR8XB7XF'),
	('ValidKindleUnknown_0x0B', 0x0B, 'A1X6FK5RDHNB96'),
	('ValidKindleUnknown_0x0C', 0x0C, 'AN1VRQENFRJN5'),
	('ValidKindleUnknown_0x0D', 0x0D, 'A3DWYIK6Y9EEQB'),
	('Kindle4NonTouch', 0x0E, 'A3R76HOPU0Z2CB'),
	('Kindle5TouchWiFi3G', 0x0F, 'A1IM4EOPHS76S7'),
	('Kindle5TouchWiFi3GEurope', 0x10, 'A138L1TOL8PIJT'),
	('Kindle5TouchWiFi', 0x11, 'A3T4TT2Z381HKD'),
	('Kindle5TouchUnknown', 0x12, 'A3LJ5WMKNRFKQS'),
	('KindlePaperWhiteWiFi3G', 0x1B, 'A1JYRMDPD0WRC1'),
	('KindlePaperWhiteWiFi3GCanada', 0x1C, 'A1U5RCOVU0NYF2'),
	('KindlePaperWhiteWiFi3GEurope', 0x1D, 'A1I7TFXKDRQDZL'),
	('KindlePaperWhiteWiFi3GJapan', 0x1F, 'A1K21FY43GMZF8'),
	('KindlePaperWhiteWiFi3GBrazil', 0x20, 'A3RN7G7QC5MWSZ'),
	('Kindle4NonTouchBlack', 0x23),
	('KindlePaperWhiteWiFi', 0x24, 'A3VSAZHKW7EWVH'),
	('KindlePaperWhite2WiFiJapan', 0x5A, 'A1XFE4LQM16OSW'),
	('KindlePaperWhite2WiFi', 0xD4, 'A2X1JOFWQIYV75'),
	('KindlePaperWhite2WiFi3G', 0xD5, 'A2LTUGSV2JQ93O'),
	('KindlePaperWhite2WiFi3GCanada', 0xD6, 'A3CG2RMGG8NQEJ'),
	('KindlePaperWhite2WiFi3GEurope', 0xD7, 'A2RWEQK36M6DUE'),
	('KindlePaperWhite2WiFi3GRussia', 0xD8, 'A3DM9ZTSZGUSMW'),
	('KindlePaperWhite2WiFi3GJapan', 0xF2, 'A36L7QE2V0XKCZ'),
	('KindlePaperWhite2WiFi4GBInternational', 0x17, 'A3I3CR3NPZFVHY'),
	('KindlePaperWhite2WiFi3G4GBCanada', 0x5F, 'A16EMENY0O3Z2H'),
	('KindlePaperWhite2WiFi3G4GBEurope', 0x60, 'A3D1N3J5SXSYPF'),
	('KindlePaperWhite2WiFi3G4GBBrazil', 0x61, 'A3NRQ2KXEO33BF'),
	('KindlePaperWhite2WiFi3G4GB', 0x62, 'A3QT0UFVNUDPAE'),
	('KindlePaperWhite2Unknown_0xF4', 0xF4),
	('KindlePaperWhite2Unknown_0xF9', 0xF9),
	('KindleVoyageWiFi', 0x13, 'A3FE7AD5N5R11'),
	('KindleVoyageWiFi3G', 0x54, 'A1VHVRSIVA49BF'),
	('KindleVoyageWiFi3GJapan', 0x2A, 'A2KSI370ME58SV'),
	('KindleVoyageUnknown_0x4F', 0x4F, 'AEK24W3B90XSI'),
	('KindleVoyageWiFi3GMexico', 0x52, 'A66ZTOXC8UWFP'),
	('KindleVoyageWiFi3GEurope', 0x53, 'A26JMGYIXWMKGL'),
	('KindleBasic', 0xC6, 'A2TNPB8EVLW5FA'),
	('ValidKindleUnknown_0x99', 0x99, 'A2I96HKA5TK143'),
	('KindleBasicKiwi', 0xDD, 'A9N06WOIL49CA'),
	('ValidKindleUnknown_0x16', 0x16),
	('ValidKindleUnknown_0x21', 0x21),
	('KindlePaperWhite3WiFi', 0x201, 'A21RY355YUXQAF'),		# 0G1
	('KindlePaperWhite3WiFi3G', 0x202, 'A6S0KGW65V1TV'),		# 0G2
	('KindlePaperWhite3WiFi3GMexico', 0x204, 'A3P87LH4DLAKE2'),	# 0G4
	('KindlePaperWhite3WiFi3GEurope', 0x205, 'A3OLIINW419WLP'),	# 0G5
	('KindlePaperWhite3WiFi3GCanada', 0x206, 'AOPKCG97868D2'),	# 0G6
	('KindlePaperWhite3WiFi3GJapan', 0x207, 'A3MTNJ7FDYZOPO'),	# 0G7
	('KindlePaperWhite3WhiteWiFi', 0x26B),				# 0KB
	('KindlePaperWhite3WhiteWiFi3GJapan', 0x26C),			# 0KC
	('KindlePW3WhiteUnknown_0KD', 0x26D),
	('KindlePaperWhite3WhiteWiFi3GInternational', 0x26E),		# 0KE
	('KindlePaperWhite3WhiteWiFi3GInternationalBis', 0x26F),	# 0KF
	('KindlePW3WhiteUnknown_0KG', 0x270),
	('KindlePaperWhite3WiFi32GBJapanBlack', 0x293),		# 0LK
	('KindlePaperWhite3WiFi32GBJapanWhite', 0x294),		# 0LL
	('KindleOasisWiFi', 0x20C),					# 0GC
	('KindleOasisWiFi3G', 0x20D),					# 0GD
	('KindleOasisWiFi3GInternational', 0x219),	# 0GR
	('KindleOasisUnknown_0GS', 0x21A),
	('KindleOasisWiFi3GChina', 0x21B),				# 0GT
	('KindleOasisWiFi3GEurope', 0x21C),				# 0GU
	('KindleBasic2Unknown_0DU', 0x1BC),
	('KindleBasic2', 0x269),					# 0K9
	('KindleBasic2White', 0x26A),					# 0KA
	('KindleOasis2Unknown_0LM', 0x295),				# 0LM?
	('KindleOasis2Unknown_0LN', 0x296),				# 0LN?
	('KindleOasis2Unknown_0LP', 0x297),				# 0LP?
	('KindleOasis2Unknown_0LQ', 0x298),				# 0LQ?
	('KindleOasis2Unknown_0P1', 0x2E1),				# 0P1?
	('KindleOasis2Unknown_0P2', 0x2E2),				# 0P2?
	('KindleOasis2Unknown_0P6', 0x2E6),				# 0P6?
	('KindleOasis2Unknown_0P7', 0x2E7),				# 0P7?
	('KindleOasis2WiFi8GB', 0x2E8),					# 0P8
	('KindleOasis2WiFi3G32GB', 0x341),				# 0S1
	('KindleOasis2WiFi3G32GBEurope', 0x342),			# 0S2
	('KindleOasis2Unknown_0S3', 0x343),				# 0S3?
	('KindleOasis2Unknown_0S4', 0x344),				# 0S4?
	('KindleOasis2Unknown_0S7', 0x347),				# 0S7?
	('KindleOasis2WiFi32GB', 0x34A),				# 0SA
	('KindleUnknown', 0x00)
]

# We need the ID of a few very specific cutoff models...
wario_cutoff_id = 0
for i, v in enumerate(model_tuples):
	if v[0] == 'KindleVoyageWiFi3GJapan':
		wario_cutoff_id = v[1]


print 'Kindle models sorted by device code\n'
for t in sorted(model_tuples, key=itemgetter(1)):
	# Handle the base32hex device IDs in a dedicated manner...
	if t[1] > 0xFF:
		print "{:<45} {:04X} (0{:<2}) {:4} {:<14}".format(t[0], t[1], baseN(t[1], 32), '', t[2] if len(t) == 3 else '')
	else:
		print "{:<45} {:02X} {:12} {:<14}".format(t[0], t[1], '', t[2] if len(t) == 3 else '')

print '\nKindle models >= KindleVoyageWiFi3GJapan (i.e., Platform >= Wario)\n'
for t in model_tuples:
	if t[1] >= wario_cutoff_id:
		if t[1] > 0xFF:
			print "{:<45} {:04X} (0{:<2})".format(t[0], t[1], baseN(t[1], 32))
		else:
			print "{:<45} {:02X}".format(t[0], t[1])
"""
	# That's to double-check that everything's sane for KindleTool's info command...
	else:
		print "!!{:<44}!!".format(t[0])
"""

print '\nKindle models with new device code decoding (i.e., >= PW3)\n'
for t in model_tuples:
	if t[1] >= wario_cutoff_id:
		if t[1] > 0xFF:
			print "{:<45} {:04X} (0{:<2} <-> {:04X})".format(t[0], t[1], baseN(t[1], 32), devCode(baseN(t[1], 32)))
