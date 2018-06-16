/*
**  KindleTool, convert.c
**
**  Copyright (C) 2011-2012  Yifan Lu
**  Copyright (C) 2012-2018  NiLuJe
**  Concept based on an original Python implementation by Igor Skochinsky & Jean-Yves Avenard,
**    cf., http://www.mobileread.com/forums/showthread.php?t=63225
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "convert.h"

static const char*
    convert_magic_number(char magic_number[MAGIC_NUMBER_LENGTH])
{
	if (!strncmp(magic_number, "FB02", MAGIC_NUMBER_LENGTH))
		return "(Fullbin [signed?])";    // /mnt/us/update-full.bin
	else if (!strncmp(magic_number, "FB03", MAGIC_NUMBER_LENGTH))
		return "(Fullbin [OTA?, fwo?])";    // /mnt/us/update-%lld-fwo.bin
	else if (!strncmp(magic_number, "FB", MAGIC_NUMBER_LENGTH / 2))
		return "(Fullbin)";
	else if (!strncmp(magic_number, "FC", MAGIC_NUMBER_LENGTH / 2))
		return "(OTA [ota])";    // /mnt/us/Update_%lld_%lld.bin
	else if (!strncmp(magic_number, "FD", MAGIC_NUMBER_LENGTH / 2))
		return "(Versionless [vls])";    // /mnt/us/Update_VLS_%lld.bin
	else if (!strncmp(magic_number, "FL", MAGIC_NUMBER_LENGTH / 2))
		return "(Language [lang])";    // /mnt/us/Update_LANG_%s.bin
	else if (!strncmp(magic_number, "SP", MAGIC_NUMBER_LENGTH / 2))
		return "(Signing Envelope)";
	else if (!memcmp(magic_number, "\x1F\x8B\x08\x00", MAGIC_NUMBER_LENGTH))
		return "(Userdata tarball)";
	else if (!memcmp(magic_number, "\x50\x4B\x03\x04", MAGIC_NUMBER_LENGTH))
		return "(Android update)";
	else
		return "Unknown";
}

// Pilfered from http://rosettacode.org/wiki/Non-decimal_radices/Convert#C
static char*
    to_base(int64_t num, unsigned int base)
{
	// FIXME: Crockford's Base32, but with the "L" & "U" re-added in?
	const char*  tbl     = "0123456789ABCDEFGHJKLMNPQRSTUVWX";
	char         buf[66] = { '\0' };
	char*        out;
	uint64_t     n;
	unsigned int i, len = 0, neg = 0;
	if (base > strlen(tbl)) {
		fprintf(stderr, "base %u is unsupported (too large).\n", base);
		return 0;
	}

	// safe against most negative integer
	n = ((neg = num < 0)) ? (uint64_t)(~num) + 1 : (uint64_t) num;

	do {
		buf[len++] = tbl[n % base];
	} while (n /= base);

	out = malloc(len + neg + 1);
	memset(out, 0, len + neg + 1);
	for (i = neg; len > 0; i++)
		out[i] = buf[--len];
	if (neg)
		out[0] = '-';

	return out;
}

// Pilfered and mangled from http://rosettacode.org/wiki/Non-decimal_radices/Convert#C++
// NOTE: Eh, turns out to be basically the same implemention I used for kindle_model_sort.py...
unsigned long int
    from_base(char* num, unsigned int base)
{
	// FIXME: Crockford's Base32, but with the "L" & "U" re-added in?
	const char*       tbl    = "0123456789ABCDEFGHJKLMNPQRSTUVWX";
	unsigned long int result = 0;

	if (base > strlen(tbl)) {
		fprintf(stderr, "base %u is unsupported (too large).\n", base);
		return 0;
	}

	// Hi, my name is Neo. I know pointers! (Or not.)
	char* p;
	for (p = num; *p != '\0'; p++) {
		size_t i = 0;
		for (i = 0; tbl[i] != '\0'; i++) {
			if (*p == tbl[i]) {
				result = result * base + i;
				break;
			}
		}
	}

	return result;
}

static int
    kindle_read_bundle_header(UpdateHeader* header, FILE* input)
{
	if (fread(header, sizeof(unsigned char), MAGIC_NUMBER_LENGTH, input) < 1 || ferror(input) != 0) {
		return -1;
	}
	return 0;
}

static int
    kindle_convert(FILE*      input,
		   FILE*      output,
		   FILE*      sig_output,
		   const bool fake_sign,
		   const bool unwrap_only,
		   FILE*      unwrap_output,
		   char*      header_md5)
{
	UpdateHeader  header;
	BundleVersion bundle_version;
	// Zero init to make Valgrind happy
	// (it considers a variable to be uninitialized if any variable or memory location used in its calculation were uninitialized,
	// and we effectiveley only initialize the first MAGIC_NUMBER_LENGTH bytes of header with kindle_read_bundle_header, so it shouts at us
	// later during the header.magic_number printf (asking for a MAGIC_NUMBER_LENGTH field width also helps) ;)).
	memset(&header, 0, sizeof(UpdateHeader));

	unsigned char buffer[BUFFER_SIZE];
	size_t        count;

	if (kindle_read_bundle_header(&header, input) < 0) {
		fprintf(stderr, "Cannot read input file: %s.\n", strerror(errno));
		return -1;
	}
	if (get_bundle_version(header.magic_number) == UnknownUpdate) {
		// Cf. http://stackoverflow.com/questions/3555791
		fprintf(stderr,
			"Bundle         Unknown (0x%02X%02X%02X%02X [%.*s])\n",
			(unsigned) (unsigned char) header.magic_number[0],
			(unsigned) (unsigned char) header.magic_number[1],
			(unsigned) (unsigned char) header.magic_number[2],
			(unsigned) (unsigned char) header.magic_number[3],
			MAGIC_NUMBER_LENGTH,
			header.magic_number);
	} else
		fprintf(stderr,
			"Bundle         %.*s %s\n",
			MAGIC_NUMBER_LENGTH,
			(get_bundle_version(header.magic_number) == UserDataPackage
			     ? "GZIP"
			     : get_bundle_version(header.magic_number) == AndroidUpdate ? "ZIP" : header.magic_number),
			convert_magic_number(header.magic_number));
	bundle_version = get_bundle_version(header.magic_number);
	switch (bundle_version) {
		case OTAUpdateV2:
			if (unwrap_only) {
				fprintf(stderr, "Nothing to unwrap!\n");
				return 0;
			} else {
				fprintf(stderr, "Bundle Type    %s\n", "OTA V2");
				// No absolute size, so no struct to pass
				return kindle_convert_ota_update_v2(input, output, fake_sign, header_md5);
			}
			break;
		case UpdateSignature:
			if (kindle_convert_signature(&header, input, sig_output) < 0) {
				fprintf(stderr, "Cannot extract signature file!\n");
				return -1;
			}
			// If we asked to simply unwrap the package, just write our unwrapped package ;).
			if (unwrap_only) {
				while ((count = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input)) > 0) {
					if (fwrite(buffer, sizeof(unsigned char), count, unwrap_output) < count) {
						fprintf(stderr,
							"Error writing unwrapped update to output: %s.\n",
							strerror(errno));
						return -1;
					}
				}
				// NOTE: We don't handle unwrapping nested UpdateSignature
				return 0;
			} else {
				return kindle_convert(input, output, sig_output, fake_sign, 0, NULL, header_md5);
			}
			break;
		case OTAUpdate:
			if (unwrap_only) {
				fprintf(stderr, "Nothing to unwrap!\n");
				return 0;
			} else {
				fprintf(stderr, "Bundle Type    %s\n", "OTA V1");
				return kindle_convert_ota_update(&header, input, output, fake_sign, header_md5);
			}
			break;
		case RecoveryUpdate:
			if (unwrap_only) {
				fprintf(stderr, "Nothing to unwrap!\n");
				return 0;
			} else {
				fprintf(stderr, "Bundle Type    %s\n", "Recovery");
				return kindle_convert_recovery(&header, input, output, fake_sign, header_md5);
			}
			break;
		case RecoveryUpdateV2:
			if (unwrap_only) {
				fprintf(stderr, "Nothing to unwrap!\n");
				return 0;
			} else {
				fprintf(stderr, "Bundle Type    %s\n", "Recovery V2");
				return kindle_convert_recovery_v2(input, output, fake_sign, header_md5);
			}
			break;
		case UserDataPackage:
			// It's a straight unmunged tarball, and we aren't only asking for info, just rip it out ;).
			if (output != NULL) {
				// We need the 4 bytes of 'bundle header' we consumed earlier back! (The GZIP magic number)
				fseek(input, -MAGIC_NUMBER_LENGTH, SEEK_CUR);
				while ((count = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input)) > 0) {
					if (fwrite(buffer, sizeof(unsigned char), count, output) < count) {
						fprintf(stderr,
							"Error writing userdata tarball to output: %s.\n",
							strerror(errno));
						return -1;
					}
				}
			}
			// Usually, nothing more to do...
			return 0;
			break;
		case AndroidUpdate:
			fprintf(stderr, "Nothing more to do!\n");
			// Usually, nothing more to do... On extract, archive_read_open_file will gracefully fail
			// with an unrecognized format error, which tracks, given that we only support tarball + gzip ;).
			return 0;
			break;
		case UnknownUpdate:
		default:
			fprintf(stderr, "Unknown update bundle version!\n");
			break;
	}
	return -1;    // If we get here, there has been an error
}

static int
    kindle_convert_ota_update_v2(FILE* input, FILE* output, const bool fake_sign, char* header_md5)
{
	unsigned char* data;
	size_t         hindex = 0;
	uint64_t       source_revision;
	uint64_t       target_revision;
	uint16_t       num_devices;
	uint16_t       device;
	//uint16_t *devices;
	uint8_t  critical;
	uint8_t  padding;
	char*    pkg_md5_sum;
	uint16_t num_metadata;
	size_t   meta_strlen;
	uint16_t metastring_length;
	char*    metastring;
	//unsigned char **metastrings;
	size_t read_size __attribute__((unused));

	// First read the set block size and determine how much to resize
	data      = malloc(OTA_UPDATE_V2_BLOCK_SIZE * sizeof(unsigned char));
	read_size = fread(data, sizeof(unsigned char), OTA_UPDATE_V2_BLOCK_SIZE, input);

	// NOTE: Use memcpy to avoid unaligned accesses on ARM...
	//       Because for some reason, even the A8 eats dirt (the alignment trap throws a SIGILL) on some vld1.64 :64
	//       instructions, and my non-existent understanding of ARM assembly & GCC innards is no help at all ;D.
	//source_revision = *(uint64_t *)&data[hindex];
	memcpy(&source_revision, &data[hindex], sizeof(uint64_t));
	hindex += sizeof(uint64_t);
	fprintf(stderr, "Minimum OTA    %llu\n", (long long unsigned int) source_revision);
	//target_revision = *(uint64_t *)&data[hindex];
	memcpy(&target_revision, &data[hindex], sizeof(uint64_t));
	hindex += sizeof(uint64_t);
	fprintf(stderr, "Target OTA     %llu\n", (long long unsigned int) target_revision);
	//num_devices = *(uint16_t *)&data[hindex];
	memcpy(&num_devices, &data[hindex], sizeof(uint16_t));
	//hindex += sizeof(uint16_t);       // Shut clang's sa up
	fprintf(stderr, "Devices        %hu\n", num_devices);
	free(data);

	// Now get the data
	// NOTE: This is stored in a temp var for the express purpose of shutting up clang's sa
	//       (uint16_t > uchar, which freaks clang. Would be dangerous if it were the other way around)...
	size_t devices_size = num_devices * sizeof(uint16_t);
	data                = malloc(devices_size);
	read_size           = fread(data, sizeof(uint16_t), num_devices, input);
	for (hindex = 0; hindex < num_devices * sizeof(uint16_t); hindex += sizeof(uint16_t)) {
		//device = *(uint16_t *)&data[hindex];
		memcpy(&device, &data[hindex], sizeof(uint16_t));
		fprintf(stderr, "Device         ");
		// Slightly hackish way to detect unknown devices...
		bool is_unknown = false;
		if (strcmp(convert_device_id(device), "Unknown") == 0) {
			is_unknown = true;
			fprintf(stderr, "Unknown (");
		} else {
			fprintf(stderr, "%s", convert_device_id(device));
		}
		if (kt_with_unknown_devcodes) {
			if (!is_unknown) {
				fprintf(stderr, " (");
			}
			// Handle the new device ID scheme...
			if (device > 0xFF) {
				char* dev_id;
				dev_id          = to_base(device, 32);
				const char* pad = "000";
				// NOTE: 0 padding a string with actual zeroes is fun....
				//       (cf. https://stackoverflow.com/questions/4133318)
				fprintf(stderr,
					"%.*s%s -> ",
					((int) strlen(pad) < (int) strlen(dev_id))
					    ? 0
					    : (int) strlen(pad) - (int) strlen(dev_id),
					pad,
					dev_id);
				// NOTE: Can't touch the formatting of this, MRPI relies on it...
				//       So relegate this to a debug only feature...
				/*
				// Check that our base conversions work both ways...
				unsigned long int dev_code = from_base(dev_id, 32);
				fprintf(stderr, "0x%03lX -> ", dev_code);
				*/
				free(dev_id);
			}
		}
		if (is_unknown || kt_with_unknown_devcodes) {
			fprintf(stderr, "0x%02X)", device);
		}
		fprintf(stderr, "\n");
	}
	free(data);

	// Now get second part of set sized data
	data      = malloc(OTA_UPDATE_V2_PART_2_BLOCK_SIZE * sizeof(unsigned char));
	read_size = fread(data, sizeof(unsigned char), OTA_UPDATE_V2_PART_2_BLOCK_SIZE, input);
	hindex    = 0;

	// NOTE: Here, the alignment is identical between critical & data, so we can get away with it safely.
	critical = *(uint8_t*) &data[hindex];
	// Apparently critical really is supposed to be 1 byte + 1 padding byte, so obey that...
	hindex += sizeof(uint8_t);
	fprintf(stderr, "Critical       %hhu\n", critical);
	padding = *(uint8_t*) &data[hindex];    // Print the (garbage?) padding byte found in official updates...
	hindex += sizeof(uint8_t);
	fprintf(stderr, "Padding Byte   %hhu (0x%02X)\n", padding, padding);
	pkg_md5_sum = (char*) &data[hindex];
	dm((unsigned char*) pkg_md5_sum, MD5_HASH_LENGTH);
	hindex += MD5_HASH_LENGTH;
	fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, pkg_md5_sum);
	strncpy(header_md5, pkg_md5_sum, MD5_HASH_LENGTH);
	//num_metadata = *(uint16_t *)&data[hindex];
	memcpy(&num_metadata, &data[hindex], sizeof(uint16_t));
	//hindex += sizeof(uint16_t);       // Shut clang's sa up
	fprintf(stderr, "Metadata       %hu\n", num_metadata);
	free(data);

	// Finally, get the metastrings
	for (hindex = 0; hindex < num_metadata; hindex++) {
		// Get correct meta string length because of the endianness swap...
		read_size         = fread(&((uint8_t*) &meta_strlen)[1], sizeof(uint8_t), 1, input);
		read_size         = fread(&((uint8_t*) &meta_strlen)[0], sizeof(uint8_t), 1, input);
		metastring_length = (uint16_t) meta_strlen;
		metastring        = malloc(metastring_length);
		read_size         = fread(metastring, sizeof(char), metastring_length, input);
		// Deobfuscate string (FIXME: Should meta strings really be obfuscated?)
		dm((unsigned char*) metastring, metastring_length);
		fprintf(stderr, "Metastring     %.*s\n", metastring_length, metastring);
		free(metastring);
	}

	if (ferror(input) != 0) {
		fprintf(stderr, "Cannot read update correctly: %s.\n", strerror(errno));
		return -1;
	}

	if (output == NULL) {
		return 0;
	}

	// Now we can decrypt the data
	return demunger(input, output, 0, fake_sign);
}

static int
    kindle_convert_signature(UpdateHeader* header, FILE* input, FILE* output)
{
	CertificateNumber cert_num;
	const char*       cert_name;
	size_t            seek;
	unsigned char*    signature;

	if (fread(header->data.signature_header_data, sizeof(unsigned char), UPDATE_SIGNATURE_BLOCK_SIZE, input) <
	    UPDATE_SIGNATURE_BLOCK_SIZE) {
		fprintf(stderr, "Cannot read signature header: %s.\n", strerror(errno));
		return -1;
	}
	cert_num = (CertificateNumber)(header->data.signature.certificate_number);
	fprintf(stderr, "Cert number    %u\n", cert_num);
	switch (cert_num) {
		case CertificateDeveloper:
			cert_name = "pubdevkey01.pem (Developer)";
			seek      = CERTIFICATE_DEV_SIZE;
			break;
		case Certificate1K:
			cert_name = "pubprodkey01.pem (Official 1K)";
			seek      = CERTIFICATE_1K_SIZE;
			break;
		case Certificate2K:
			cert_name = "pubprodkey02.pem (Official 2K)";
			seek      = CERTIFICATE_2K_SIZE;
			break;
		case CertificateUnknown:
		default:
			fprintf(stderr, "Unknown signature size, cannot continue.\n");
			return -1;
			break;
	}
	fprintf(stderr, "Cert file      %s\n", cert_name);
	if (output == NULL) {
		return fseeko(input, (off_t) seek, SEEK_CUR);
	} else {
		signature = malloc(seek);
		if (fread(signature, sizeof(unsigned char), seek, input) < seek) {
			fprintf(stderr, "Cannot read signature! %s.\n", strerror(errno));
			free(signature);
			return -1;
		}
		if (fwrite(signature, sizeof(unsigned char), seek, output) < seek) {
			fprintf(stderr, "Cannot write signature file! %s.\n", strerror(errno));
			free(signature);
			return -1;
		}
		free(signature);
	}
	return 0;
}

static int
    kindle_convert_ota_update(UpdateHeader* header, FILE* input, FILE* output, const bool fake_sign, char* header_md5)
{
	if (fread(header->data.ota_header_data, sizeof(unsigned char), OTA_UPDATE_BLOCK_SIZE, input) <
	    OTA_UPDATE_BLOCK_SIZE) {
		fprintf(stderr, "Cannot read OTA header: %s.\n", strerror(errno));
		return -1;
	}
	dm((unsigned char*) header->data.ota_update.md5_sum, MD5_HASH_LENGTH);
	fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->data.ota_update.md5_sum);
	strncpy(header_md5, header->data.ota_update.md5_sum, MD5_HASH_LENGTH);
	fprintf(stderr, "Minimum OTA    %u\n", header->data.ota_update.source_revision);
	fprintf(stderr, "Target OTA     %u\n", header->data.ota_update.target_revision);
	fprintf(stderr, "Device         ");
	// Slightly hackish way to detect unknown devices...
	bool is_unknown = false;
	if (strcmp(convert_device_id(header->data.ota_update.device), "Unknown") == 0) {
		is_unknown = true;
		fprintf(stderr, "Unknown (");
	} else {
		fprintf(stderr, "%s", convert_device_id(header->data.ota_update.device));
	}
	if (kt_with_unknown_devcodes) {
		if (!is_unknown) {
			fprintf(stderr, " (");
		}
		// Handle the new device ID scheme...
		if (header->data.ota_update.device > 0xFF) {
			char* dev_id;
			dev_id          = to_base(header->data.ota_update.device, 32);
			const char* pad = "000";
			fprintf(stderr,
				"%.*s%s -> ",
				((int) strlen(pad) < (int) strlen(dev_id)) ? 0
									   : (int) strlen(pad) - (int) strlen(dev_id),
				pad,
				dev_id);
			free(dev_id);
		}
	}
	if (is_unknown || kt_with_unknown_devcodes) {
		fprintf(stderr, "0x%02X)", header->data.ota_update.device);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "Optional       %hhu\n", header->data.ota_update.optional);
	// Print the (garbage?) padding byte... (The python tool puts 0x13 in there)
	fprintf(
	    stderr, "Padding Byte   %hhu (0x%02X)\n", header->data.ota_update.unused, header->data.ota_update.unused);

	if (output == NULL) {
		return 0;
	}

	return demunger(input, output, 0, fake_sign);
}

static int
    kindle_convert_recovery(UpdateHeader* header, FILE* input, FILE* output, const bool fake_sign, char* header_md5)
{
	if (fread(header->data.recovery_header_data, sizeof(unsigned char), RECOVERY_UPDATE_BLOCK_SIZE, input) <
	    RECOVERY_UPDATE_BLOCK_SIZE) {
		fprintf(stderr, "Cannot read recovery update header: %s.\n", strerror(errno));
		return -1;
	}
	dm((unsigned char*) header->data.recovery_update.md5_sum, MD5_HASH_LENGTH);
	fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->data.recovery_update.md5_sum);
	strncpy(header_md5, header->data.recovery_update.md5_sum, MD5_HASH_LENGTH);
	fprintf(stderr, "Magic 1        %u\n", header->data.recovery_update.magic_1);
	fprintf(stderr, "Magic 2        %u\n", header->data.recovery_update.magic_2);
	fprintf(stderr, "Minor          %u\n", header->data.recovery_update.minor);

	// Handle V2 header rev...
	if (header->data.recovery_h2_update.header_rev == 2) {
		fprintf(stderr, "Header Rev     %u\n", header->data.recovery_h2_update.header_rev);
		// Slightly ugly way to detect unknown platforms...
		if (strcmp(convert_platform_id(header->data.recovery_h2_update.platform), "Unknown") == 0) {
			fprintf(stderr, "Platform       Unknown (0x%02X)\n", header->data.recovery_h2_update.platform);
		} else {
			fprintf(stderr,
				"Platform       %s\n",
				convert_platform_id(header->data.recovery_h2_update.platform));
		}
		// Same shtick for unknown boards...
		if (strcmp(convert_board_id(header->data.recovery_h2_update.board), "Unknown") == 0) {
			fprintf(stderr, "Board          Unknown (0x%02X)\n", header->data.recovery_h2_update.board);
		} else {
			fprintf(stderr, "Board          %s\n", convert_board_id(header->data.recovery_h2_update.board));
		}
	} else {
		fprintf(stderr, "Device         ");
		// Slightly hackish way to detect unknown devices...
		bool is_unknown = false;
		if (strcmp(convert_device_id(header->data.recovery_update.device), "Unknown") == 0) {
			is_unknown = true;
			fprintf(stderr, "Unknown (");
		} else {
			fprintf(stderr, "%s", convert_device_id(header->data.recovery_update.device));
		}
		if (kt_with_unknown_devcodes) {
			if (!is_unknown) {
				fprintf(stderr, " (");
			}
			// Handle the new device ID scheme...
			if (header->data.recovery_update.device > 0xFF) {
				char* dev_id;
				dev_id          = to_base(header->data.recovery_update.device, 32);
				const char* pad = "000";
				fprintf(stderr,
					"%.*s%s -> ",
					((int) strlen(pad) < (int) strlen(dev_id))
					    ? 0
					    : (int) strlen(pad) - (int) strlen(dev_id),
					pad,
					dev_id);
				free(dev_id);
			}
		}
		if (is_unknown || kt_with_unknown_devcodes) {
			fprintf(stderr, "0x%02X)", header->data.recovery_update.device);
		}
		fprintf(stderr, "\n");
	}

	if (output == NULL) {
		return 0;
	}

	return demunger(input, output, 0, fake_sign);
}

static int
    kindle_convert_recovery_v2(FILE* input, FILE* output, const bool fake_sign, char* header_md5)
{
	unsigned char* data;
	size_t         hindex = 0;
	uint64_t       target_revision;
	char*          pkg_md5_sum;
	uint32_t       magic_1;
	uint32_t       magic_2;
	uint32_t       minor;
	uint32_t       platform;
	uint32_t       header_rev;
	uint32_t       board;
	uint16_t       device;
	uint8_t        num_devices;
	unsigned int   i;
	//uint16_t *devices;
	size_t read_size __attribute__((unused));

	// Its size is set, there's just some wonky padding involved. Read it all!
	data      = malloc(RECOVERY_UPDATE_BLOCK_SIZE * sizeof(unsigned char));
	read_size = fread(data, sizeof(unsigned char), RECOVERY_UPDATE_BLOCK_SIZE, input);

	hindex += sizeof(uint32_t);    // Padding
	//target_revision = *(uint64_t *)&data[hindex];
	memcpy(&target_revision, &data[hindex], sizeof(uint64_t));
	hindex += sizeof(uint64_t);
	fprintf(stderr, "Target OTA     %llu\n", (long long unsigned int) target_revision);
	pkg_md5_sum = (char*) &data[hindex];
	dm((unsigned char*) pkg_md5_sum, MD5_HASH_LENGTH);
	hindex += MD5_HASH_LENGTH;
	fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, pkg_md5_sum);
	strncpy(header_md5, pkg_md5_sum, MD5_HASH_LENGTH);
	//magic_1 = *(uint32_t *)&data[hindex];
	memcpy(&magic_1, &data[hindex], sizeof(uint32_t));
	hindex += sizeof(uint32_t);
	fprintf(stderr, "Magic 1        %u\n", magic_1);
	//magic_2 = *(uint32_t *)&data[hindex];
	memcpy(&magic_2, &data[hindex], sizeof(uint32_t));
	hindex += sizeof(uint32_t);
	fprintf(stderr, "Magic 2        %u\n", magic_2);
	//minor = *(uint32_t *)&data[hindex];
	memcpy(&minor, &data[hindex], sizeof(uint32_t));
	hindex += sizeof(uint32_t);
	fprintf(stderr, "Minor          %u\n", minor);
	//platform = *(uint32_t *)&data[hindex];
	memcpy(&platform, &data[hindex], sizeof(uint32_t));
	hindex += sizeof(uint32_t);
	// Slightly hackish way to detect unknown platforms...
	if (strcmp(convert_platform_id(platform), "Unknown") == 0)
		fprintf(stderr, "Platform       Unknown (0x%02X)\n", platform);
	else
		fprintf(stderr, "Platform       %s\n", convert_platform_id(platform));
	//header_rev = *(uint32_t *)&data[hindex];
	memcpy(&header_rev, &data[hindex], sizeof(uint32_t));
	hindex += sizeof(uint32_t);
	fprintf(stderr, "Header Rev     %u\n", header_rev);
	//board = *(uint32_t *)&data[hindex];
	memcpy(&board, &data[hindex], sizeof(uint32_t));
	hindex += sizeof(uint32_t);
	// Slightly hackish way to detect unknown boards
	// (Not to be confused with the 'Unspecified' board, which permits skipping the device/board check)...
	if (strcmp(convert_board_id(board), "Unknown") == 0)
		fprintf(stderr, "Board          %s (0x%02X)\n", convert_board_id(board), board);
	else
		fprintf(stderr, "Board          %s\n", convert_board_id(board));
	hindex += sizeof(uint32_t);    // Padding
	hindex += sizeof(uint16_t);    // ... Padding
	hindex += sizeof(uint8_t);     // And more weird padding
	num_devices = *(uint8_t*) &data[hindex];
	hindex += sizeof(uint8_t);
	fprintf(stderr, "Devices        %hhu\n", num_devices);
	for (i = 0; i < num_devices; i++) {
		//device = *(uint16_t *)&data[hindex];
		memcpy(&device, &data[hindex], sizeof(uint16_t));
		fprintf(stderr, "Device         ");
		// Slightly hackish way to detect unknown devices...
		bool is_unknown = false;
		if (strcmp(convert_device_id(device), "Unknown") == 0) {
			is_unknown = true;
			fprintf(stderr, "Unknown (");
		} else {
			fprintf(stderr, "%s", convert_device_id(device));
		}
		if (kt_with_unknown_devcodes) {
			if (!is_unknown) {
				fprintf(stderr, " (");
			}
			// Handle the new device ID scheme...
			if (device > 0xFF) {
				char* dev_id;
				dev_id          = to_base(device, 32);
				const char* pad = "000";
				fprintf(stderr,
					"%.*s%s -> ",
					((int) strlen(pad) < (int) strlen(dev_id))
					    ? 0
					    : (int) strlen(pad) - (int) strlen(dev_id),
					pad,
					dev_id);
				free(dev_id);
			}
		}
		if (is_unknown || kt_with_unknown_devcodes) {
			fprintf(stderr, "0x%02X)", device);
		}
		fprintf(stderr, "\n");
		hindex += sizeof(uint16_t);
	}
	free(data);

	if (ferror(input) != 0) {
		fprintf(stderr, "Cannot read update correctly: %s.\n", strerror(errno));
		return -1;
	}

	if (output == NULL) {
		return 0;
	}

	// Now we can decrypt the data
	return demunger(input, output, 0, fake_sign);
}

int
    kindle_convert_main(int argc, char* argv[])
{
	int                        opt;
	int                        opt_index;
	static const struct option opts[] = { { "stdout", no_argument, NULL, 'c' },
					      { "info", no_argument, NULL, 'i' },
					      { "keep", no_argument, NULL, 'k' },
					      { "sig", no_argument, NULL, 's' },
					      { "unsigned", no_argument, NULL, 'u' },
					      { "unwrap", no_argument, NULL, 'w' },
					      { NULL, 0, NULL, 0 } };
	FILE*                      input;
	FILE*                      output        = NULL;
	FILE*                      sig_output    = NULL;
	FILE*                      unwrap_output = NULL;
	const char*                in_name;
	char*                      out_name       = NULL;
	char*                      sig_name       = NULL;
	char*                      unwrapped_name = NULL;
	size_t                     len;
	struct stat                st;
	bool                       info_only   = false;
	bool                       keep_ori    = false;
	bool                       extract_sig = false;
	bool                       fake_sign   = false;
	bool                       unwrap_only = false;
	unsigned int               ext_offset  = 0;
	bool                       fail        = true;
	char                       header_md5[MD5_HASH_LENGTH + 1];

	while ((opt = getopt_long(argc, argv, "icksuw", opts, &opt_index)) != -1) {
		switch (opt) {
			case 'i':
				info_only = true;
				break;
			case 'k':
				keep_ori = true;
				break;
			case 'c':
				output = stdout;
				break;
			case 's':
				extract_sig = true;
				break;
			case 'u':
				fake_sign = true;
				break;
			case 'w':
				unwrap_only = true;
				break;
			case ':':
				fprintf(stderr, "Missing argument for switch '%c'.\n", optopt);
				return -1;
				break;
			case '?':
				fprintf(stderr, "Unknown switch '%c'.\n", optopt);
				return -1;
				break;
			default:
				fprintf(stderr, "?? Unknown option code 0%o ??\n", (unsigned int) opt);
				return -1;
				break;
		}
	}
	// Don't try to output to stdout or extract/unwrap the package sig if we asked for info only
	if (info_only) {
		output      = NULL;
		extract_sig = false;
		unwrap_only = false;
	}
	// Don't try to extract or unwrap the signature of an unsiged package
	if (fake_sign) {
		extract_sig = false;
		unwrap_only = false;
	}
	// Don't try to output anywhere if we only want to unwrap the package
	if (unwrap_only) {
		output = NULL;
	}

	if (optind < argc) {
		// Iterate over non-options (the file(s) we passed)
		// (stdout output is probably pretty dumb when passing multiple files...)
		while (optind < argc) {
			fail    = false;
			in_name = argv[optind++];
			// Check that a valid package input properly ends in .bin or .stgz,
			// unless we just want to parse the header
			if (!info_only && (!IS_BIN(in_name) && !IS_STGZ(in_name))) {
				fprintf(
				    stderr,
				    "Input file '%s' is neither a '.bin' update package nor a '.stgz' userdata package.\n",
				    in_name);
				fail = true;
				continue;    // It's fatal, go away
			}
			// Set the appropriate file extension offset...
			if (IS_STGZ(in_name))
				ext_offset = 1;
			else
				ext_offset = 0;
			// Not info only, not unwrap only AND not stdout
			if (!info_only && !unwrap_only && output != stdout) {
				len      = strlen(in_name);
				out_name = malloc(len + 1 + (13 - ext_offset));
				memcpy(out_name, in_name, len - (4 + ext_offset));
				out_name[len - (4 + ext_offset)] = 0;    // . => \0
				strncat(out_name, "_converted.tar.gz", 17);
				if ((output = fopen(out_name, "wb")) == NULL) {
					fprintf(stderr, "Cannot open output '%s' for writing.\n", out_name);
					fail = true;
					free(out_name);
					continue;    // It's fatal, go away
				}
			}
			// We want the payload sig (implies not info only)
			if (extract_sig) {
				len      = strlen(in_name);
				sig_name = malloc(len + 1 + (1 - ext_offset));
				memcpy(sig_name, in_name, len - (4 + ext_offset));
				sig_name[len - (4 + ext_offset)] = 0;    // . => \0
				strncat(sig_name, ".psig", 5);
				if ((sig_output = fopen(sig_name, "wb")) == NULL) {
					fprintf(stderr, "Cannot open signature output '%s' for writing.\n", sig_name);
					fail = true;
					if (!info_only && !unwrap_only && output != stdout) {
						if (output != NULL) {
							fclose(output);
							unlink(out_name);
						}
						free(out_name);
					}
					free(sig_name);
					continue;    // It's fatal, go away
				}
			}
			// We want an unwrapped package (implies not info only)
			if (unwrap_only) {
				len            = strlen(in_name);
				unwrapped_name = malloc(len + 1 + (10 - ext_offset));
				memcpy(unwrapped_name, in_name, len - (4 + ext_offset));
				unwrapped_name[len - (4 + ext_offset)] = 0;    // . => \0
				// If input is an userdata package, we can safely assume we'll end up with a tarballl
				if (ext_offset)
					strncat(unwrapped_name, "_unwrapped.tgz", 14);
				else
					strncat(unwrapped_name, "_unwrapped.bin", 14);
				if ((unwrap_output = fopen(unwrapped_name, "wb")) == NULL) {
					fprintf(stderr,
						"Cannot open unwrapped package output '%s' for writing.\n",
						unwrapped_name);
					fail = true;
					free(unwrapped_name);
					if (extract_sig) {
						if (sig_output != NULL) {
							fclose(sig_output);
							unlink(sig_name);
						}
						free(sig_name);
					}
					continue;    // It's fatal, go away
				}
			}
			if ((input = fopen(in_name, "rb")) == NULL) {
				fprintf(stderr, "Cannot open input '%s' for reading.\n", in_name);
				fail = true;
				if (!info_only && !unwrap_only && output != stdout) {
					// Don't leave 0-byte files behind...
					if (output != NULL) {
						fclose(output);
						unlink(out_name);
					}
					free(out_name);
				}
				if (extract_sig) {
					if (sig_output != NULL) {
						fclose(sig_output);
						unlink(sig_name);
					}
					free(sig_name);
				}
				if (unwrap_only) {
					if (unwrap_output != NULL) {
						fclose(unwrap_output);
						unlink(unwrapped_name);
					}
					free(unwrapped_name);
				}
				continue;    // It's fatal, go away
			}
			// If we're outputting to stdout, set a dummy human readable output name
			if (!info_only && output == stdout) {
				out_name = strdup("standard output");
			}
			// Print a recap of what we're doing
			if (info_only) {
				fprintf(stderr,
					"Checking %s%s package '%s'.\n",
					(fake_sign ? "fake " : ""),
					(IS_STGZ(in_name) ? "userdata" : "update"),
					in_name);
			} else if (unwrap_only) {
				fprintf(stderr,
					"Unwrapping %s package '%s' to '%s'.\n",
					(IS_STGZ(in_name) ? "userdata" : "update"),
					in_name,
					unwrapped_name);
			} else {
				fprintf(stderr,
					"Converting %s%s package '%s' to '%s' (%s, %s).\n",
					(fake_sign ? "fake " : ""),
					(IS_STGZ(in_name) ? "userdata" : "update"),
					in_name,
					out_name,
					(extract_sig ? "with sig" : "without sig"),
					(keep_ori ? "keep input" : "delete input"));
			}
			if (kindle_convert(
				input, output, sig_output, fake_sign, unwrap_only, unwrap_output, header_md5) < 0) {
				fprintf(stderr,
					"Error converting %s package '%s'.\n",
					(IS_STGZ(in_name) ? "userdata" : "update"),
					in_name);
				if (output != NULL && output != stdout)
					unlink(out_name);    // Clean up our mess, if we made one
				fail = true;
			}
			// If output was some file, and we didn't ask to keep it, and we didn't fail to convert it,
			// delete the original
			if (output != stdout && !info_only && !keep_ori && !fail) {
				unlink(in_name);
			}

			// Clean up behind us
			if (!info_only && !unwrap_only)
				free(out_name);
			if (output != NULL && output != stdout)
				fclose(output);
			if (input != NULL)
				fclose(input);
			if (sig_output != NULL)
				fclose(sig_output);
			if (unwrap_output != NULL)
				fclose(unwrap_output);
			// Remove empty sigs (since we have to open the fd before calling kindle_convert,
			// we end up with an empty file for packages that aren't wrapped in an UpdateSignature)
			if (extract_sig) {
				stat(sig_name, &st);
				if (st.st_size == 0)
					unlink(sig_name);
				free(sig_name);
			}
			// Same thing for unwrapped packages...
			if (unwrap_only) {
				stat(unwrapped_name, &st);
				if (st.st_size == 0)
					unlink(unwrapped_name);
				free(unwrapped_name);
			}

			// If we're not the last file, throw an LF to untangle the output
			if (optind < argc)
				fprintf(stderr, "\n");
		}
	} else {
		fprintf(stderr, "No input specified.\n");
		return -1;
	}

	// Return
	if (fail)
		return -1;
	else
		return 0;
}

// Heavily inspired from libarchive's tar/read.c ;)
static int
    libarchive_extract(const char* filename, const char* prefix)
{
	struct archive*       a;
	struct archive_entry* entry;
	int                   flags;
	int                   r;
	const char*           path       = NULL;
	char*                 fixed_path = NULL;
	size_t                len;

	// Select which attributes we want to restore.
	flags = ARCHIVE_EXTRACT_TIME;
	// Don't preserve permissions, as most files in kindle packages will be owned by root,
	// and if the perms are effed up, it gets annoying.
	// We could also just rewrite every entry in the archive with sane permissions, but that seems a bit overkill.
	//flags |= ARCHIVE_EXTRACT_PERM;
	//flags |= ARCHIVE_EXTRACT_ACL;
	flags |= ARCHIVE_EXTRACT_FFLAGS;

	a = archive_read_new();
	// Let's handle a wide range or tar formats, just to be on the safe side
	archive_read_support_format_tar(a);
	archive_read_support_format_gnutar(a);
	archive_read_support_filter_gzip(a);

	if (filename != NULL && strcmp(filename, "-") == 0) {
		filename = NULL;
	}
	if ((r = archive_read_open_filename(a, filename, 10240))) {
		fprintf(stderr, "archive_read_open_file() failure: %s.\n", archive_error_string(a));
		archive_read_free(a);
		return 1;
	}

	for (;;) {
		r = archive_read_next_header(a, &entry);
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK)
			fprintf(stderr, "archive_read_next_header() failed: %s.\n", archive_error_string(a));
		if (r < ARCHIVE_WARN)
			goto cleanup;

		// Print what we're extracting, like bsdtar
		path = archive_entry_pathname(entry);
		fprintf(stderr, "x %s\n", path);
		// Rewrite the entry's pathname to extract in the right output directory
		len        = strlen(prefix) + 1 + strlen(path) + 1;
		fixed_path = malloc(len);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
		snprintf(fixed_path, len, "%s/%s", prefix, path);
#pragma GCC diagnostic pop
		archive_entry_copy_pathname(entry, fixed_path);

		// archive_read_extract should take care of everything for us...
		// (creating a write_disk archive, setting a standard lookup, the flags we asked for,
		// writing our entry header & content, and destroying the write_disk archive ;))
		r = archive_read_extract(a, entry, flags);
		if (r != ARCHIVE_OK) {
			fprintf(stderr, "archive_read_extract() failed: %s.\n", archive_error_string(a));
			free(fixed_path);
			goto cleanup;
		}

		// Cleanup
		free(fixed_path);
	}
	archive_read_close(a);
	archive_read_free(a);

	return 0;

cleanup:
	archive_read_close(a);
	archive_read_free(a);

	return 1;
}

int
    kindle_extract_main(int argc, char* argv[])
{
	int                        opt;
	int                        opt_index;
	static const struct option opts[]    = { { "unsigned", no_argument, NULL, 'u' }, { NULL, 0, NULL, 0 } };
	bool                       fake_sign = false;

	char* bin_filename = NULL;
	char  tgz_filename[PATH_MAX];
	snprintf(tgz_filename, PATH_MAX, "%s/%s", kt_tempdir, "/kindletool_extract_tgz_XXXXXX");
	char* output_dir = NULL;
	FILE* bin_input;
	int   tgz_fd;
	FILE* tgz_output;
	char  header_md5[MD5_HASH_LENGTH + 1] = { '\0' };
	char  actual_md5[MD5_HASH_LENGTH + 1] = { '\0' };

	while ((opt = getopt_long(argc, argv, "u", opts, &opt_index)) != -1) {
		switch (opt) {
			case 'u':
				fake_sign = true;
				break;
			case ':':
				fprintf(stderr, "Missing argument for switch '%c'.\n", optopt);
				return -1;
				break;
			case '?':
				fprintf(stderr, "Unknown switch '%c'.\n", optopt);
				return -1;
				break;
			default:
				fprintf(stderr, "?? Unknown option code 0%o ??\n", (unsigned int) opt);
				return -1;
				break;
		}
	}

	// We need exactly 2 non-switch options (I/O)!
	if (optind < argc && (optind + 2) == argc) {
		// We know exactly what we need, and in what order
		bin_filename = argv[optind];
		output_dir   = argv[optind + 1];
	} else {
		fprintf(stderr, "Invalid number of arguments (need input & output).\n");
		return -1;
	}
	// Double validation, and make GCC happy
	if (bin_filename == NULL) {
		fprintf(stderr, "Input filename isn't set!\n");
		return -1;
	}
	if (output_dir == NULL) {
		fprintf(stderr, "Output directory isn't set!\n");
		return -1;
	}

	// Check that input properly ends in .bin or .stgz
	if (!IS_BIN(bin_filename) && !IS_STGZ(bin_filename) && !IS_TARBALL(bin_filename) && !IS_TGZ(bin_filename)) {
		fprintf(
		    stderr,
		    "Input file '%s' is neither a '.bin' update package nor a '.stgz' or '.tar.gz'/'.tgz' userdata package.\n",
		    bin_filename);
		return -1;
	}
	// NOTE: Do some sanity checks for output directory handling?
	// The 'rewrite pathname entry' cheap method we currently use is pretty 'dumb'
	// (it assumes the path is correct, creating it if need be),
	// but the other (more correct?) way to handle this (chdir) would need some babysitting
	// (cf. bsdtar's *_chdir() in tar/util.c)...
	if ((bin_input = fopen(bin_filename, "rb")) == NULL) {
		fprintf(stderr,
			"Cannot open input %s package '%s': %s.\n",
			((IS_STGZ(bin_filename) || IS_TARBALL(bin_filename) || IS_TGZ(bin_filename)) ? "userdata"
												     : "update"),
			bin_filename,
			strerror(errno));
		return -1;
	}
	// Use a non-racey tempfile, hopefully... (Heavily inspired from http://www.tldp.org/HOWTO/Secure-Programs-HOWTO/avoid-race.html)
	// We always create them in P_tmpdir (usually /tmp or /var/tmp), and rely on the OS implementation to handle the umask,
	// it'll cost us less LOC that way since I don't really want to introduce a dedicated utility function for tempfile handling...
	// NOTE: Probably still racey on MinGW, according to libarchive, but, meh, and we're not multithreaded...
	//       See the ifdef in kindle_tool.h for more details.
	tgz_fd = mkstemp(tgz_filename);
	if (tgz_fd == -1) {
		fprintf(stderr, "Couldn't open temporary file: %s.\n", strerror(errno));
		fclose(bin_input);
		return -1;
	}
	if ((tgz_output = fdopen(tgz_fd, "w+b")) == NULL) {
		fprintf(stderr, "Cannot open temp output '%s' for writing: %s.\n", tgz_filename, strerror(errno));
		fclose(bin_input);
		close(tgz_fd);
		unlink(tgz_filename);
		return -1;
	}
	// Print a recap of what we're about to do
	fprintf(stderr,
		"Extracting %s package '%s' to '%s'.\n",
		((IS_STGZ(bin_filename) || IS_TARBALL(bin_filename) || IS_TGZ(bin_filename)) ? "userdata" : "update"),
		bin_filename,
		output_dir);
	if (kindle_convert(bin_input, tgz_output, NULL, fake_sign, 0, NULL, header_md5) < 0) {
		fprintf(stderr,
			"Error converting %s package '%s'.\n",
			((IS_STGZ(bin_filename) || IS_TARBALL(bin_filename) || IS_TGZ(bin_filename)) ? "userdata"
												     : "update"),
			bin_filename);
		fclose(bin_input);
		fclose(tgz_output);
		return -1;
	}
	fclose(bin_input);
	// When appropriate, check the integrity of the tarball, thanks to the md5 hash stored in the package's header...
	if (!fake_sign && strlen(header_md5) != 0) {
		// First, calculate the hash of what we've just extracted...
		rewind(tgz_output);
		if (md5_sum(tgz_output, actual_md5) < 0) {
			fprintf(stderr, "Error calculating MD5 of package.\n");
			fclose(tgz_output);
			unlink(tgz_filename);
			return -1;
		}
		// ...And compare it against the one stored in the package's header.
		if (strcmp(header_md5, actual_md5) != 0) {
			fprintf(
			    stderr, "Integrity check failed! Header: '%s' vs Package: '%s'.\n", header_md5, actual_md5);
			fclose(tgz_output);
			unlink(tgz_filename);
			return -1;
		}
	}
	fclose(tgz_output);
	if (libarchive_extract(tgz_filename, output_dir) < 0) {
		fprintf(stderr, "Error extracting temp tarball '%s' to '%s'.\n", tgz_filename, output_dir);
		unlink(tgz_filename);
		return -1;
	}
	unlink(tgz_filename);
	return 0;
}
