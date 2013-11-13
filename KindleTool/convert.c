//
//  extract.c
//  KindleTool
//
//  Copyright (C) 2011-2013  Yifan Lu
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#include "kindle_tool.h"

int kindle_read_bundle_header(UpdateHeader *header, FILE *input)
{
    if(fread(header, sizeof(unsigned char), MAGIC_NUMBER_LENGTH, input) < 1 || ferror(input) != 0)
    {
        return -1;
    }
    return 0;
}

int kindle_convert(FILE *input, FILE *output, FILE *sig_output, const unsigned int fake_sign, const unsigned int unwrap_only, FILE *unwrap_output)
{
    UpdateHeader header;
    BundleVersion bundle_version;
    // Zero init to make Valgrind happy
    // (it considers a variable to be uninitialized if any variable or memory location used in its calculation were uninitialized,
    // and we effectiveley only initialize the first MAGIC_NUMBER_LENGTH bytes of header with kindle_read_bundle_header, so it shouts at us
    // later during the header.magic_number printf (asking for a MAGIC_NUMBER_LENGTH field width also helps) ;)).
    memset(&header, 0, sizeof(UpdateHeader));

    unsigned char buffer[BUFFER_SIZE];
    size_t count;

    if(kindle_read_bundle_header(&header, input) < 0)
    {
        fprintf(stderr, "Cannot read input file: %s.\n", strerror(errno));
        return -1;
    }
    // Slightly hackish way to detect unknown bundle types...
    if(strcmp(convert_magic_number(header.magic_number), "Unknown") == 0)
    {
        // Cf. http://stackoverflow.com/questions/3555791
        fprintf(stderr, "Bundle         Unknown (0x%02X%02X%02X%02X [%.*s])\n", (unsigned)(unsigned char)header.magic_number[0], (unsigned)(unsigned char)header.magic_number[1], (unsigned)(unsigned char)header.magic_number[2], (unsigned)(unsigned char)header.magic_number[3], MAGIC_NUMBER_LENGTH, header.magic_number);
    }
    else
        fprintf(stderr, "Bundle         %.*s%s%s\n", MAGIC_NUMBER_LENGTH, header.magic_number, (strlen(header.magic_number) < 4 ? "" : " "), convert_magic_number(header.magic_number));
                                                                                                // ^ cheap trick to avoid an extra space due to the unprintable GZIP magic number
    bundle_version = get_bundle_version(header.magic_number);
    switch(bundle_version)
    {
        case OTAUpdateV2:
            if(unwrap_only)
            {
                fprintf(stderr, "Nothing to unwrap!\n");
                return 0;
            }
            else
            {
                fprintf(stderr, "Bundle Type    %s\n", "OTA V2");
                return kindle_convert_ota_update_v2(input, output, fake_sign); // No absolute size, so no struct to pass
            }
            break;
        case UpdateSignature:
            if(kindle_convert_signature(&header, input, sig_output) < 0)
            {
                fprintf(stderr, "Cannot extract signature file!\n");
                return -1;
            }
            // If we asked to simply unwrap the package, just write our unwrapped package ;).
            if(unwrap_only)
            {
                while((count = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input)) > 0)
                {
                    if(fwrite(buffer, sizeof(unsigned char), count, unwrap_output) < count)
                    {
                        fprintf(stderr, "Error writing unwrapped update to output: %s.\n", strerror(errno));
                        return -1;
                    }
                }
                // NOTE: We don't handle unwrapping nested UpdateSignature
                return 0;
            }
            else
            {
                return kindle_convert(input, output, sig_output, fake_sign, 0, NULL);
            }
            break;
        case OTAUpdate:
            if(unwrap_only)
            {
                fprintf(stderr, "Nothing to unwrap!\n");
                return 0;
            }
            else
            {
                fprintf(stderr, "Bundle Type    %s\n", "OTA V1");
                return kindle_convert_ota_update(&header, input, output, fake_sign);
            }
            break;
        case RecoveryUpdate:
            if(unwrap_only)
            {
                fprintf(stderr, "Nothing to unwrap!\n");
                return 0;
            }
            else
            {
                fprintf(stderr, "Bundle Type    %s\n", "Recovery");
                return kindle_convert_recovery(&header, input, output, fake_sign);
            }
            break;
        case RecoveryUpdateV2:
            if(unwrap_only)
            {
                fprintf(stderr, "Nothing to unwrap!\n");
                return 0;
            }
            else
            {
                fprintf(stderr, "Bundle Type    %s\n", "Recovery V2");
                return kindle_convert_recovery_v2(input, output, fake_sign);
            }
            break;
        case UserDataPackage:
            // It's a straight unmunged tarball, and we aren't only asking for info, just rip it out ;).
            if(output != NULL)
            {
                // We need the 4 bytes of 'bundle header' we consumed earlier back! (The GZIP magic number)
                fseek(input, - MAGIC_NUMBER_LENGTH, SEEK_CUR);
                while((count = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input)) > 0)
                {
                    if(fwrite(buffer, sizeof(unsigned char), count, output) < count)
                    {
                        fprintf(stderr, "Error writing userdata tarball to output: %s.\n", strerror(errno));
                        return -1;
                    }
                }
            }
            // Usually, nothing more to do...
            return 0;
            break;
        case UnknownUpdate:
        default:
            fprintf(stderr, "Unknown update bundle version!\n");
            break;
    }
    return -1; // If we get here, there has been an error
}

int kindle_convert_ota_update_v2(FILE *input, FILE *output, const unsigned int fake_sign)
{
    unsigned char *data;
    size_t hindex;
    uint64_t source_revision;
    uint64_t target_revision;
    uint16_t num_devices;
    uint16_t device;
    //uint16_t *devices;
    uint8_t critical;
    uint8_t padding;
    char *pkg_md5_sum;
    uint16_t num_metadata;
    size_t meta_strlen;
    uint16_t metastring_length;
    char *metastring;
    //unsigned char **metastrings;
    size_t read_size __attribute__((unused));

    // First read the set block size and determine how much to resize
    data = malloc(OTA_UPDATE_V2_BLOCK_SIZE * sizeof(unsigned char));
    read_size = fread(data, sizeof(unsigned char), OTA_UPDATE_V2_BLOCK_SIZE, input);
    hindex = 0;

    source_revision = *(uint64_t *)&data[hindex];
    hindex += sizeof(uint64_t);
    fprintf(stderr, "Minimum OTA    %llu\n", (long long) source_revision);
    target_revision = *(uint64_t *)&data[hindex];
    hindex += sizeof(uint64_t);
    fprintf(stderr, "Target OTA     %llu\n", (long long) target_revision);
    num_devices = *(uint16_t *)&data[hindex];
    //hindex += sizeof(uint16_t);       // Shut clang's sa up
    fprintf(stderr, "Devices        %hd\n", num_devices);
    free(data);

    // Now get the data
    data = malloc(num_devices * sizeof(uint16_t));
    read_size = fread(data, sizeof(uint16_t), num_devices, input);
    for(hindex = 0; hindex < num_devices * sizeof(uint16_t); hindex += sizeof(uint16_t))
    {
        device = *(uint16_t *)&data[hindex];
        // Slightly hackish way to detect unknown devices, because I don't want to refactor convert_device_id()
        if(strcmp(convert_device_id(device), "Unknown") == 0)
            fprintf(stderr, "Device         Unknown (0x%02X)\n", device);
        else
            fprintf(stderr, "Device         %s\n", convert_device_id(device));
    }
    free(data);

    // Now get second part of set sized data
    data = malloc(OTA_UPDATE_V2_PART_2_BLOCK_SIZE * sizeof(unsigned char));
    read_size = fread(data, sizeof(unsigned char), OTA_UPDATE_V2_PART_2_BLOCK_SIZE, input);
    hindex = 0;

    critical = *(uint8_t *)&data[hindex];       // Apparently critical really is supposed to be 1 byte + 1 padding byte, so obey that...
    hindex += sizeof(uint8_t);
    fprintf(stderr, "Critical       %hhu\n", critical);
    padding = *(uint8_t *)&data[hindex];        // Print the (garbage?) padding byte found in official updates...
    hindex += sizeof(uint8_t);
    fprintf(stderr, "Padding Byte   %hhu (0x%02X)\n", padding, padding);
    pkg_md5_sum = (char *)&data[hindex];
    dm((unsigned char *)pkg_md5_sum, MD5_HASH_LENGTH);
    hindex += MD5_HASH_LENGTH;
    fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, pkg_md5_sum);
    num_metadata = *(uint16_t *)&data[hindex];
    //hindex += sizeof(uint16_t);       // Shut clang's sa up
    fprintf(stderr, "Metadata       %hd\n", num_metadata);
    free(data);

    // Finally, get the metastrings
    for(hindex = 0; hindex < num_metadata; hindex++)
    {
        // Get correct meta string length because of the endianness swap...
        read_size = fread(&((uint8_t *)&meta_strlen)[1], sizeof(uint8_t), 1, input);
        read_size = fread(&((uint8_t *)&meta_strlen)[0], sizeof(uint8_t), 1, input);
        metastring_length = (uint16_t)meta_strlen;
        metastring = malloc(metastring_length);
        read_size = fread(metastring, sizeof(char), metastring_length, input);
        dm((unsigned char *)metastring, metastring_length);      // Deobfuscate string (FIXME: Should meta strings really be obfuscated?)
        fprintf(stderr, "Metastring     %.*s\n", metastring_length, metastring);
        free(metastring);
    }

    if(ferror(input) != 0)
    {
        fprintf(stderr, "Cannot read update correctly: %s.\n", strerror(errno));
        return -1;
    }

    if(output == NULL)
    {
        return 0;
    }

    // Now we can decrypt the data
    return demunger(input, output, 0, fake_sign);
}

int kindle_convert_signature(UpdateHeader *header, FILE *input, FILE *output)
{
    CertificateNumber cert_num;
    char *cert_name;
    size_t seek;
    unsigned char *signature;

    if(fread(header->data.signature_header_data, sizeof(unsigned char), UPDATE_SIGNATURE_BLOCK_SIZE, input) < UPDATE_SIGNATURE_BLOCK_SIZE)
    {
        fprintf(stderr, "Cannot read signature header: %s.\n", strerror(errno));
        return -1;
    }
    cert_num = (CertificateNumber)(header->data.signature.certificate_number);
    fprintf(stderr, "Cert number    %u\n", cert_num);
    switch(cert_num)
    {
        case CertificateDeveloper:
            cert_name = "pubdevkey01.pem (Developer)";
            seek = CERTIFICATE_DEV_SIZE;
            break;
        case Certificate1K:
            cert_name = "pubprodkey01.pem (Official 1K)";
            seek = CERTIFICATE_1K_SIZE;
            break;
        case Certificate2K:
            cert_name = "pubprodkey02.pem (Official 2K)";
            seek = CERTIFICATE_2K_SIZE;
            break;
        case CertificateUnknown:
        default:
            fprintf(stderr, "Unknown signature size, cannot continue.\n");
            return -1;
            break;
    }
    fprintf(stderr, "Cert file      %s\n", cert_name);
    if(output == NULL)
    {
        return fseeko(input, (off_t)seek, SEEK_CUR);
    }
    else
    {
        signature = malloc(seek);
        if(fread(signature, sizeof(unsigned char), seek, input) < seek)
        {
            fprintf(stderr, "Cannot read signature! %s.\n", strerror(errno));
            free(signature);
            return -1;
        }
        if(fwrite(signature, sizeof(unsigned char), seek, output) < seek)
        {
            fprintf(stderr, "Cannot write signature file! %s.\n", strerror(errno));
            free(signature);
            return -1;
        }
        free(signature);
    }
    return 0;
}

int kindle_convert_ota_update(UpdateHeader *header, FILE *input, FILE *output, const unsigned int fake_sign)
{
    if(fread(header->data.ota_header_data, sizeof(unsigned char), OTA_UPDATE_BLOCK_SIZE, input) < OTA_UPDATE_BLOCK_SIZE)
    {
        fprintf(stderr, "Cannot read OTA header: %s.\n", strerror(errno));
        return -1;
    }
    dm((unsigned char *)header->data.ota_update.md5_sum, MD5_HASH_LENGTH);
    fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->data.ota_update.md5_sum);
    fprintf(stderr, "Minimum OTA    %u\n", header->data.ota_update.source_revision);
    fprintf(stderr, "Target OTA     %u\n", header->data.ota_update.target_revision);
    fprintf(stderr, "Device         %s\n", convert_device_id(header->data.ota_update.device));
    fprintf(stderr, "Optional       %hhu\n", header->data.ota_update.optional);
    fprintf(stderr, "Padding Byte   %hhu (0x%02X)\n", header->data.ota_update.unused, header->data.ota_update.unused);  // Print the (garbage?) padding byte... (The python tool puts 0x13 in there)

    if(output == NULL)
    {
        return 0;
    }

    return demunger(input, output, 0, fake_sign);
}

int kindle_convert_recovery(UpdateHeader *header, FILE *input, FILE *output, const unsigned int fake_sign)
{
    if(fread(header->data.recovery_header_data, sizeof(unsigned char), RECOVERY_UPDATE_BLOCK_SIZE, input) < RECOVERY_UPDATE_BLOCK_SIZE)
    {
        fprintf(stderr, "Cannot read recovery update header: %s.\n", strerror(errno));
        return -1;
    }
    dm((unsigned char *)header->data.recovery_update.md5_sum, MD5_HASH_LENGTH);
    fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->data.recovery_update.md5_sum);
    fprintf(stderr, "Magic 1        %d\n", header->data.recovery_update.magic_1);
    fprintf(stderr, "Magic 2        %d\n", header->data.recovery_update.magic_2);
    fprintf(stderr, "Minor          %d\n", header->data.recovery_update.minor);

    // Handle V2 header rev...
    if(header->data.recovery_h2_update.header_rev == 2)
    {
        fprintf(stderr, "Header Rev     %d\n", header->data.recovery_h2_update.header_rev);
        // Slightly ugly way to detect unknown platforms...
        if(strcmp(convert_platform_id(header->data.recovery_h2_update.platform), "Unknown") == 0)
            fprintf(stderr, "Platform       Unknown (0x%02X)\n", header->data.recovery_h2_update.platform);
        else
            fprintf(stderr, "Platform       %s\n", convert_platform_id(header->data.recovery_h2_update.platform));
        // Same shtick for unknown boards...
        if(strcmp(convert_board_id(header->data.recovery_h2_update.board), "Unknown") == 0)
            fprintf(stderr, "Board          Unknown (0x%02X)\n", header->data.recovery_h2_update.board);
        else
            fprintf(stderr, "Board          %s\n", convert_board_id(header->data.recovery_h2_update.board));
    }
    else
    {
        fprintf(stderr, "Device         %s\n", convert_device_id(header->data.recovery_update.device));
    }

    if(output == NULL)
    {
        return 0;
    }

    return demunger(input, output, 0, fake_sign);
}

int kindle_convert_recovery_v2(FILE *input, FILE *output, const unsigned int fake_sign)
{
    unsigned char *data;
    size_t hindex;
    uint64_t target_revision;
    char *pkg_md5_sum;
    uint32_t magic_1;
    uint32_t magic_2;
    uint32_t minor;
    uint32_t platform;
    uint32_t header_rev;
    uint32_t board;
    uint16_t device;
    uint8_t num_devices;
    unsigned int i;
    //uint16_t *devices;
    size_t read_size __attribute__((unused));

    // Its size is set, there's just some wonky padding involved. Read it all!
    data = malloc(RECOVERY_UPDATE_BLOCK_SIZE * sizeof(unsigned char));
    read_size = fread(data, sizeof(unsigned char), RECOVERY_UPDATE_BLOCK_SIZE, input);
    hindex = 0;

    hindex += sizeof(uint32_t); // Padding
    target_revision = *(uint64_t *)&data[hindex];
    hindex += sizeof(uint64_t);
    fprintf(stderr, "Target OTA     %llu\n", (long long) target_revision);
    pkg_md5_sum = (char *)&data[hindex];
    dm((unsigned char *)pkg_md5_sum, MD5_HASH_LENGTH);
    hindex += MD5_HASH_LENGTH;
    fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, pkg_md5_sum);
    magic_1 = *(uint32_t *)&data[hindex];
    hindex += sizeof(uint32_t);
    fprintf(stderr, "Magic 1        %d\n", magic_1);
    magic_2 = *(uint32_t *)&data[hindex];
    hindex += sizeof(uint32_t);
    fprintf(stderr, "Magic 2        %d\n", magic_2);
    minor = *(uint32_t *)&data[hindex];
    hindex += sizeof(uint32_t);
    fprintf(stderr, "Minor          %d\n", minor);
    platform = *(uint32_t *)&data[hindex];
    hindex += sizeof(uint32_t);
    // Slightly hackish way to detect unknown platforms...
    if(strcmp(convert_platform_id(platform), "Unknown") == 0)
        fprintf(stderr, "Platform       Unknown (0x%02X)\n", platform);
    else
        fprintf(stderr, "Platform       %s\n", convert_platform_id(platform));
    header_rev = *(uint32_t *)&data[hindex];
    hindex += sizeof(uint32_t);
    fprintf(stderr, "Header Rev     %d\n", header_rev);
    board = *(uint32_t *)&data[hindex];
    hindex += sizeof(uint32_t);
    // Slightly hackish way to detect unknown boards (Not to be confused with the 'Unspecified' board, which permits skipping the device/board check)...
    if(strcmp(convert_board_id(board), "Unknown") == 0)
        fprintf(stderr, "Board          %s (0x%02X)\n", convert_board_id(board), board);
    else
        fprintf(stderr, "Board          %s\n", convert_board_id(board));
    hindex += sizeof(uint32_t); // Padding
    hindex += sizeof(uint16_t); // ... Padding
    hindex += sizeof(uint8_t);  // And more weird padding
    num_devices = *(uint8_t *)&data[hindex];
    hindex += sizeof(uint8_t);
    fprintf(stderr, "Devices        %hhd\n", num_devices);
    for(i = 0; i < num_devices; i++)
    {
        device = *(uint16_t *)&data[hindex];
        // Slightly hackish way to detect unknown devices...
        if(strcmp(convert_device_id(device), "Unknown") == 0)
            fprintf(stderr, "Device         Unknown (0x%02X)\n", device);
        else
            fprintf(stderr, "Device         %s\n", convert_device_id(device));
        hindex += sizeof(uint16_t);
    }
    free(data);

    if(ferror(input) != 0)
    {
        fprintf(stderr, "Cannot read update correctly: %s.\n", strerror(errno));
        return -1;
    }

    if(output == NULL)
    {
        return 0;
    }

    // Now we can decrypt the data
    return demunger(input, output, 0, fake_sign);
}

int kindle_convert_main(int argc, char *argv[])
{
    int opt;
    int opt_index;
    static const struct option opts[] =
    {
        { "stdout", no_argument, NULL, 'c' },
        { "info", no_argument, NULL, 'i' },
        { "keep", no_argument, NULL, 'k' },
        { "sig", no_argument, NULL, 's' },
        { "unsigned", no_argument, NULL, 'u' },
        { "unwrap", no_argument, NULL, 'w' },
        { NULL, 0, NULL, 0 }
    };
    FILE *input;
    FILE *output;
    FILE *sig_output;
    FILE *unwrap_output;
    const char *in_name;
    char *out_name = NULL;
    char *sig_name = NULL;
    char *unwrapped_name = NULL;
    size_t len;
    struct stat st;
    int info_only;
    int keep_ori;
    int extract_sig;
    unsigned int fake_sign;
    unsigned int unwrap_only;
    unsigned int ext_offset;
    int fail;

    sig_output = NULL;
    unwrap_output = NULL;
    output = NULL;
    info_only = 0;
    keep_ori = 0;
    extract_sig = 0;
    fake_sign = 0;
    unwrap_only = 0;
    ext_offset = 0;
    fail = 1;
    while((opt = getopt_long(argc, argv, "icksuw", opts, &opt_index)) != -1)
    {
        switch(opt)
        {
            case 'i':
                info_only = 1;
                break;
            case 'k':
                keep_ori = 1;
                break;
            case 'c':
                output = stdout;
                break;
            case 's':
                extract_sig = 1;
                break;
            case 'u':
                fake_sign = 1;
                break;
            case 'w':
                unwrap_only = 1;
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
                fprintf(stderr, "?? Unknown option code 0%o ??\n", opt);
                return -1;
                break;
        }
    }
    // Don't try to output to stdout or extract/unwrap the package sig if we asked for info only
    if(info_only)
    {
        output = NULL;
        extract_sig = 0;
        unwrap_only = 0;
    }
    // Don't try to extract or unwrap the signature of an unsiged package
    if(fake_sign)
    {
        extract_sig = 0;
        unwrap_only = 0;
    }
    // Don't try to output anywhere if we only want to unwrap the package
    if(unwrap_only)
    {
        output = NULL;
    }

    if(optind < argc)
    {
        // Iterate over non-options (the file(s) we passed) (stdout output is probably pretty dumb when passing multiple files...)
        while(optind < argc)
        {
            fail = 0;
            in_name = argv[optind++];
            // Check that a valid package input properly ends in .bin or .stgz, unless we just want to parse the header
            if(!info_only && (!IS_BIN(in_name) && !IS_STGZ(in_name)))
            {
                fprintf(stderr, "Input file '%s' is neither a '.bin' update package nor a '.stgz' userdata package.\n", in_name);
                fail = 1;
                continue;   // It's fatal, go away
            }
            // Set the appropriate file extension offset...
            if(IS_STGZ(in_name))
                ext_offset = 1;
            else
                ext_offset = 0;
            if(!info_only && !unwrap_only && output != stdout) // Not info only, not unwrap only AND not stdout
            {
                len = strlen(in_name);
                out_name = malloc(len + 1 + (13 - ext_offset));
                memcpy(out_name, in_name, len - (4 + ext_offset));
                out_name[len - (4 + ext_offset)] = 0;    // . => \0
                strncat(out_name, "_converted.tar.gz", 17);
                if((output = fopen(out_name, "wb")) == NULL)
                {
                    fprintf(stderr, "Cannot open output '%s' for writing.\n", out_name);
                    fail = 1;
                    free(out_name);
                    continue;   // It's fatal, go away
                }
            }
            if(extract_sig) // We want the payload sig (implies not info only)
            {
                len = strlen(in_name);
                sig_name = malloc(len + 1 + (1 - ext_offset));
                memcpy(sig_name, in_name, len - (4 + ext_offset));
                sig_name[len - (4 + ext_offset)] = 0;  // . => \0
                strncat(sig_name, ".psig", 5);
                if((sig_output = fopen(sig_name, "wb")) == NULL)
                {
                    fprintf(stderr, "Cannot open signature output '%s' for writing.\n", sig_name);
                    fail = 1;
                    if(!info_only && output != stdout)
                        free(out_name);
                    free(sig_name);
                    continue;   // It's fatal, go away
                }
            }
            if(unwrap_only)     // We want an unwrapped package (implies not info only)
            {
                len = strlen(in_name);
                unwrapped_name = malloc(len + 1 + (10 - ext_offset));
                memcpy(unwrapped_name, in_name, len - (4 + ext_offset));
                unwrapped_name[len - (4 + ext_offset)] = 0;  // . => \0
                // If input is an userdata package, we can safely assume we'll end up with a tarballl
                if(ext_offset)
                    strncat(unwrapped_name, "_unwrapped.tgz", 14);
                else
                    strncat(unwrapped_name, "_unwrapped.bin", 14);
                if((unwrap_output = fopen(unwrapped_name, "wb")) == NULL)
                {
                    fprintf(stderr, "Cannot open unwrapped package output '%s' for writing.\n", unwrapped_name);
                    fail = 1;
                    free(unwrapped_name);
                    continue;   // It's fatal, go away
                }
            }
            if((input = fopen(in_name, "rb")) == NULL)
            {
                fprintf(stderr, "Cannot open input '%s' for reading.\n", in_name);
                fail = 1;
                if(!info_only && !unwrap_only && output != stdout)
                    free(out_name);
                if(extract_sig)
                    free(sig_name);
                continue;   // It's fatal, go away
            }
            // If we're outputting to stdout, set a dummy human readable output name
            if(!info_only && output == stdout)
            {
                out_name = strdup("standard output");
            }
            // Print a recap of what we're doing
            if(info_only)
            {
                fprintf(stderr, "Checking %s%s package '%s'.\n", (fake_sign ? "fake " : ""), (IS_STGZ(in_name) ? "userdata" : "update"), in_name);
            }
            else if(unwrap_only)
            {
                fprintf(stderr, "Unwrapping %s package '%s' to '%s'.\n", (IS_STGZ(in_name) ? "userdata" : "update"), in_name, unwrapped_name);
            }
            else
            {
                fprintf(stderr, "Converting %s%s package '%s' to '%s' (%s, %s).\n", (fake_sign ? "fake " : ""), (IS_STGZ(in_name) ? "userdata" : "update"), in_name, out_name, (extract_sig ? "with sig" : "without sig"), (keep_ori ? "keep input" : "delete input"));
            }
            if(kindle_convert(input, output, sig_output, fake_sign, unwrap_only, unwrap_output) < 0)
            {
                fprintf(stderr, "Error converting %s package '%s'.\n", (IS_STGZ(in_name) ? "userdata" : "update"), in_name);
                if(output != NULL && output != stdout)
                    unlink(out_name); // Clean up our mess, if we made one
                fail = 1;
            }
            if(output != stdout && !info_only && !keep_ori && !fail) // If output was some file, and we didn't ask to keep it, and we didn't fail to convert it, delete the original
                unlink(in_name);

            // Clean up behind us
            if(!info_only && !unwrap_only)
                free(out_name);
            if(output != NULL && output != stdout)
                fclose(output);
            if(input != NULL)
                fclose(input);
            if(sig_output != NULL)
                fclose(sig_output);
            if(unwrap_output != NULL)
                fclose(unwrap_output);
            // Remove empty sigs (since we have to open the fd before calling kindle_convert, we end up with an empty file for packages that aren't wrapped in an UpdateSignature)
            if(extract_sig)
            {
                stat(sig_name, &st);
                if(st.st_size == 0)
                    unlink(sig_name);
                free(sig_name);
            }
            // Same thing for unwrapped packages...
            if(unwrap_only)
            {
                stat(unwrapped_name, &st);
                if(st.st_size == 0)
                    unlink(unwrapped_name);
                free(unwrapped_name);
            }

            // If we're not the last file, throw an LF to untangle the output
            if(optind < argc)
                fprintf(stderr, "\n");
        }
    }
    else
    {
        fprintf(stderr, "No input specified.\n");
        return -1;
    }

    // Return
    if(fail)
        return -1;
    else
        return 0;
}

// Heavily inspired from libarchive's tar/read.c ;)
int libarchive_extract(const char *filename, const char *prefix)
{
    struct archive *a;
    struct archive_entry *entry;
    int flags;
    int r;
    const char *path = NULL;
    char *fixed_path = NULL;
    size_t len;

    // Select which attributes we want to restore.
    flags = ARCHIVE_EXTRACT_TIME;
    // Don't preserve permissions, as most files in kindle packages will be owned by root, and if the perms are effed up, it gets annoying.
    // We could also just rewrite every entry in the archive with sane permissions, but that seems a bit overkill.
    //flags |= ARCHIVE_EXTRACT_PERM;
    //flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;

    a = archive_read_new();
    // Let's handle a wide range or tar formats, just to be on the safe side
    archive_read_support_format_tar(a);
    archive_read_support_format_gnutar(a);
    archive_read_support_filter_gzip(a);

    if(filename != NULL && strcmp(filename, "-") == 0)
        filename = NULL;
    if((r = archive_read_open_filename(a, filename, 10240)))
    {
        fprintf(stderr, "archive_read_open_file() failure: %s.\n", archive_error_string(a));
        archive_read_free(a);
        return 1;
    }

    for(;;)
    {
        r = archive_read_next_header(a, &entry);
        if(r == ARCHIVE_EOF)
            break;
        if(r != ARCHIVE_OK)
            fprintf(stderr, "archive_read_next_header() failed: %s.\n", archive_error_string(a));
        if(r < ARCHIVE_WARN)
            goto cleanup;

        // Print what we're extracting, like bsdtar
        path = archive_entry_pathname(entry);
        fprintf(stderr, "x %s\n", path);
        // Rewrite the entry's pathname to extract in the right output directory
        len = strlen(prefix) + 1 + strlen(path) + 1;
        fixed_path = malloc(len);
        snprintf(fixed_path, len, "%s/%s", prefix, path);
        archive_entry_copy_pathname(entry, fixed_path);

        // archive_read_extract should take care of everything for us...
        // (creating a write_disk archive, setting a standard lookup, the flags we asked for, writing our entry header & content, and destroying the write_disk archive ;))
        r = archive_read_extract(a, entry, flags);
        if(r != ARCHIVE_OK)
        {
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

int kindle_extract_main(int argc, char *argv[])
{
    int opt;
    int opt_index;
    static const struct option opts[] =
    {
        { "unsigned", no_argument, NULL, 'u' },
        { NULL, 0, NULL, 0 }
    };
    unsigned int fake_sign;

    char *bin_filename;
    char tgz_filename[] = KT_TMPDIR "/kindletool_extract_tgz_XXXXXX";
    char *output_dir;
    FILE *bin_input;
    int tgz_fd;
    FILE *tgz_output;

    fake_sign = 0;
    bin_filename = NULL;
    output_dir = NULL;
    while((opt = getopt_long(argc, argv, "u", opts, &opt_index)) != -1)
    {
        switch(opt)
        {
            case 'u':
                fake_sign = 1;
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
                fprintf(stderr, "?? Unknown option code 0%o ??\n", opt);
                return -1;
                break;
        }
    }

    // We need exactly 2 non-switch options (I/O)!
    if(optind < argc && (optind + 2) == argc)
    {
        // We know exactly what we need, and in what order
        bin_filename = argv[optind];
        output_dir = argv[optind + 1];
    }
    else
    {
        fprintf(stderr, "Invalid number of arguments (need input & output).\n");
        return -1;
    }
    // Double validation, and make GCC happy
    if(bin_filename == NULL)
    {
        fprintf(stderr, "Input filename isn't set!\n");
        return -1;
    }
    if(output_dir == NULL)
    {
        fprintf(stderr, "Output directory isn't set!\n");
        return -1;
    }

    // Check that input properly ends in .bin or .stgz
    if(!IS_BIN(bin_filename) && !IS_STGZ(bin_filename))
    {
        fprintf(stderr, "Input file '%s' is neither a '.bin' update package nor a '.stgz' userdata package.\n", bin_filename);
        return -1;
    }
    // NOTE: Do some sanity checks for output directory handling?
    // The 'rewrite pathname entry' cheap method we currently use is pretty 'dumb' (it assumes the path is correct, creating it if need be),
    // but the other (more correct?) way to handle this (chdir) would need some babysitting (cf. bsdtar's *_chdir() in tar/util.c)...
    if((bin_input = fopen(bin_filename, "rb")) == NULL)
    {
        fprintf(stderr, "Cannot open input %s package '%s': %s.\n", (IS_STGZ(bin_filename) ? "userdata" : "update"), bin_filename, strerror(errno));
        return -1;
    }
    // Use a non-racy tempfile, hopefully... (Heavily inspired from http://www.tldp.org/HOWTO/Secure-Programs-HOWTO/avoid-race.html)
    // We always create them in P_tmpdir (usually /tmp or /var/tmp), and rely on the OS implementation to handle the umask,
    // it'll cost us less LOC that way since I don't really want to introduce a dedicated utility function for tempfile handling...
    // NOTE: Probably not as race-proof on MinGW, according to libarchive...
#if defined(_WIN32) && !defined(__CYGWIN__)
    // Inspired from libgit2's Posix emulation layer (https://github.com/libgit2/libgit2)
    if(_mktemp(tgz_filename) == NULL)
    {
        fprintf(stderr, "Couldn't create temporary file template: %s.\n", strerror(errno));
        fclose(bin_input);
        return -1;
    }
    tgz_fd = open(tgz_filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0744);
#else
    tgz_fd = mkstemp(tgz_filename);
#endif
    if(tgz_fd == -1)
    {
        fprintf(stderr, "Couldn't open temporary file: %s.\n", strerror(errno));
        fclose(bin_input);
        return -1;
    }
    if((tgz_output = fdopen(tgz_fd, "wb")) == NULL)
    {
        fprintf(stderr, "Cannot open temp output '%s' for writing: %s.\n", tgz_filename, strerror(errno));
        fclose(bin_input);
        close(tgz_fd);
        unlink(tgz_filename);
        return -1;
    }
    // Print a recap of what we're about to do
    fprintf(stderr, "Extracting %s package '%s' to '%s'.\n", (IS_STGZ(bin_filename) ? "userdata" : "update"), bin_filename, output_dir);
    if(kindle_convert(bin_input, tgz_output, NULL, fake_sign, 0, NULL) < 0)
    {
        fprintf(stderr, "Error converting %s package '%s'.\n", (IS_STGZ(bin_filename) ? "userdata" : "update"), bin_filename);
        fclose(bin_input);
        fclose(tgz_output);
        return -1;
    }
    fclose(bin_input);
    fclose(tgz_output);
    if(libarchive_extract(tgz_filename, output_dir) < 0)
    {
        fprintf(stderr, "Error extracting temp tarball '%s' to '%s'.\n", tgz_filename, output_dir);
        unlink(tgz_filename);
        return -1;
    }
    unlink(tgz_filename);
    return 0;
}

// kate: indent-mode cstyle; indent-width 4; replace-tabs on;
