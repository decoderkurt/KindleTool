//
//  main.c
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

void md(unsigned char *bytes, size_t length)
{
    unsigned int i;
    for(i = 0; i < length; i++)
    {
        bytes[i] = (unsigned char)((bytes[i] >> 4 | bytes[i] << 4) & 0xFF) ^ 0x7A;
    }
}

void dm(unsigned char *bytes, size_t length)
{
    unsigned int i;
    for(i = 0; i < length; i++)
    {
        bytes[i] = (bytes[i] ^ 0x7A);
        bytes[i] = (unsigned char)(bytes[i] >> 4 | bytes[i] << 4) & 0xFF;
    }
}

int munger(FILE *input, FILE *output, size_t length, const unsigned int fake_sign)
{
    unsigned char bytes[BUFFER_SIZE];
    size_t bytes_read;
    size_t bytes_written;

    while((bytes_read = fread(bytes, sizeof(unsigned char), (length < BUFFER_SIZE && length > 0 ? length : BUFFER_SIZE), input)) > 0)
    {
        // Don't munge if we asked for a fake package
        if(!fake_sign)
            md(bytes, bytes_read);
        bytes_written = fwrite(bytes, sizeof(unsigned char), bytes_read, output);
        if(ferror(output) != 0)
        {
            fprintf(stderr, "Error munging, cannot write to output.\n");
            return -1;
        }
        else if(bytes_written < bytes_read)
        {
            fprintf(stderr, "Error munging, read %zu bytes but only wrote %zu bytes\n", bytes_read, bytes_written);
            return -1;
        }
        length -= bytes_read;
    }
    if(ferror(input) != 0)
    {
        fprintf(stderr, "Error munging, cannot read input.\n");
        return -1;
    }

    return 0;
}

int demunger(FILE *input, FILE *output, size_t length, const unsigned int fake_sign)
{
    unsigned char bytes[BUFFER_SIZE];
    size_t bytes_read;
    size_t bytes_written;
    while((bytes_read = fread(bytes, sizeof(unsigned char), (length < BUFFER_SIZE && length > 0 ? length : BUFFER_SIZE), input)) > 0)
    {
        // Don't demunge if we supplied a fake package
        if(!fake_sign)
            dm(bytes, bytes_read);
        bytes_written = fwrite(bytes, sizeof(unsigned char), bytes_read, output);
        if(ferror(output) != 0)
        {
            fprintf(stderr, "Error demunging, cannot write to output.\n");
            return -1;
        }
        else if(bytes_written < bytes_read)
        {
            fprintf(stderr, "Error demunging, read %zu bytes but only wrote %zu bytes\n", bytes_read, bytes_written);
            return -1;
        }
        length -= bytes_read;
    }
    if(ferror(input) != 0)
    {
        fprintf(stderr, "Error demunging, cannot read input.\n");
        return -1;
    }

    return 0;
}

const char *convert_device_id(Device dev)
{
    switch(dev)
    {
        case Kindle1:
            return "Kindle 1";
        case Kindle2US:
            return "Kindle 2 US";
        case Kindle2International:
            return "Kindle 2 International";
        case KindleDXUS:
            return "Kindle DX US";
        case KindleDXInternational:
            return "Kindle DX International";
        case KindleDXGraphite:
            return "Kindle DX Graphite";
        case Kindle3Wifi:
            return "Kindle 3 Wifi";
        case Kindle3Wifi3G:
            return "Kindle 3 Wifi+3G";
        case Kindle3Wifi3GEurope:
            return "Kindle 3 Wifi+3G Europe";
        case Kindle4NonTouch:
            return "Kindle 4 Non-Touch Silver (2011)";
        case Kindle5TouchWifi:
            return "Kindle 5 Touch Wifi";
        case Kindle5TouchWifi3G:
            return "Kindle 5 Touch Wifi+3G";
        case Kindle5TouchWifi3GEurope:
            return "Kindle 5 Touch Wifi+3G Europe";
        case Kindle5TouchUnknown:
            return "Kindle 5 Touch (Unknown Variant)";
        case Kindle4NonTouchBlack:
            return "Kindle 4 Non-Touch Black (2012)";
        case KindlePaperWhiteWifi:
            return "Kindle PaperWhite Wifi";
        case KindlePaperWhiteWifi3G:
            return "Kindle PaperWhite Wifi+3G";
        case KindlePaperWhiteWifi3GCanada:
            return "Kindle PaperWhite Wifi+3G Canada";
        case KindlePaperWhiteWifi3GEurope:
            return "Kindle PaperWhite Wifi+3G Europe";
        case KindlePaperWhiteWifi3GJapan:
            return "Kindle PaperWhite Wifi+3G Japan";
        case KindlePaperWhiteWifi3GBrazil:
            return "Kindle PaperWhite Wifi+3G Brazil";
        case KindlePaperWhite2Wifi:
            return "Kindle PaperWhite 2 (2013) Wifi";
#ifdef KT_UNKNOWN_DEVID
        case ValidKindleUnknown_0x13:
            return "Unknown Kindle (B013)";
        case ValidKindleUnknown_0x16:
            return "Unknown Kindle (B016)";
        case ValidKindleUnknown_0x21:
            return "Unknown Kindle (B021)";
#endif
        case KindleUnknown:
        default:
            return "Unknown";
    }
}

const char *convert_platform_id(Platform plat)
{
    switch(plat)
    {
        case MarioDeprecated:
            return "Mario (Deprecated)";
        case Luigi:
            return "Luigi";
        case Banjo:
            return "Banjo";
        case Yoshi:
            return "Yoshi";
        case YoshimeProto:
            return "Yoshime (Prototype)";
        case Yoshime:
            return "Yoshime (Yoshime3)";
        case Wario:
            return "Wario";
        case Plat_Unspecified:
            return "Unspecified";
        default:
            return "Unknown";
    }
}

const char *convert_board_id(Board board)
{
    switch(board)
    {
        case Board_Unspecified:
            return "Unspecified";
        case Tequila:
            return "Tequila";
        case Whitney:
            return "Whitney";
        default:
            return "Unknown";
    }
}

const char *convert_bundle_version(BundleVersion bundlev)
{
    switch(bundlev)
    {
        case UpdateSignature:
            return "Signature";
        case OTAUpdateV2:
            return "OTA V2";
        case OTAUpdate:
            return "OTA V1";
        case RecoveryUpdate:
            return "Recovery";
        case RecoveryUpdateV2:
            return "Recovery V2";
        case UnknownUpdate:
        default:
            return "Unknown";
    }
}

BundleVersion get_bundle_version(char magic_number[4])
{
    if(!strncmp(magic_number, "FB02", 4) || !strncmp(magic_number, "FB01", 4))
        return RecoveryUpdate;
    else if(!strncmp(magic_number, "FB03", 4))
        return RecoveryUpdateV2;
    else if(!strncmp(magic_number, "FC02", 4) || !strncmp(magic_number, "FD03", 4))
        return OTAUpdate;
    else if(!strncmp(magic_number, "FC04", 4) || !strncmp(magic_number, "FD04", 4) || !strncmp(magic_number, "FL01", 4))
        return OTAUpdateV2;
    else if(!strncmp(magic_number, "SP01", 4))
        return UpdateSignature;
    else
        return UnknownUpdate;
}

const char *convert_magic_number(char magic_number[4])
{
    if(!strncmp(magic_number, "FB02", 4))
        return "(Fullbin [signed?])";           // /mnt/us/update-full.bin
    else if(!strncmp(magic_number, "FB03", 4))
        return "(Fullbin [OTA?, fwo?])";        // /mnt/us/update-%lld-fwo.bin
    else if(!strncmp(magic_number, "FB", 2))
        return "(Fullbin)";
    else if(!strncmp(magic_number, "FC", 2))
        return "(OTA [ota])";                   // /mnt/us/Update_%lld_%lld.bin
    else if(!strncmp(magic_number, "FD", 2))
        return "(Versionless [vls])";           // /mnt/us/Update_VLS_%lld.bin
    else if(!strncmp(magic_number, "FL", 2))
        return "(Language [lang])";             // /mnt/us/Update_LANG_%s.bin
    else if(!strncmp(magic_number, "SP", 2))
        return "(Signing Envelope)";
    else
        return "Unknown";
}


int md5_sum(FILE *input, char output_string[MD5_HASH_LENGTH])
{
    unsigned char bytes[BUFFER_SIZE];
    size_t bytes_read;
    MD5_CTX md5;
    unsigned char output[MD5_DIGEST_LENGTH];
    char output_string_temp[MD5_HASH_LENGTH + 1]; // sprintf adds a trailing null, we do not want that!
    int i;

    MD5_Init(&md5);
    while((bytes_read = fread(bytes, sizeof(unsigned char), BUFFER_SIZE, input)) > 0)
    {
        MD5_Update(&md5, bytes, bytes_read);
    }
    if(ferror(input) != 0)
    {
        fprintf(stderr, "Error reading input.\n");
        return -1;
    }
    MD5_Final(output, &md5);
    for(i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        sprintf(output_string_temp + (i * 2), "%02x", output[i]);
    }
    memcpy(output_string, output_string_temp, MD5_HASH_LENGTH); // Remove the trailing null. Any better way to do this?
    return 0;
}

RSA *get_default_key(void)
{
    static char sign_key[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICXgIBAAKBgQDJn1jWU+xxVv/eRKfCPR9e47lPWN2rH33z9QbfnqmCxBRLP6mM\n"
        "jGy6APyycQXg3nPi5fcb75alZo+Oh012HpMe9LnpeEgloIdm1E4LOsyrz4kttQtG\n"
        "RlzCErmBGt6+cAVEV86y2phOJ3mLk0Ek9UQXbIUfrvyJnS2MKLG2cczjlQIDAQAB\n"
        "AoGASLym1POD2kOznSERkF5yoc3vvXNmzORYkRk1eJkJuDY6yAbYiO7kDppqj4l8\n"
        "wGogTpv98OMXauY8JgQj6tgO5LkY2upttukDr8uhE2z9Dh7HMZV/rDYa+9rybJus\n"
        "RiAQDmF+VCzY2HirjpsSzgRu0r82NC8znNm2eGORys9BvmECQQDoIokOr0fYz3UT\n"
        "SbHfD3engXFPZ+JaJqU8xayR7C+Gp5I0CgSnCDTQVgdkVGbPuLVYiWDIcEaxjvVr\n"
        "hXYt2Ac9AkEA3lnERgg0RmWBC3K8toCyfDvr8eXao+xgUJ3lNWbqS0HtwxczwnIE\n"
        "H49IIDojbTnLUr3OitFMZuaJuT2MtWzTOQJBAK6GCHU54tJmZqbxqQEDJ/qPnxkM\n"
        "CWmt1F00YOH0qGacZZcqUQUjblGT3EraCdHyFKVT46fOgdfMm0cTOB6PZCECQQDI\n"
        "s5Zq8HTfJjg5MTQOOFTjtuLe0m9sj6zQl/WRInhRvgzzkDn0Rh5armaYUGIx8X0K\n"
        "DrIks4+XQnkGb/xWtwhhAkEA3FdnrsFiCNNJhvit2aTmtLzXxU46K+sV6NIY1tEJ\n"
        "G+RFzLRwO4IFDY4a/dooh1Yh1iFFGjcmpqza6tRutaw8zA==\n"
        "-----END RSA PRIVATE KEY-----\0";
    static RSA *rsa_pkey = NULL;
    BIO *bio;
    if(rsa_pkey == NULL)
    {
        bio = BIO_new_mem_buf((void *)sign_key, -1);
        if(PEM_read_bio_RSAPrivateKey(bio, &rsa_pkey, NULL, NULL) == NULL)
        {
            fprintf(stderr, "Error loading RSA Private Key File\n");
            return NULL;
        }
        // Don't leak our BIO
        BIO_free(bio);
    }
    return rsa_pkey;
}

int kindle_print_help(const char *prog_name)
{
    printf(
        "usage:\n"
        "  %s md [ <input> ] [ <output> ]\n"
        "    Obfuscates data using Amazon's update algorithm.\n"
        "    If no input is provided, input from stdin\n"
        "    If no output is provided, output to stdout\n"
        "    \n"
        "  %s dm [ <input> ] [ <output> ]\n"
        "    Deobfuscates data using Amazon's update algorithm.\n"
        "    If no input is provided, input from stdin\n"
        "    If no output is provided, output to stdout\n"
        "    \n"
        "  %s convert [options] <input>...\n"
        "    Converts a Kindle update package to a gzipped tar archive file, and delete input\n"
        "    \n"
        "    Options:\n"
        "      -c, --stdout                Write to standard output, keeping original files unchanged\n"
        "      -i, --info                  Just print the package information, no conversion done\n"
        "      -s, --sig                   OTA V2 updates only. Extract the package signature.\n"
        "      -k, --keep                  Don't delete the input package.\n"
        "      -u, --unsigned              Assume input is an unsigned package.\n"
        "      -w, --unwrap                Just unwrap the package, if it's wrapped in an UpdateSignature header\n"
        "      \n"
        "  %s extract <input> <output>\n"
        "    Extracts a Kindle update package to a directory\n"
        "    \n"
        "  %s create <type> <devices> [options] <dir|file>... [ <output> ]\n"
        "    Creates a Kindle update package\n"
        "    You should be able to throw a mix of files & directories as input without trouble.\n"
        "    Just keep in mind that by default, if you feed it absolute paths, it will archive absolute paths, which usually isn't what you want!\n"
        "    If input is a single gzipped tarball (\".tgz\" or \".tar.gz\") file, we assume it is properly packaged (bundlefile & sigfile), and will only convert it to an update.\n"
        "    Output should be a file with the extension \".bin\", if it is not provided, or if it's a single dash, output to stdout.\n"
        "    In case of OTA updates, all files with the extension \".ffs\" or \".sh\" will be treated as update scripts.\n"
        "    \n"
        "    Type:\n"
        "      ota                         OTA V1 update package. Works on Kindle 3 and older.\n"
        "      ota2                        OTA V2 signed update package. Works on Kindle 4 and newer.\n"
        "      recovery                    Recovery package for restoring partitions.\n"
        "      recovery2                   Recovery V2 package for restoring partitions. Works on Kindle 5 (PaperWhite) and newer.\n"
        "    \n"
        "    Devices:\n"
        "      OTA V1 & Recovery packages only support one device. OTA V2 & Recovery V2 packages can support multiple devices.\n"
        "      \n"
        "      -d, --device k1             Kindle 1\n"
        "      -d, --device k2             Kindle 2 US\n"
        "      -d, --device k2i            Kindle 2 International\n"
        "      -d, --device dx             Kindle DX US\n"
        "      -d, --device dxi            Kindle DX International\n"
        "      -d, --device dxg            Kindle DX Graphite\n"
        "      -d, --device k3w            Kindle 3 Wifi\n"
        "      -d, --device k3g            Kindle 3 Wifi+3G\n"
        "      -d, --device k3gb           Kindle 3 Wifi+3G Europe\n"
        "      -d, --device k4             Kindle 4 (No Touch) Silver (2011)\n"
        "      -d, --device k4b            Kindle 4 (No Touch) Black (2012)\n"
        "      -d, --device kindle4        Alias for k4 & k4b\n"
        "      -d, --device k5w            Kindle 5 (Kindle Touch) Wifi\n"
        "      -d, --device k5g            Kindle 5 (Kindle Touch) Wifi+3G\n"
        "      -d, --device k5gb           Kindle 5 (Kindle Touch) Wifi+3G Europe\n"
        "      -d, --device k5u            Kindle 5 (Kindle Touch) Unknown Variant (4th device code found in Touch official updates)\n"
        "      -d, --device pw             Kindle PaperWhite Wifi\n"
        "      -d, --device pwg            Kindle PaperWhite Wifi+3G\n"
        "      -d, --device pwgc           Kindle PaperWhite Wifi+3G Canada\n"
        "      -d, --device pwgb           Kindle PaperWhite Wifi+3G Europe\n"
        "      -d, --device pwgj           Kindle PaperWhite Wifi+3G Japan\n"
        "      -d, --device pwgbr          Kindle PaperWhite Wifi+3G Brazil\n"
        "      -d, --device pw2            Kindle PaperWhite 2 (2013) Wifi\n"
        "      -d, --device kindle5        Alias for k5w, k5g, k5gb, pw, pwg, pwgc, pwgb, pwgj, pwgbr & pw2\n"
        "      -d, --device touch          Alias for k5w, k5g & k5gb\n"
        "      -d, --device paperwhite     Alias for pw, pwg, pwgc, pwgb, pwgj & pwgbr\n"
        "      -d, --device paperwhite2    Alias for pw2\n"
        "      -d, --device none           No specific device (Recovery V2 & Recovery FB02 with header rev 2 only, default)\n"
        "      \n"
        "    Platforms:\n"
        "      Recovery V2 & recovery FB02 with header rev 2 updates only. Use a single platform per package.\n"
        "      \n"
        "      -p, --platform mario        Mario (mostly devices shipped on FW 1.x) [Deprecated]\n"
        "      -p, --platform luigi        Luigi (mostly devices shipped on FW 2.x)\n"
        "      -p, --platform banjo        Banjo (devices shipped on FW 3.x?)\n"
        "      -p, --platform yoshi        Yoshi (mostly devices shipped on FW <= 5.1)\n"
        "      -p, --platform yoshime-p    Yoshime (Prototype)\n"
        "      -p, --platform yoshime      Yoshime (Also known as Yoshime3, mostly devices shipped on FW >= 5.2)\n"
        "      -p, --platform wario        Wario (mostly devices shipped on FW >= 5.4)\n"
        "      \n"
        "    Boards:\n"
        "      Recovery V2 & Recovery FB02 with header rev 2 updates only. Use a single board per package.\n"
        "      \n"
        "      -B, --board unspecified     Don't target a specific board, skip the device check\n"
        "      -B, --board tequila         Tequila (Kindle 4)\n"
        "      -B, --board whitney         Whitney (Kindle Touch)\n"
        "      \n"
        "    Options:\n"
        "      All the following options are optional and advanced.\n"
        "      -k, --key <file>            PEM file containing RSA private key to sign update. Default is popular jailbreak key.\n"
        "      -b, --bundle <type>         Manually specify package magic number. May override the value dictated by \"type\", if it makes sense. Valid bundle versions:\n"
        "                                    FB01, FB02 = recovery; FB03 = recovery2; FC02, FD03 = ota; FC04, FD04, FL01 = ota2\n"
        "      -s, --srcrev <ulong|uint>   OTA updates only. Source revision. OTA V1 uses uint, OTA V2 uses ulong.\n"
        "                                    Lowest version of device that package supports. Default is 0.\n"
        "      -t, --tgtrev <ulong|uint>   OTA & Recovery V2 updates only. Target revision. OTA V1 uses uint, OTA V2 & Recovery V2 uses ulong.\n"
        "                                    Highest version of device that package supports. Default is ulong/uint max value.\n"
        "      -h, --hdrrev <uint>         Recovery V2 & Recovery FB02 updates only. Header Revision. Default is 0.\n"
        "      -1, --magic1 <uint>         Recovery updates only. Magic number 1. Default is 0.\n"
        "      -2, --magic2 <uint>         Recovery updates only. Magic number 2. Default is 0.\n"
        "      -m, --minor <uint>          Recovery updates only. Minor number. Default is 0.\n"
        "      -c, --cert <ushort>         OTA V2 updates only. The number of the certificate to use (found in /etc/uks on device). Default is 0.\n"
        "                                    0 = pubdevkey01.pem, 1 = pubprodkey01.pem, 2 = pubprodkey02.pem\n"
        "      -o, --opt <uchar>           OTA V1 updates only. One byte optional data expressed as a number. Default is 0.\n"
        "      -r, --crit <uchar>          OTA V2 updates only. One byte optional data expressed as a number. Default is 0.\n"
        "      -x, --meta <str>            OTA V2 updates only. An optional string to add. Multiple \"--meta\" options supported.\n"
        "                                    Format of metastring must be: key=value\n"
        "      -a, --archive               Keep the intermediate archive.\n"
        "      -u, --unsigned              Build an unsigned package.\n"
        "      -C, --legacy                Emulate the behaviour of yifanlu's KindleTool regarding directories. By default, we behave like tar:\n"
        "                                    every path passed on the commandline is stored as-is in the archive. This switch changes that, and store paths\n"
        "                                    relative to the path passed on the commandline, like if we had chdir'ed into it.\n"
        "      \n"
        "  %s info <serialno>\n"
        "    Get the default root password\n"
        "    Unless you changed your password manually, the first password shown will be the right one.\n"
        "    (The Kindle defaults to DES hashed passwords, which are truncated to 8 characters.)\n"
        "    If you're looking for the recovery MMC export password, that's the second one.\n"
        "    \n"
        "  %s version\n"
        "    Show some info about this KindleTool build\n"
        "    \n"
        "  %s help\n"
        "    Show this help screen\n"
        "    \n"
        "notices:\n"
        "  1)  Kindle 4.0+ has a known bug that prevents some updates with meta-strings to run.\n"
        "  2)  Currently, even though OTA V2 supports updates that run on multiple devices, it is not possible to create an update package that will run on both the Kindle 4 (No Touch) and Kindle 5 (Kindle Touch).\n"
        , prog_name, prog_name, prog_name, prog_name, prog_name, prog_name, prog_name, prog_name);
    return 0;
}

int kindle_print_version(const char *prog_name)
{
#ifdef __clang__
    printf("%s (KindleTool) %s built by %s with Clang %s on %s @ %s against %s\n", prog_name, KT_VERSION, KT_USERATHOST, __clang_version__, __DATE__, __TIME__, ARCHIVE_VERSION_STRING);
#else
    printf("%s (KindleTool) %s built by %s with GCC %s on %s @ %s against %s\n", prog_name, KT_VERSION, KT_USERATHOST, __VERSION__, __DATE__, __TIME__, ARCHIVE_VERSION_STRING);
#endif
    return 0;
}

int kindle_obfuscate_main(int argc, char *argv[])
{
    FILE *input;
    FILE *output;
    input = stdin;
    output = stdout;
    // Skip command
    argv++;
    argc--;
    if(argc > 1)
    {
        if((output = fopen(argv[1], "wb")) == NULL)
        {
            fprintf(stderr, "Cannot open output for writing.\n");
            return -1;
        }
    }
    if(argc > 0)
    {
        if((input = fopen(argv[0], "rb")) == NULL)
        {
            fprintf(stderr, "Cannot open input for reading.\n");
            fclose(output);
            return -1;
        }
    }
    if(munger(input, output, 0, 0) < 0)
    {
        fprintf(stderr, "Cannot obfuscate.\n");
        fclose(input);
        fclose(output);
        return -1;
    }
    fclose(input);
    fclose(output);
    return 0;
}

int kindle_deobfuscate_main(int argc, char *argv[])
{
    FILE *input;
    FILE *output;
    input = stdin;
    output = stdout;
    // Skip command
    argv++;
    argc--;
    if(argc > 1)
    {
        if((output = fopen(argv[1], "wb")) == NULL)
        {
            fprintf(stderr, "Cannot open output for writing.\n");
            return -1;
        }
    }
    if(argc > 0)
    {
        if((input = fopen(argv[0], "rb")) == NULL)
        {
            fprintf(stderr, "Cannot open input for reading.\n");
            fclose(output);
            return -1;
        }
    }
    if(demunger(input, output, 0, 0) < 0)
    {
        fprintf(stderr, "Cannot deobfuscate.\n");
        fclose(input);
        fclose(output);
        return -1;
    }
    fclose(input);
    fclose(output);
    return 0;
}

int kindle_info_main(int argc, char *argv[])
{
    char *serial_no;
    char md5[MD5_HASH_LENGTH];
    FILE *temp;
    unsigned int i;
    // Skip command
    argv++;
    argc--;
    if(argc < 1)
    {
        fprintf(stderr, "No serial number found in input.\n");
        return -1;
    }
    serial_no = argv[0];
    temp = tmpfile();
    if(strlen(serial_no) != SERIAL_NO_LENGTH)
    {
        fprintf(stderr, "Serial number must be 16 digits long (no spaces). Example: %s\n", "B0NNXXXXXXXXXXXX");
        return -1;
    }
    for(i = 0; i < SERIAL_NO_LENGTH; i++)
    {
        if(islower((int)serial_no[i]))
        {
            serial_no[i] = (char)toupper((int)serial_no[i]);
        }
    }
    // Find root password
    if(fprintf(temp, "%s\n", serial_no) < SERIAL_NO_LENGTH)
    {
        fprintf(stderr, "Cannot write serial to temporary file.\n");
        fclose(temp);
        return -1;
    }
    rewind(temp);
    if(md5_sum(temp, md5) < 0)
    {
        fprintf(stderr, "Cannot calculate MD5 of serial number.\n");
        fclose(temp);
        return -1;
    }
    // Default root passwords are DES hashed, so we only care about the first 8 chars. On the other hand,
    // the recovery MMC export option expects a 9 chars password, so, provide both...
    fprintf(stderr, "Root PW        %s%.*s        (or possibly %s%.*s)\n", "fiona", 3, &md5[7], "fiona", 4, &md5[7]);
    fclose(temp);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *prog_name;
    const char *cmd;

    prog_name = argv[0];
    // Discard program name for easier parsing
    argv++;
    argc--;

    if(argc > 0)
    {
        if(strncmp(argv[0], "--", 2) == 0)
        {
            // Allow our commands to be passed in longform
            argv[0] += 2;
        }
    }
    else
    {
        // No command was given, print help and die
        fprintf(stderr, "No command was specified!\n\n");
        kindle_print_help(prog_name);
        exit(1);
    }
    cmd = argv[0];

#if defined(_WIN32) && !defined(__CYGWIN__)
    // Set binary mode properly on MingW, MSVCRT craps out when freopen'ing NULL ;)
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#else
    if(freopen(NULL, "rb", stdin) == NULL)
    {
        fprintf(stderr, "Cannot set stdin to binary mode.\n");
        return -1;
    }
    if(freopen(NULL, "wb", stdout) == NULL)
    {
        fprintf(stderr, "Cannot set stdout to binary mode.\n");
        return -1;
    }
#endif

    if(strncmp(cmd, "md", 2) == 0)
        return kindle_obfuscate_main(argc, argv);
    else if(strncmp(cmd, "dm", 2) == 0)
        return kindle_deobfuscate_main(argc, argv);
    else if(strncmp(cmd, "convert", 7) == 0)
        return kindle_convert_main(argc, argv);
    else if(strncmp(cmd, "extract", 7) == 0)
        return kindle_extract_main(argc, argv);
    else if(strncmp(cmd, "create", 6) == 0)
        return kindle_create_main(argc, argv);
    else if(strncmp(cmd, "info", 4) == 0)
        return kindle_info_main(argc, argv);
    else if(strncmp(cmd, "version", 7) == 0)
        return kindle_print_version(prog_name);
    else if(strncmp(cmd, "help", 4) == 0 || strncmp(cmd, "-help", 5) == 0 || strncmp(cmd, "-h", 2) == 0 || strncmp(cmd, "-?", 2) == 0 || strncmp(cmd, "/?", 2) == 0 || strncmp(cmd, "/h", 2) == 0 || strncmp(cmd, "/help", 2) == 0)
        return kindle_print_help(prog_name);
    else
    {
        fprintf(stderr, "Unknown command '%s'!\n\n", cmd);
        kindle_print_help(prog_name);
        exit(1);
    }

    return 1;
}

// kate: indent-mode cstyle; indent-width 4; replace-tabs on;
