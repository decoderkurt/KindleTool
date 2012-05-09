//
//  create.c
//  KindleTool
//
//  Copyright (C) 2011-2012  Yifan Lu
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

int sign_file(FILE *in_file, RSA *rsa_pkey, FILE *sigout_file)
{
    /* Taken from: http://stackoverflow.com/a/2054412/91422 */
    EVP_PKEY *pkey;
    EVP_MD_CTX ctx;
    unsigned char buffer[BUFFER_SIZE];
    size_t len;
    unsigned char *sig;
    uint32_t siglen;
    pkey = EVP_PKEY_new();

    if(EVP_PKEY_set1_RSA(pkey, rsa_pkey) == 0)
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        return -2;
    }
    EVP_MD_CTX_init(&ctx);
    if(!EVP_SignInit(&ctx, EVP_sha256()))
    {
        fprintf(stderr, "EVP_SignInit: failed.\n");
        EVP_PKEY_free(pkey);
        return -3;
    }
    while((len = fread(buffer, sizeof(char), BUFFER_SIZE, in_file)) > 0)
    {
        if(!EVP_SignUpdate(&ctx, buffer, len))
        {
            fprintf(stderr, "EVP_SignUpdate: failed.\n");
            EVP_PKEY_free(pkey);
            return -4;
        }
    }
    if(ferror(in_file))
    {
        fprintf(stderr, "Error reading file.\n");
        EVP_PKEY_free(pkey);
        return -5;
    }
    sig = malloc(EVP_PKEY_size(pkey));
    if(!EVP_SignFinal(&ctx, sig, &siglen, pkey))
    {
        fprintf(stderr, "EVP_SignFinal: failed.\n");
        free(sig);
        EVP_PKEY_free(pkey);
        return -6;
    }

    if(fwrite(sig, sizeof(char), siglen, sigout_file) < siglen)
    {
        fprintf(stderr, "Error writing signature file.\n");
        free(sig);
        EVP_PKEY_free(pkey);
        return -7;
    }

    free(sig);
    EVP_PKEY_free(pkey);
    return 0;
}

// As usual, largely based on libarchive's doc, examples, and source ;)
int kindle_create_package_archive(const char *outname, char **filename, const int total_files, RSA *rsa_pkey_file)
{
    struct archive *a;
    struct archive *disk;
    struct archive *disk_sig;
    struct archive_entry *entry;
    struct archive_entry *entry_sig;
    struct stat st;
    struct stat st_sig;
    int r;
    char buff[8192];
    int len;
    int fd;
    int i;
    FILE *file;
    FILE *sigfile;
    char md5[MD5_HASH_LENGTH + 1];
    FILE *bundlefile;
    int dirty_bundlefile;

    // To avoid some more code duplication (and because I suck at C), we're going to add & sign our bundle file with a bit of a hack.
    // We'll build it in our PWD, and we've just appended it to our filelist. It should be the last file walked. We just need to close our open fd at the right time.
    if((bundlefile = fopen(INDEX_FILE_NAME, "w+")) == NULL)
    {
        fprintf(stderr, "Cannot create index file.\n");
        return -1;
    }
    dirty_bundlefile = 1;

    a = archive_write_new();
    archive_write_add_filter_gzip(a);
    archive_write_set_format_gnutar(a);
    archive_write_open_filename(a, outname);

    for(i = 0; i < total_files; i++)
    {
        disk = archive_read_disk_new();

        // Dirty hack ahoy. If we're the last file in our list, that means we're the bundlefile, close our fd
        if(i == total_files - 1)
        {
            fclose(bundlefile);
            dirty_bundlefile = 0;
        }

        r = archive_read_disk_open(disk, filename[i]);
        archive_read_disk_set_standard_lookup(disk);
        if(r != ARCHIVE_OK)
        {
            fprintf(stderr, "archive_read_disk_open() failed: %s\n", archive_error_string(disk));
            goto cleanup;
        }

        for(;;)
        {
            entry = archive_entry_new();
            r = archive_read_next_header2(disk, entry);
            if(r == ARCHIVE_EOF)
                break;
            if(r != ARCHIVE_OK)
            {
                fprintf(stderr, "archive_read_next_header2() failed: %s\n", archive_error_string(disk));
                goto cleanup;
            }
            // Get some basic entry fields from stat (use the entry pathname, we might be in the middle of a directory lookup)
            // We're gonna use it after freeing entry, make a copy
            char *pathname = strdup(archive_entry_pathname(entry));
            // Get our absolute path, or weird things happen with the directory lookup...
            char *resolved_path = NULL;
            char *sourcepath = realpath(pathname, resolved_path);
            archive_entry_copy_sourcepath(entry, sourcepath);

            // Use lstat to handle symlinks, in case libarchive was built without HAVE_LSTAT (idea blatantly stolen from Ark)
            // NOTE: Err, except that we use the resolved path in sourcepath, and that's what we use to read the file we actually put in the archive, so, err... :D
            lstat(pathname, &st);
            r = archive_read_disk_entry_from_file(disk, entry, -1, &st);
            if(r < ARCHIVE_OK)
                fprintf(stderr, "archive_read_disk_entry_from_file() failed: %s\n", archive_error_string(disk));
            if(r == ARCHIVE_FATAL)
                goto cleanup;

            // And then override a bunch of stuff (namely, uig/guid/chmod)
            archive_entry_set_uid(entry, 0);
            archive_entry_set_uname(entry, "root");
            archive_entry_set_gid(entry, 0);
            archive_entry_set_gname(entry, "root");
            // If we have a regular file, and it's a script, make it executable (probably overkill, but hey :))
            if(S_ISREG(st.st_mode) && (IS_SCRIPT(pathname) || IS_SHELL(pathname)))
                archive_entry_set_perm(entry, 0755);
            else
                archive_entry_set_perm(entry, 0644);

            // NOTE: I actually don't know if the directory lookup is live (probably not), but let's avoid signing/adding sig files multiple times anyway
            if(IS_SIG(pathname))
            {
                printf("Skipping sig file '%s' to avoid duplicates\n", pathname);
                archive_entry_free(entry);
                continue;
            }

            archive_read_disk_descend(disk);
            r = archive_write_header(a, entry);
            if(r < ARCHIVE_OK)
                fprintf(stderr, "archive_write_header() failed: %s\n", archive_error_string(a));
            if(r == ARCHIVE_FATAL)
                goto cleanup;
            if(r > ARCHIVE_FAILED)
            {
                fd = open(archive_entry_sourcepath(entry), O_RDONLY);
                len = read(fd, buff, sizeof(buff));
                while(len > 0)
                {
                    archive_write_data(a, buff, len);
                    len = read(fd, buff, sizeof(buff));
                }
                close(fd);
            }
            archive_entry_free(entry);

            // If we just added a regular file, hash it, sign it, add it to the index, and put the sig in our tarball
            if(S_ISREG(st.st_mode))
            {
                if((file = fopen(pathname, "rb")) == NULL)
                {
                    fprintf(stderr, "Cannot open '%s' for reading!\n", pathname);
                    goto cleanup;
                }
                // Don't hash our bundlefile
                if(i != total_files - 1)
                {
                    if(md5_sum(file, md5) != 0)
                    {
                        fprintf(stderr, "Cannot calculate hash sum for '%s'\n", pathname);
                        fclose(file);
                        goto cleanup;
                    }
                    md5[MD5_HASH_LENGTH] = 0;
                    rewind(file);
                }

                char signame[PATH_MAX + 1];
                snprintf(signame, PATH_MAX, "%s.sig", pathname);
                if((sigfile = fopen(signame, "wb")) == NULL)
                {
                    fprintf(stderr, "Cannot create signature file '%s'\n", signame);
                    goto cleanup;
                }
                if(sign_file(file, rsa_pkey_file, sigfile) < 0)
                {
                    fprintf(stderr, "Cannot sign '%s'\n", pathname);
                    fclose(file);
                    fclose(sigfile);
                    remove(signame);   // Delete empty/broken sigfile
                    goto cleanup;
                }

                // Don't add the bundlefile to itself
                if(i != total_files - 1)
                {
                    if(fprintf(bundlefile, "%d %s %s %lld %s\n", ((IS_SCRIPT(pathname) || IS_SHELL(pathname)) ? 129 : 128), md5, pathname, (long long) st.st_size / BLOCK_SIZE, sourcepath) < 0) // FIXME: The python script does pathname+"_file" for the last field.
                    {
                        fprintf(stderr, "Cannot write to index file.\n");
                        // Cleanup a bit before crapping out
                        fclose(file);
                        fclose(sigfile);
                        remove(signame);
                        goto cleanup;
                    }
                }

                // Cleanup
                fclose(file);
                fclose(sigfile);

                // And now, for the fun part! Ninja our sigfile into the archive... Ugly code duplication ahead!
                disk_sig = archive_read_disk_new();

                r = archive_read_disk_open(disk_sig, signame);
                archive_read_disk_set_standard_lookup(disk_sig);
                if(r != ARCHIVE_OK)
                {
                    fprintf(stderr, "archive_read_disk_open() failed: %s\n", archive_error_string(disk_sig));
                    remove(signame);
                    goto cleanup;
                }

                for(;;)
                {
                    // First, inject a new entry, based on our sigfile :)
                    entry_sig = archive_entry_new();
                    r = archive_read_next_header2(disk_sig, entry_sig);
                    if(r == ARCHIVE_EOF)
                        break;
                    if(r != ARCHIVE_OK)
                    {
                        fprintf(stderr, "archive_read_next_header2() failed: %s\n", archive_error_string(disk_sig));
                        remove(signame);
                        goto cleanup;
                    }
                    // Get some basic entry fields from stat
                    char *pathname_sig = strdup(archive_entry_pathname(entry_sig));
                    char *resolved_path_sig = NULL;
                    char *sourcepath_sig = realpath(pathname_sig, resolved_path_sig);
                    archive_entry_copy_sourcepath(entry_sig, sourcepath_sig);

                    lstat(pathname_sig, &st_sig);
                    r = archive_read_disk_entry_from_file(disk_sig, entry_sig, -1, &st_sig);
                    if(r < ARCHIVE_OK)
                        fprintf(stderr, "archive_read_disk_entry_from_file() failed: %s\n", archive_error_string(disk_sig));
                    if(r == ARCHIVE_FATAL)
                    {
                        remove(signame);
                        goto cleanup;
                    }

                    archive_entry_set_uid(entry_sig, 0);
                    archive_entry_set_uname(entry_sig, "root");
                    archive_entry_set_gid(entry_sig, 0);
                    archive_entry_set_gname(entry_sig, "root");
                    archive_entry_set_perm(entry_sig, 0644);

                    // And then, write it to the archive...
                    archive_read_disk_descend(disk_sig);
                    r = archive_write_header(a, entry_sig);
                    if(r < ARCHIVE_OK)
                        fprintf(stderr, "archive_write_header() failed: %s\n", archive_error_string(a));
                    if(r == ARCHIVE_FATAL)
                    {
                        remove(signame);
                        goto cleanup;
                    }
                    if(r > ARCHIVE_FAILED)
                    {
                        fd = open(archive_entry_sourcepath(entry_sig), O_RDONLY);
                        len = read(fd, buff, sizeof(buff));
                        while(len > 0)
                        {
                            archive_write_data(a, buff, len);
                            len = read(fd, buff, sizeof(buff));
                        }
                        close(fd);
                    }
                    archive_entry_free(entry_sig);
                    // Delete the sigfile once we're done
                    remove(sourcepath_sig);
                    // Cleanup
                    free(pathname_sig);
                    free(resolved_path_sig);
                    free(sourcepath_sig);
                }
            }

            // Delete the bundle file once we're done
            if(i == total_files - 1)
            {
                remove(sourcepath);
            }

            // Cleanup
            free(pathname);
            free(resolved_path);
            free(sourcepath);
        }
        archive_read_close(disk);
        archive_read_free(disk);
    }

    archive_write_close(a);
    archive_write_free(a);

    return 0;

cleanup:
    // Close & remove the bundlefile if we crapped out in the middle of processing
    if(dirty_bundlefile)
        fclose(bundlefile);
    remove(INDEX_FILE_NAME);
    // FIXME: We're probably leaking stuff, too...
    return 1;
}

int kindle_create(UpdateInformation *info, FILE *input_tgz, FILE *output, const int fake_sign)
{
    char buffer[BUFFER_SIZE];
    size_t count;
    FILE *temp;

    switch(info->version)
    {
        case OTAUpdateV2:
            if((temp = tmpfile()) == NULL)
            {
                fprintf(stderr, "Error opening temp file.\n");
                return -1;
            }
            if(kindle_create_ota_update_v2(info, input_tgz, temp, fake_sign) < 0) // create the update
            {
                fprintf(stderr, "Error creating update package.\n");
                fclose(temp);
                return -1;
            }
            rewind(temp); // rewind the file before reading back
            if (!fake_sign)
            {
                if(kindle_create_signature(info, temp, output) < 0) // write the signature (unless we asked for an unsigned package)
                {
                    fprintf(stderr, "Error signing update package.\n");
                    fclose(temp);
                    return -1;
                }
                rewind(temp); // rewind the file before writing it to output
            }
            // write the update
            while((count = fread(buffer, sizeof(char), BUFFER_SIZE, temp)) > 0)
            {
                if(fwrite(buffer, sizeof(char), count, output) < count)
                {
                    fprintf(stderr, "Error writing update to output.\n");
                    fclose(temp);
                    return -1;
                }
            }
            if(ferror(temp) != 0)
            {
                fprintf(stderr, "Error reading generated update.\n");
                fclose(temp);
                return -1;
            }
            fclose(temp);
            return 0;
            break;
        case OTAUpdate:
            return kindle_create_ota_update(info, input_tgz, output, fake_sign);
            break;
        case RecoveryUpdate:
            return kindle_create_recovery(info, input_tgz, output, fake_sign);
            break;
        case UnknownUpdate:
        default:
            fprintf(stderr, "Unknown update type.\n");
            break;
    }
    return -1;
}

int kindle_create_ota_update_v2(UpdateInformation *info, FILE *input_tgz, FILE *output, const int fake_sign)
{
    unsigned int header_size;
    unsigned char *header;
    int hindex;
    int i;
    size_t str_len;

    // first part of the set sized data
    header_size = MAGIC_NUMBER_LENGTH + OTA_UPDATE_V2_BLOCK_SIZE;
    header = malloc(header_size);
    hindex = 0;
    strncpy((char *)header, info->magic_number, MAGIC_NUMBER_LENGTH);
    hindex += MAGIC_NUMBER_LENGTH;
    memcpy(&header[hindex], &info->source_revision, sizeof(uint64_t)); // source
    hindex += sizeof(uint64_t);
    memcpy(&header[hindex], &info->target_revision, sizeof(uint64_t)); // target
    hindex += sizeof(uint64_t);
    memcpy(&header[hindex], &info->num_devices, sizeof(uint16_t)); // device count
    hindex += sizeof(uint16_t);

    // next, we write the devices
    header_size += info->num_devices * sizeof(uint16_t);
    header = realloc(header, header_size);
    for(i = 0; i < info->num_devices; i++)
    {
        memcpy(&header[hindex], &info->devices[i], sizeof(uint16_t)); // device
        hindex += sizeof(uint16_t);
    }

    // part two of the set sized data
    header_size += OTA_UPDATE_V2_PART_2_BLOCK_SIZE;
    header = realloc(header, header_size);
    memcpy(&header[hindex], &info->critical, sizeof(uint8_t)); // critical
    hindex += sizeof(uint8_t);
    memset(&header[hindex], 0, sizeof(uint8_t)); // 1 byte padding
    hindex += sizeof(uint8_t);

    // If we asked for a fake package, the Kindle expects to see the MD5 sum of the obfuscated archive, but a clear archive...
    // If you're confused with the whole md/munger/dm/demunger, the line starts right there! :D
    // Sum a temp obfuscated tarball to fake it ;)
    if (fake_sign)
    {
        FILE *obfuscated_tgz;
        if((obfuscated_tgz = tmpfile()) == NULL)
        {
            fprintf(stderr, "Error opening temp file.\n");
            return -1;
        }
        demunger(input_tgz, obfuscated_tgz, 0);
        rewind(input_tgz);
        rewind(obfuscated_tgz);
        if(md5_sum(obfuscated_tgz, (char *)&header[hindex]) < 0)
        {
            fprintf(stderr, "Error calculating MD5 of package.\n");
            free(header);
            return -1;
        }
        fclose(obfuscated_tgz);
    }
    else
    {
        if(md5_sum(input_tgz, (char *)&header[hindex]) < 0) // md5 hash
        {
            fprintf(stderr, "Error calculating MD5 of package.\n");
            free(header);
            return -1;
        }
        rewind(input_tgz); // reset input for later reading
    }

    md(&header[hindex], MD5_HASH_LENGTH); // obfuscate md5 hash
    hindex += MD5_HASH_LENGTH;
    memcpy(&header[hindex], &info->num_meta, sizeof(uint16_t)); // num meta, cannot be casted
    hindex += sizeof(uint16_t);

    // next, we write the meta strings
    for(i = 0; i < info->num_meta; i++)
    {
        str_len = strlen(info->metastrings[i]);
        header_size += str_len + sizeof(uint16_t);
        header = realloc(header, header_size);
        // string length: little endian -> big endian
        memcpy(&header[hindex], &((uint8_t *)&str_len)[1], sizeof(uint8_t));
        hindex += sizeof(uint8_t);
        memcpy(&header[hindex], &((uint8_t *)&str_len)[0], sizeof(uint8_t));
        hindex += sizeof(uint8_t);
        strncpy((char *)&header[hindex], info->metastrings[i], str_len);
        hindex += str_len;
    }

    // now, we write the header to the file
    if(fwrite(header, sizeof(char), header_size, output) < header_size)
    {
        fprintf(stderr, "Error writing update header.\n");
        free(header);
        return -1;
    }

    // write the actual update
    free(header);
    return munger(input_tgz, output, 0, fake_sign);
}

int kindle_create_signature(UpdateInformation *info, FILE *input_bin, FILE *output)
{
    UpdateHeader header; // header to write

    memset(&header, 0, sizeof(UpdateHeader)); // set them to zero
    strncpy(header.magic_number, "SP01", 4); // write magic number
    header.data.signature.certificate_number = (uint32_t)info->certificate_number; // 4 byte certificate number
    if(fwrite(&header, sizeof(char), MAGIC_NUMBER_LENGTH + UPDATE_SIGNATURE_BLOCK_SIZE, output) < MAGIC_NUMBER_LENGTH + UPDATE_SIGNATURE_BLOCK_SIZE)
    {
        fprintf(stderr, "Error writing update header.\n");
        return -1;
    }
    // write signature to output
    if(sign_file(input_bin, info->sign_pkey, output) < 0)
    {
        fprintf(stderr, "Error signing update package.\n");
        return -1;
    }
    return 0;
}

int kindle_create_ota_update(UpdateInformation *info, FILE *input_tgz, FILE *output, const int fake_sign)
{
    UpdateHeader header;

    memset(&header, 0, sizeof(UpdateHeader)); // set them to zero
    strncpy(header.magic_number, info->magic_number, 4); // magic number
    header.data.ota_update.source_revision = (uint32_t)info->source_revision; // source
    header.data.ota_update.target_revision = (uint32_t)info->target_revision; // target
    header.data.ota_update.device = (uint16_t)info->devices[0]; // device
    header.data.ota_update.optional = (unsigned char)info->optional; // optional

    if (fake_sign)
    {
        FILE *obfuscated_tgz;
        if((obfuscated_tgz = tmpfile()) == NULL)
        {
            fprintf(stderr, "Error opening temp file.\n");
            return -1;
        }
        demunger(input_tgz, obfuscated_tgz, 0);
        rewind(input_tgz);
        rewind(obfuscated_tgz);
        if(md5_sum(obfuscated_tgz, header.data.ota_update.md5_sum) < 0)
        {
            fprintf(stderr, "Error calculating MD5 of package.\n");
            return -1;
        }
        fclose(obfuscated_tgz);
    }
    else
    {
        if(md5_sum(input_tgz, header.data.ota_update.md5_sum) < 0)
        {
            fprintf(stderr, "Error calculating MD5 of input tgz.\n");
            return -1;
        }
        rewind(input_tgz); // rewind input
    }
    md((unsigned char *)header.data.ota_update.md5_sum, MD5_HASH_LENGTH); // obfuscate md5 hash

    // write header to output
    if(fwrite(&header, sizeof(char), MAGIC_NUMBER_LENGTH + OTA_UPDATE_BLOCK_SIZE, output) < MAGIC_NUMBER_LENGTH + OTA_UPDATE_BLOCK_SIZE)
    {
        fprintf(stderr, "Error writing update header.\n");
        return -1;
    }

    // write package to output
    return munger(input_tgz, output, 0, fake_sign);
}

int kindle_create_recovery(UpdateInformation *info, FILE *input_tgz, FILE *output, const int fake_sign)
{
    UpdateHeader header;

    memset(&header, 0, sizeof(UpdateHeader)); // set them to zero
    strncpy(header.magic_number, info->magic_number, 4); // magic number
    header.data.recovery_update.magic_1 = (uint32_t)info->magic_1; // magic 1
    header.data.recovery_update.magic_2 = (uint32_t)info->magic_2; // magic 2
    header.data.recovery_update.minor = (uint32_t)info->minor; // minor
    header.data.recovery_update.device = (uint32_t)info->devices[0]; // device

    if (fake_sign)
    {
        FILE *obfuscated_tgz;
        if((obfuscated_tgz = tmpfile()) == NULL)
        {
            fprintf(stderr, "Error opening temp file.\n");
            return -1;
        }
        demunger(input_tgz, obfuscated_tgz, 0);
        rewind(input_tgz);
        rewind(obfuscated_tgz);
        if(md5_sum(obfuscated_tgz, header.data.recovery_update.md5_sum) < 0)
        {
            fprintf(stderr, "Error calculating MD5 of package.\n");
            return -1;
        }
        fclose(obfuscated_tgz);
    }
    else
    {
        if(md5_sum(input_tgz, header.data.recovery_update.md5_sum) < 0)
        {
            fprintf(stderr, "Error calculating MD5 of input tgz.\n");
            return -1;
        }
        rewind(input_tgz); // rewind input
    }
    md((unsigned char *)header.data.recovery_update.md5_sum, MD5_HASH_LENGTH); // obfuscate md5 hash

    // write header to output
    if(fwrite(&header, sizeof(char), MAGIC_NUMBER_LENGTH + RECOVERY_UPDATE_BLOCK_SIZE, output) < MAGIC_NUMBER_LENGTH + RECOVERY_UPDATE_BLOCK_SIZE)
    {
        fprintf(stderr, "Error writing update header.\n");
        return -1;
    }

    // write package to output
    return munger(input_tgz, output, 0, fake_sign);
}

int kindle_create_main(int argc, char *argv[])
{
    int opt;
    int opt_index;
    static const struct option opts[] =
    {
        { "device", required_argument, NULL, 'd' },
        { "key", required_argument, NULL, 'k' },
        { "bundle", required_argument, NULL, 'b' },
        { "srcrev", required_argument, NULL, 's' },
        { "tgtrev", required_argument, NULL, 't' },
        { "magic1", required_argument, NULL, '1' },
        { "magic2", required_argument, NULL, '2' },
        { "minor", required_argument, NULL, 'm' },
        { "cert", required_argument, NULL, 'c' },
        { "opt", required_argument, NULL, 'o' },
        { "crit", required_argument, NULL, 'r' },
        { "meta", required_argument, NULL, 'x' },
        { "archive", no_argument, NULL, 'a' },
        { "unsigned", no_argument, NULL, 'u' }
    };
    UpdateInformation info = {"\0\0\0\0", UnknownUpdate, get_default_key(), 0, UINT32_MAX, 0, 0, 0, 0, NULL, CertificateDeveloper, 0, 0, 0, NULL };
    FILE *input;
    FILE *output;
    BIO *bio;
    int i;
    int optcount;
    char *output_filename;
    char *raw_filelist;
    char **input_list;
    int input_index;
    int input_total;
    int keep_archive;
    int skip_archive;
    int fake_sign;

    // defaults
    output = stdout;
    input = NULL;
    output_filename = NULL;
    optcount = 0;
    input_index = 0;
    input_total = 0;
    keep_archive = 0;
    skip_archive = 0;
    fake_sign = 0;

    // Skip command
    argv++;
    argc--;

    // update type
    if(argc < 1)
    {
        fprintf(stderr, "Not enough arguments.\n");
        return -1;
    }
    if(strncmp(argv[0], "ota2", 4) == 0)
    {
        info.version = OTAUpdateV2;
    }
    else if(strncmp(argv[0], "ota", 3) == 0)
    {
        info.version = OTAUpdate;
        strncpy(info.magic_number, "FC02", 4);
    }
    else if(strncmp(argv[0], "recovery", 8) == 0)
    {
        info.version = RecoveryUpdate;
        strncpy(info.magic_number, "FB02", 4);
    }
    else
    {
        fprintf(stderr, "Invalid update type.\n");
        return -1;
    }

    // arguments
    while((opt = getopt_long(argc, argv, "d:k:b:s:t:1:2:m:c:o:r:x:au", opts, &opt_index)) != -1)
    {
        switch(opt)
        {
            case 'd':
                info.devices = realloc(info.devices, ++info.num_devices * sizeof(Device));
                if(strcmp(optarg, "k1") == 0)
                    info.devices[info.num_devices - 1] = Kindle1;
                else if(strcmp(optarg, "k2") == 0)
                    info.devices[info.num_devices - 1] = Kindle2US;
                else if(strcmp(optarg, "k2i") == 0)
                    info.devices[info.num_devices - 1] = Kindle2International;
                else if(strcmp(optarg, "dx") == 0)
                    info.devices[info.num_devices - 1] = KindleDXUS;
                else if(strcmp(optarg, "dxi") == 0)
                    info.devices[info.num_devices - 1] = KindleDXInternational;
                else if(strcmp(optarg, "dxg") == 0)
                    info.devices[info.num_devices - 1] = KindleDXGraphite;
                else if(strcmp(optarg, "k3w") == 0)
                    info.devices[info.num_devices - 1] = Kindle3Wifi;
                else if(strcmp(optarg, "k3g") == 0)
                    info.devices[info.num_devices - 1] = Kindle3Wifi3G;
                else if(strcmp(optarg, "k3gb") == 0)
                    info.devices[info.num_devices - 1] = Kindle3Wifi3GEurope;
                else if(strcmp(optarg, "k4") == 0)
                {
                    info.devices[info.num_devices - 1] = Kindle4NonTouch;
                    strncpy(info.magic_number, "FC04", 4);
                }
                else if(strcmp(optarg, "k5w") == 0)
                {
                    info.devices[info.num_devices - 1] = Kindle5TouchWifi;
                    strncpy(info.magic_number, "FD04", 4);
                }
                else if(strcmp(optarg, "k5g") == 0)
                {
                    info.devices[info.num_devices - 1] = Kindle5TouchWifi3G;
                    strncpy(info.magic_number, "FD04", 4);
                }
                else if(strcmp(optarg, "k5gb") == 0)
                {
                    info.devices[info.num_devices - 1] = Kindle5TouchWifi3GEurope;
                    strncpy(info.magic_number, "FD04", 4);
                }
                else if(strcmp(optarg, "k5u") == 0)
                {
                    info.devices[info.num_devices - 1] = Kindle5TouchUnknown;
                    strncpy(info.magic_number, "FD04", 4);
                }
                else
                {
                    fprintf(stderr, "Unknown device %s.\n", optarg);
                    goto do_error;
                }
                break;
            case 'k':
                if((bio = BIO_new_file(optarg, "rb")) == NULL || PEM_read_bio_RSAPrivateKey(bio, &info.sign_pkey, NULL, NULL) == NULL)
                {
                    fprintf(stderr, "Key %s cannot be loaded.\n", optarg);
                    goto do_error;
                }
                break;
            case 'b':
                strncpy(info.magic_number, optarg, 4);
                if((info.version = get_bundle_version(optarg)) == UnknownUpdate)
                {
                    fprintf(stderr, "Invalid bundle version %s.\n", optarg);
                    goto do_error;
                }
                break;
            case 's':
                info.source_revision = strtoul(optarg, NULL, 0);
                break;
            case 't':
                info.target_revision = strtoul(optarg, NULL, 0);
                break;
            case '1':
                info.magic_1 = atoi(optarg);
                break;
            case '2':
                info.magic_2 = atoi(optarg);
                break;
            case 'm':
                info.minor = atoi(optarg);
                break;
            case 'c':
                info.certificate_number = (CertificateNumber)atoi(optarg);
                break;
            case 'o':
                info.optional = (uint16_t)atoi(optarg);
                break;
            case 'r':
                info.critical = (uint16_t)atoi(optarg);
                break;
            case 'x':
                if(strchr(optarg, '=') == NULL) // metastring must contain =
                {
                    fprintf(stderr, "Invalid metastring. Format: key=value, input: %s\n", optarg);
                    goto do_error;
                }
                if(strlen(optarg) > 0xFFFF)
                {
                    fprintf(stderr, "Metastring too long. Max length: %d, input: %s\n", 0xFFFF, optarg);
                    goto do_error;
                }
                info.metastrings = realloc(info.metastrings, ++info.num_meta * sizeof(char *));
                info.metastrings[info.num_meta - 1] = strdup(optarg);
                break;
            case 'a':
                keep_archive = 1;
                break;
            case 'u':
                fake_sign = 1;
                break;
            default:
                fprintf(stderr, "Unknown option code 0%o\n", opt);
                break;
        }
    }
    // validation
    if(info.num_devices < 1 || (info.version != OTAUpdateV2 && info.num_devices > 1))
    {
        fprintf(stderr, "Invalid number of supported devices, %d, for this update type.\n", info.num_devices);
        goto do_error;
    }
    if(info.version != OTAUpdateV2 && (info.source_revision > UINT32_MAX || info.target_revision > UINT32_MAX))
    {
        fprintf(stderr, "Source/target revision for this update type cannot exceed %u\n", UINT32_MAX);
        goto do_error;
    }
    // Not sure why we end up with -1 instead of UINT32_MAX, but we do, so, err, clamp to INT32_MAX instead when building an ota update, like the python tool did.
    // Since the default is hardcoded, fix it silently.
    if(info.version != OTAUpdateV2 && info.target_revision > INT32_MAX)
        info.target_revision = INT32_MAX;
    // FIXME? Untested, but I assume the same holds true for source_revision, so handle it too.
    if(info.version != OTAUpdateV2 && info.source_revision > INT32_MAX)
    {
        fprintf(stderr, "Source revision for this update type cannot exceed %d\n", INT32_MAX);
        goto do_error;
    }
    // When building an ota update with ota2 only devices, don't try to use non ota v1 bundle versions, reset it @ FC02, or shit happens.
    if(info.version == OTAUpdate)
    {
        // OTA V1 only supports one device, we don't need to loop (fix anything newer than a K3GB)
        if(info.devices[0] > Kindle3Wifi3GEurope && (strncmp(info.magic_number, "FC02", 4) != 0 && strncmp(info.magic_number, "FD03", 4) != 0))
        {
            // FC04 is hardcoded when we set K4 as a device, and FD04 when we ask for a K5, so fix it silently.
            strncpy(info.magic_number, "FC02", 4);
        }
    }

    if(optind < argc)
    {
        // Save 'real' options count
        optcount = optind;
        // Alloc our input filelist, based on the number of non-options, minus the output
        // Heavily *cough* 'inspired' *cough* from http://stackoverflow.com/questions/5935933/
        // Keep an extra space for the bundlefile
        input_total = argc - optcount;
        // If we only have one input file, fake it, or things go kablooey with stdout output
        if(input_total == 1)
            input_total++;
        raw_filelist = malloc(input_total * (PATH_MAX + 1));
        input_list = malloc(sizeof(*input_list) * input_total);
        // Iterate over non-options (the file(s) we passed)
        while(optind < argc)
        {
            // The last one will always be our output (but only check if we have at least one input file, we might really want to output to stdout)
            if(optind == argc - 1 && input_index > 0)
            {
                output_filename = argv[optind++];
                if((output = fopen(output_filename, "wb")) == NULL)
                {
                    fprintf(stderr, "Cannot create output '%s'.\n", output_filename);
                    goto do_error;
                }
            }
            else
            {
                // Build a list of all our input files/dir, libarchive will do most of the heavy lifting for us
                const char *tmp_buf = argv[optind++];
                input_list[input_index] = &raw_filelist[input_index * (PATH_MAX + 1)];
                strcpy(input_list[input_index], tmp_buf);

                input_index++;
            }
        }
    }
    else
    {
        fprintf(stderr, "No input/output specified.\n");
        return -1;
    }
    if(input_total < 1)
    {
        fprintf(stderr, "You need to specify at least ONE input item in conjunction with the output file.\n");
        return -1;
    }
    // Add our bundle index to the end of the list, see kindle_create_package_archive() for more details. (Granted, it's a bit hackish).
    input_list[input_index] = &raw_filelist[input_index * (PATH_MAX + 1)];
    strcpy(input_list[input_index], INDEX_FILE_NAME);
    input_index++;

    // Build the package archive name based on the output name.
    char tarball_filename[PATH_MAX + 1];
    // While we're at it, check that our output name properly ends in .bin
    if(output_filename != NULL && IS_BIN(output_filename))
    {
        // It does, switch from .bin to .tar.gz, using a tmp copy, because we're still gonna need out proper output name later
        size_t len = strlen(output_filename);
        char *tmp_outname = malloc(len - 3);
        memcpy(tmp_outname, output_filename, len - 4);
        tmp_outname[len - 4] = 0;       // . => \0

        snprintf(tarball_filename, PATH_MAX, "%s.tar.gz", tmp_outname);
        free(tmp_outname);
    }
    else
    {
        // We're outputting to stdout, assign a generic name to the archive
        snprintf(tarball_filename, PATH_MAX, "update_kindletool_%d_archive.tar.gz", getpid());
        output_filename = strdup("standard output");
    }

    // If we only provided a single input file, and it's a tarball, assume it's properly packaged, and just sign/munge it. (Restore backwards compatibilty with ixtab's tools, among other things)
    if(input_total <= 2)
    {
        // Yes, 2, because we'll aways at least have the bundlefile in there, and we bump input_total when outputting to stdout...
        if(IS_TGZ(input_list[0]) || IS_TARBALL(input_list[0]))
        {
            // NOTE: There's no real check beside the file extension...
            skip_archive = 1;
            // Use it as our tarball...
            snprintf(tarball_filename, PATH_MAX, "%s", input_list[0]);
        }
    }

    // Recap (to stderr, in order not to mess stuff up if we output to stdout) what we're building
    fprintf(stderr, "Building %s%s (%s) update to %s %s %s for %hd device%s (", (fake_sign > 0 ? "fake " : ""), (convert_bundle_version(info.version)), info.magic_number, output_filename, (skip_archive > 0 ? "directly from" : "via"), tarball_filename, info.num_devices, (info.num_devices > 1 ? "s" : ""));
    // Loop over devices
    for(i = 0; i < info.num_devices; i++)
    {
        fprintf(stderr, "%s", convert_device_id(info.devices[i]));
        if(i != info.num_devices - 1)
            fprintf(stderr, ", ");
    }
    fprintf(stderr, ") Min. OTA: %llu, Target OTA: %llu, Critical: %hd, Optional: %d, Magic 1: %d, Magic 2: %d, %hd Metadata%s", (long long) info.source_revision, (long long) info.target_revision, info.critical, info.optional, info.magic_1, info.magic_2, info.num_meta, (info.num_meta > 0 ? " (" : "\n"));
    // Loop over meta
    for(i = 0; i < info.num_meta; i++)
    {
        fprintf(stderr, "%s", info.metastrings[i]);
        if(i != info.num_meta - 1)
            fprintf(stderr, "; ");
        else
            fprintf(stderr, ")\n");
    }

    // Create our package archive, sigfile & bundlefile included
    if(!skip_archive)
    {
        if(kindle_create_package_archive(tarball_filename, input_list, input_total, info.sign_pkey) != 0)
        {
            fprintf(stderr, "Failed to create intermediate archive '%s'.\n", tarball_filename);
            // Delete the borked file
            remove(tarball_filename);
            goto do_error;
        }
    }

    // And finally, build our package :).
    if((input = fopen(tarball_filename, "rb")) == NULL)
    {
        fprintf(stderr, "Cannot read input tarball '%s'.\n", tarball_filename);
        goto do_error;
    }
    // Don't try to create a file if we're outputting to stdout
    if(output != stdout)
    {
        if((output = fopen(output_filename, "wb")) == NULL)
        {
            fprintf(stderr, "Cannot create output package '%s'.\n", output_filename);
            goto do_error;
        }
    }
    if(kindle_create(&info, input, output, fake_sign) < 0)
    {
        fprintf(stderr, "Cannot write update to output.\n");
        goto do_error;
    }

    // Clean-up
    free(input_list);
    free(raw_filelist);
    free(info.devices);
    for(i = 0; i < info.num_meta; i++)
        free(info.metastrings[i]);
    free(info.metastrings);
    fclose(input);
    if(output != stdout)
        fclose(output);
    // Remove tarball, unless we asked to keep it
    if(!keep_archive)
        remove(tarball_filename);

    return 0;

do_error:
    if(input_total > 0)
    {
        free(input_list);
        free(raw_filelist);
    }
    free(info.devices);
    for(i = 0; i < info.num_meta; i++)
        free(info.metastrings[i]);
    free(info.metastrings);
    if(input != NULL)
        fclose(input);
    if(output != NULL && output != stdout)
        fclose(output);
    return -1;
}

// kate: indent-mode cstyle; indent-width 4; replace-tabs on;
