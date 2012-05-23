# KindleTool
## usage:
* KindleTool md [ &lt;**input**&gt; ] [ &lt;**output**&gt; ]

>> Obfuscates data using Amazon's update algorithm.  
>> If no input is provided, input from stdin  
>> If no output is provided, output to stdout  

* KindleTool dm [ &lt;**input**&gt; ] [ &lt;**output**&gt; ]

>> Deobfuscates data using Amazon's update algorithm.  
>> If no input is provided, input from stdin  
>> If no output is provided, output to stdout  

* KindleTool convert [*options*] &lt;**input**&gt;...

>> Converts a Kindle update package to a gzipped TAR file, and delete input  

	Options:
		-c, --stdout                Write to standard output, keeping original files unchanged
		-i, --info                  Just print the package information, no conversion done
		-s, --sig                   OTA V2 updates only. Extract the package signature.
		-k, --keep                  Don't delete the input package.

* KindleTool extract &lt;**input**&gt; &lt;**output**&gt;

>> Extracts a Kindle update package to a directory  

* KindleTool create &lt;**type**&gt; &lt;**devices**&gt; [*options*] &lt;**dir**|**file**&gt;... [ &lt;**output**&gt; ]

>> Creates a Kindle update package  
>> You should be able to throw a mix of files &amp; directories as input without trouble."  
>> If input is a single tarball (".tgz" or ".tar.gz") file, we assume it is properly packaged (bundlefile &amp; sigfile), and will only convert it to an update.  
>> Output should be a file with the extension ".bin", if it is not provided, output to stdout.  
>> In case of OTA updates, all files with the extension ".ffs" or ".sh" will be treated as update scripts.  

	Type:
		ota                         OTA V1 update package. Works on Kindle 3 and older.
		ota2                        OTA V2 signed update package. Works on Kindle 4 and newer.
		recovery                    Recovery package for restoring partitions.

	Devices:
		OTA V1 packages only support one device. OTA V2 packages can support multiple devices.

		-d, --device k1             Kindle 1
		-d, --device k2             Kindle 2 US
		-d, --device k2i            Kindle 2 International
		-d, --device dx             Kindle DX US
		-d, --device dxi            Kindle DX International
		-d, --device dxg            Kindle DX Graphite
		-d, --device k3w            Kindle 3 Wifi
		-d, --device k3g            Kindle 3 Wifi+3G
		-d, --device k3gb           Kindle 3 Wifi+3G Europe
		-d, --device k4             Kindle 4 (No Touch)
		-d, --device k5w            Kindle 5 (Kindle Touch) Wifi
		-d, --device k5g            Kindle 5 (Kindle Touch) Wifi+3G
		-d, --device k5gb           Kindle 5 (Kindle Touch) Wifi+3G Europe (Spain, at least)
		-d, --device k5u            Kindle 5 (Kindle Touch) Unknown (4th device code the 5.1.0 update can run on)

	Options:
		All the following options are optional and advanced.
		-k, --key <file>            PEM file containing RSA private key to sign update. Default is popular jailbreak key.
		-b, --bundle <type>         Manually specify package magic number. Overrides "type". Valid bundle versions:
                                      FB01, FB02 = recovery; FC02, FD03 = ota; FC04, FD04, FL01 = ota2
		-s, --srcrev <ulong|uint>   OTA updates only. Source revision. OTA V1 uses uint, OTA V2 uses ulong.
                                      Lowest version of device that package supports. Default is 0.
		-t, --tgtrev <ulong|uint>   OTA updates only. Target revision. OTA V1 uses uint, OTA V2 uses ulong.
                                      Highest version of device that package supports. Default is ulong/uint max value.
		-1, --magic1 <uint>         Recovery updates only. Magic number 1. Default is 0.
		-2, --magic2 <uint>         Recovery updates only. Magic number 2. Default is 0.
		-m, --minor <uint>          Recovery updates only. Minor number. Default is 0.
		-c, --cert <ushort>         OTA V2 updates only. The number of the certificate to use (found in /etc/uks on device). Default is 0.
                                      0 = pubdevkey01.pem, 1 = pubprodkey01.pem, 2 = pubprodkey02.pem
		-o, --opt <uchar>           OTA V1 updates only. One byte optional data expressed as a number. Default is 0.
		-r, --crit <uchar>          OTA V2 updates only. One byte optional data expressed as a number. Default is 0.
		-x, --meta <str>            OTA V2 updates only. An optional string to add. Multiple "--meta" options supported.
                                      Format of metastring must be: key=value
		-a, --archive               Keep the intermediate archive.
		-u, --unsigned              Build an unsigned package.


* KindleTool info &lt;**serialno**&gt;

>> Get the default root password  

* KindleTool version

>> Show some info about this KindleTool build  

* KindleTool help

>> Show this help screen  

### notices:
1. Kindle 4.0+ has a known bug that prevents some updates with meta-strings to run.
2. Currently, even though OTA V2 supports updates that run on multiple devices, it is not possible to create a update package that will run on both the Kindle 4 (No Touch) and Kindle 5 (Kindle Touch).

### NOTE:
> This fork is probably broken on everything except Linux x86/x86_64/arm, Cygwin x86.  
> Patches/Pull requests to fix that are welcome :).  

// kate: indent-mode cstyle; indent-width 4; replace-tabs on; remove-trailing-space off; replace-trailing-space-save off;
