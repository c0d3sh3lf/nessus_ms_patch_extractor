#!/usr/bin/python

__author__ = "Sumit Shrivastava (@invad3rsam)"
__version__ = "v1.0.0"

import re, optparse, sys


def read_csv(filename):
    csv_file = open(filename, "r")
    csv_file_data = csv_file.readlines()
    csv_file.close()
    return csv_file_data


def create_patch_dict(patches):
    ms_patch_re = re.compile(r"\"MS.*?")
    ms_unsupported_re = re.compile(r"\"Microsoft.*?Unsupported.*?\"")
    nessus_plugin_re = re.compile(r"\"\d{5}\"")
    patch_list = {}
    for index in range(1, len(patches)):
        cursor = patches[index]
        if nessus_plugin_re.match(cursor):
            ip_address = cursor.split(",")[4]
            if len(patch_list) == 0:
                patch_list[ip_address] = []
            else:
                if ip_address not in patch_list.keys():
                    patch_list[ip_address] = []
                else:
                    pass
            patch_name = cursor.split(",")[7]
            if ms_patch_re.match(patch_name) or ms_unsupported_re.match(patch_name):
                ip_patches = patch_list[ip_address]
                ip_patches.append(patch_name)
    return patch_list


def write_to_file(patch_dict, outputfilename):
    outputfile = open(outputfilename, "w")
    for key in patch_dict.keys():
        patches = patch_dict[key]
        if len(patches) > 0:
            outputfile.write(str(key.strip("\""))+"\n\r")
            for patch in patches:
                outputfile.write(str(patch.strip("\"")) + "\n\r")
            outputfile.write("\n")
    outputfile.close()
    print "[+] Output written to",outputfilename, "successfully"

def create_csv(patch_dict, outputfilename):
    csv_re = re.compile(r".*?\.csv$")
    if csv_re.match(outputfilename):
        pass
    else:
        outputfilename += ".csv"
    outputfile = open(outputfilename, "w")
    outputfile.write("\"IP Address\",\"Missing Patch(s)\"\n\r")
    for key in patch_dict.keys():
        patches = patch_dict[key]
        if len(patches) > 0:
            for patch in patches:
                outputfile.write(str(key) + "," + str(patch) + "\n\r")
    outputfile.close()
    print "[+] Output written to", outputfilename, "successfully"

def main():
    print "Author: Sumit Shrivastava (@invad3rsam)"
    print "Version: 1.0.0"
    print "Published on: 25-June-2016"
    parser = optparse.OptionParser()
    parser.add_option("-c", "--csv", dest="csv_file", help="Nessus CSV file")
    parser.add_option("-o", "--output-file", dest="output_file", help="Output File")
    parser.add_option("-f", "--format", dest="output_format", help="Format of output file (text, csv). Default format is text.")
    (options, args) = parser.parse_args()
    if not options.csv_file:
        if not options.output_file:
            print "[-] Missing input and output files"
            print parser.print_help()
            sys.exit(1)
        else:
            print "[-] Missing input file"
            print parser.print_help()
            sys.exit(1)
    else:
        if not options.output_file:
            print "[-] Missing output file"
            print parser.print_help()
            sys.exit(1)
        else:
            if not options.output_format:
                options.output_format = "text"
            if options.output_format == "text":
                write_to_file(create_patch_dict(read_csv(options.csv_file)), options.output_file)
            elif options.output_format == "csv":
                create_csv(create_patch_dict(read_csv(options.csv_file)), options.output_file)
            else:
                print "[-] Invalid Output Format"
                print parser.print_help()
                sys.exit(1)


if __name__ == "__main__":
    main()