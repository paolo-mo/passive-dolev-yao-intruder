'''
 Copyright 2024-2026 Paolo Modesti
 Copyright 2024-2026 SCM/SCDT/SCEDT, Teesside University
 
 AnBx is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 any later version.

 AnBx is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with AnBx. If not, see <http://www.gnu.org/licenses/>.

'''

import os
import sys
import subprocess
import argparse
import fnmatch
import configparser

JAVA_MAGIC_NUMBER = "aced0005"
CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "jpcap2ser.cfg"
)

# This program requires the following tools
# TShark: https://www.wireshark.org/ https://tshark.dev/
# SerializationDumper: https://github.com/NickstaDB/SerializationDumper

def load_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config

def is_java_magic_number_present(file_path):
    with open(file_path, 'r') as f:
        first_bytes = f.read(len(JAVA_MAGIC_NUMBER))
        return first_bytes == JAVA_MAGIC_NUMBER

def run_tshark(input_file, output_file, config):
    tshark_cmd = config['DEFAULT']['TSHARK_CMD']
    if not os.path.exists(tshark_cmd):
        print("TShark is required but was not found in this location: " + tshark_cmd)
        sys.exit(1)
    
    tshark_command = [
        tshark_cmd,
        "-r", input_file,
        "-Y", "tcp.payload",
        "-2", "-T", "fields",
        "-e", "tcp.stream",
        "-e", "ip.addr",
        "-e", "data",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "frame.time_epoch",
    ]
    
    with open(output_file, "w") as outfile:
        subprocess.run(tshark_command, stdout=outfile)

def run_serialization_dumper(directory, protocol_name, config, args, patterns):
    serdump_jar = config['DEFAULT']['SERDUMP_JAR_FILE']
    if not os.path.exists(serdump_jar):
        print("Serialization Dumper is required but was not found in this location: " + serdump_jar)
        sys.exit(1)

    for pattern in patterns:
        for filename in os.listdir(directory):
            if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                file_path = os.path.join(directory, filename)
                print("Checking file:", file_path)
                if is_java_magic_number_present(file_path):
                    filename_without_extension = os.path.splitext(filename)[0]
                    output_file_path = os.path.join(directory, filename_without_extension + config['DEFAULT']['SERDUMP_SUFFIX_EXT'])
                    with open(output_file_path, "w") as output:
                        subprocess.run([
                            "java", "-jar", serdump_jar,
                            "-f", file_path
                        ], stdout=output)
                    print("Checked file:", file_path)
                else:
                    print("Error: Java magic number not found in file. Serialization dumper not executed.")    

def main():
    parser = argparse.ArgumentParser(description="Extract Java serialized streams/objects by converting a pcap file using TShark, and parsing the output. Optionally run Serialization Dumper to check the integrity of the serialised objects. - CONFIG_FILE=" + CONFIG_FILE)
    parser.add_argument("Protocol", help="Protocol name")
    parser.add_argument("output_file", nargs='?', default="output.txt", help="Output file path")
    parser.add_argument("--run-serialization-dumper", action="store_true", default=False, help="Enable running serialization dumper")
    parser.add_argument("--stream", type=int, default=0, help="TCP stream index to extract (default: 0)")
    parser.add_argument("--allstreams", action="store_true", help="Process all TCP streams (overrides --stream)")
    parser.add_argument("--emit-meta", action="store_true", default=False, help="Emit {Protocol}_streams.json with per-stream metadata")
    parser.add_argument("--pcap", default=None, help="Direct path to the .pcap file. Overrides BASE_PATH lookup.")
    parser.add_argument("--base-path", default=None, help="Override BASE_PATH from jpcap2ser.cfg for this run.")
    parser.add_argument("--properties", default=None, help="Direct path to the .properties file. Defaults to <pcap dir>/<Protocol>.properties.")
    args = parser.parse_args()

    print ("-------------------")
    print ("----","jPCap2Ser","----")
    print ("-------------------")

    if not os.path.exists(CONFIG_FILE):
        print("Config file: " + CONFIG_FILE + " does not exist.")
        sys.exit(1)
        
    config = load_config(CONFIG_FILE)

    Protocol = args.Protocol
    # Get OUTPUT_FOLDER from config
    output_folder = config['DEFAULT'].get('OUTPUT_FOLDER', os.getcwd())
    # Ensure output folder exists
    os.makedirs(output_folder, exist_ok=True)
    
    # Save output.txt to OUTPUT_FOLDER
    output_file = os.path.join(output_folder, args.Protocol + "_" + args.output_file)
    
    base_path = args.base_path or config['DEFAULT']['BASE_PATH']
    pcap_suffix = config['DEFAULT']['PCAP_SUFFIX_EXT']

    if args.pcap:
        InputFile = os.path.abspath(args.pcap)
    else:
        InputFile = os.path.join(base_path, Protocol.lower(),
                                 Protocol + pcap_suffix)

    if not os.path.exists(InputFile):
        print("Input file: " + InputFile + " does not exist.")
        sys.exit(1)

    print("Protocol: " + Protocol)
    print("Input File: " + InputFile)
    print("Output Folder: " + output_folder)
    if args.allstreams:
        print("Processing all TCP streams")
    else:
        print("Stream index: " + str(args.stream))

    # Remove existing obsolete files matching the patterns
    protocol_name_without_extension = Protocol.lower()
    directory = os.path.dirname(InputFile)
    
    patterns = [
        "{}_*_STEP_*.txt".format(protocol_name_without_extension),
        "{}_STREAM_*.txt".format(protocol_name_without_extension)
    ]

    patterns_ser = [
        "{}_*_STEP_*.ser".format(protocol_name_without_extension),
        "{}_STREAM_*.ser".format(protocol_name_without_extension)
    ]

    for pattern in (patterns+patterns_ser):
        for filename in os.listdir(directory):
            if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                file_path = os.path.join(directory, filename)
                print("Removing existing file:", file_path)
                os.remove(file_path)

    # Run TShark
    print("Running TShark - InputFile:", InputFile)
    run_tshark(InputFile, output_file, config)

    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        print("Parsing output:", output_file)
        
        if args.properties:
            properties_file = os.path.abspath(args.properties)
        else:
            properties_file = os.path.join(directory, Protocol + ".properties")
        # Build the outparse command
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cmd = [
            sys.executable, os.path.join(script_dir, "outparse.py"),
            "--inputfile", output_file,
            "--outputfolder", directory,
            "--fileprefix", Protocol,
            "--filenameformat", config['DEFAULT']['FILENAMEFORMAT'],
            "--outtype", config['DEFAULT']['OUTTYPE'],               
            "--outformat", config['DEFAULT']['OUTFORMAT'],
            "--properties", properties_file
        ]
        if args.allstreams:
            cmd.append("--allstreams")
        else:
            cmd.extend(["--stream", str(args.stream)])
        
        if args.emit_meta:
            cmd.append("--emit-meta")
        
        
        
        
        
        cmd.extend(["--pcap", InputFile])
        
        subprocess.run(cmd)

        if args.run_serialization_dumper:
            if (config['DEFAULT']['OUTTYPE']=="all" or config['DEFAULT']['OUTTYPE']=="txt"):
                    print("Checking with SerializationDumper")
                    run_serialization_dumper(directory, Protocol.lower(), config, args, patterns)
            else: 
                print("SerializationDumper not run as outtype must be \"txt\" or \"all\"")
                    
    else:
        print("Error: Output file", output_file ,"does not exist or is empty.")

if __name__ == "__main__":
    main()