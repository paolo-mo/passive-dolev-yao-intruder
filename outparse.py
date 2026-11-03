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


 Read Streams Objects functions are derived from initial work
 of Louis Holmes for his Computing Project at Teesside University
 https://github.com/Louisholmes0217/jcryptgrabber

'''

import argparse
import os.path
import re
from enum import Enum

JAVA_MAGIC_NUMBER = "aced0005"
START_INDEX_ANBX = 1

# Define Enum for filenameformat type
class FileNameFormatType(Enum):
    DEFAULT = "default"
    ANBX = "anbx"

# Define Enum for output format
class OutputFormat(Enum):
    SINGLE = "single"
    STREAM = "stream"
    ALL = "all"

# Define Enum for output type
class OutputType(Enum):
    ALL = "all"
    SER = "ser"
    TXT = "txt"

class PcapObj:
    def __init__(self, stream, index, data):
        self.stream = stream
        self.index = index
        self.data = data

class ValidStream:
    def __init__(self, id, index, addressPair, firstLine, data,
                 src_ip="", src_port=0, dst_ip="", dst_port=0,
                 t_first=0.0, t_last=0.0, magic_count=0):
        self.id = id
        self.streamIndex = index
        self.addressPair = addressPair
        self.firstLine = firstLine
        self.data = data
        # --- new fields (Step 1) ---
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.t_first = t_first
        self.t_last = t_last
        self.magic_count = magic_count

def _extract_metadata(parts):
    """
    Extract metadata from a TShark output line.
    parts is the tab-split line.
    Expected layout (Step 1):
       0: tcp.stream
       1: ip.addr
       2: data
       3: ip.src
       4: ip.dst
       5: tcp.srcport
       6: tcp.dstport
       7: frame.time_epoch
    Returns a dict or None if the new fields are not present.
    """
    if len(parts) < 8:
        return None
    try:
        return {
            "src_ip": parts[3],
            "dst_ip": parts[4],
            "src_port": int(parts[5]),
            "dst_port": int(parts[6]),
            "t_epoch":  float(parts[7]),
        }
    except (ValueError, IndexError):
        return None

def emit_streams_meta(output_folder, fileprefix, streams, protocol, pcap_name,
                      allstreams=False):
    """
    Write {Protocol}_streams.json with per-stream metadata.
    Filenames match those produced by save_streams in the same run.
    """
    import json
    import datetime
    from collections import defaultdict

    # Normalise prefix the same way generate_filename does
    prefix = fileprefix
    if prefix and prefix[-1] != "_":
        prefix += "_"

    entries = []

    if allstreams:
        groups = defaultdict(list)
        for stream in streams:
            groups[int(stream.streamIndex) + 1].append(stream)
        for stream_idx, group in groups.items():
            for dir_idx, stream in enumerate(group, start=1):
                filename = f"{prefix}STREAM_{stream_idx}_{dir_idx}.ser"
                magic_count = sum(1 for c in stream.data
                                if c.startswith(JAVA_MAGIC_NUMBER))
                entries.append({
                    "file":       filename,
                    "tcp_stream": int(stream.streamIndex),
                    "src_ip":     stream.src_ip,
                    "src_port":   stream.src_port,
                    "dst_ip":     stream.dst_ip,
                    "dst_port":   stream.dst_port,
                    "t_first":    stream.t_first,
                    "t_last":     stream.t_last,
                    "magic_count":  magic_count,
                })
    else:
        for i, stream in enumerate(streams, start=1):
            filename = f"{prefix}STREAM_{i}.ser"
            magic_count = sum(1 for c in stream.data
                            if c.startswith(JAVA_MAGIC_NUMBER))
            entries.append({
                "file":       filename,
                "tcp_stream": int(stream.streamIndex),
                "src_ip":     stream.src_ip,
                "src_port":   stream.src_port,
                "dst_ip":     stream.dst_ip,
                "dst_port":   stream.dst_port,
                "t_first":    stream.t_first,
                "t_last":     stream.t_last,
                "magic_count":  magic_count,
            })

    if not entries:
        print(f"Warning: {protocol}_streams.json has no entries "
              f"(no streams matched the filter).")
    
    
    doc = {
        "protocol":     protocol,
        "pcap":         pcap_name,
        "generated_by": "outparse.py (step 1)",
        "generated_at": datetime.datetime.now(
                            datetime.timezone.utc).isoformat(),
        "streams":      entries,
    }

    out_path = os.path.join(output_folder, f"{protocol}_streams.json")
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=2)
    print(f"Saved metadata: {out_path} ({len(entries)} streams)")
        
def print_stream(stream):
    print("Stream ID:", stream.id)
    print("Stream Index:", stream.index)
    print("Address Pair:", stream.addressPair)
    print("FirstLine:", stream.firstLine)
    print("Data:", stream.data)
    print()

def print_stream_ids(streams):
    # Extract all StreamIDs from valid_streams
    stream_ids = [stream.id for stream in streams]
    # Print both messages in a single line
    print(f"Valid Streams ({len(streams)}): {', '.join(stream_ids)}")

def generate_filename(filenameformat, output_format, index_label, fileprefix):
    if fileprefix and fileprefix[-1] != "_":
        fileprefix += "_"

    if filenameformat == FileNameFormatType.ANBX:
        if output_format == OutputFormat.STREAM:
            filename = f"{fileprefix}STREAM_{index_label}"
        elif output_format == OutputFormat.SINGLE:
            filename = f"{fileprefix}STEP_{index_label}"
        else:
            raise ValueError("Invalid output format.")
    else:
        if output_format == OutputFormat.STREAM:
            filename = f"{fileprefix}STREAM_{index_label}"
        elif output_format == OutputFormat.SINGLE:
            filename = f"{fileprefix}STEP_{index_label}"
        else:
            raise ValueError("Invalid output format.")

    separator = "-" if filenameformat == FileNameFormatType.ANBX else ","
    filename = filename.replace(',', separator)

    return filename

def save_file(output_folder, output_format, filenameformat, index_or_stream_id, data, output_type, fileprefix):
    filename = generate_filename(filenameformat, output_format, index_or_stream_id, fileprefix)
    full_path = os.path.join(output_folder, f"{filename}.{output_type}")
    data_size = 0

    if output_type == OutputType.SER.value and (output_format == OutputFormat.SINGLE or output_format == OutputFormat.STREAM) :
        with open(full_path, "wb") as f:
            f.write(bytes.fromhex(data))  # Encode text to bytes before writing
            data_size = len(data)
    elif output_type == OutputType.SER.value and output_format == OutputFormat.ALL :
        with open(full_path, "wb") as f:
            f.write(data)
            data_size = len(data)
    else:
        with open(full_path, "w") as f:
            f.write(data)
            data_size = len(data)   

    print("Saved file:", full_path, "- Data size:", data_size, "- Output Format:", output_format, "- Output Type:", output_type)

def parse_properties(properties_file):
    """
    Parses the .properties file to extract the order of address pairs.
    The order is determined by the sequence of channel definitions in the file.
    Each channel is preceded by a comment line that contains the two IP addresses
    in the order source,destination.
    Returns a dict mapping address_pair (e.g., "10.0.1.2,10.0.2.2") to an integer order.
    """
    order_map = {}
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    try:
        with open(properties_file, 'r') as f:
            lines = f.readlines()
            comment = None
            for line in lines:
                line = line.strip()
                if line.startswith('#'):
                    comment = line
                elif '_role =' in line and not line.startswith('#'):
                    if comment:
                        # Extract all IPs from the comment in order
                        ips = ip_pattern.findall(comment)
                        if len(ips) >= 2:
                            # Take the first two IPs as source,destination
                            addr_pair = f"{ips[0]},{ips[1]}"
                            if addr_pair not in order_map:
                                order_map[addr_pair] = len(order_map)
                    comment = None  # reset after processing
    except FileNotFoundError:
        print(f"Warning: properties file {properties_file} not found. Using default ordering.")
    return order_map

def read_streams_from_file(input_file, order_map=None, stream_filter=None):
    """
    Reads the TShark output file and groups streams by TCP stream index.
    If an order_map is provided (from the .properties file), it sorts the streams
    according to that order. Otherwise, it falls back to sorting by firstLine.
    Returns a list of ValidStream objects in the desired order.
    If stream_filter is given (int), only lines with that tcp.stream are kept.
    """
    streams = []
    with open(input_file, "r") as f:
        for line_index, line in enumerate(f):
            line = line.strip().split("\t")
            if len(line) < 3:
                continue

            # Apply stream filter (if any)
            try:
                current_stream = int(line[0])
            except ValueError:
                continue  # or handle error
            if stream_filter is not None and current_stream != stream_filter:
                continue

            stream_index = line[0]
            address_pair = line[1]
            meta = _extract_metadata(line)

            # Build the stream identifier. When the two endpoints share the
            # same IP (e.g. a localhost capture, or two agents behind the
            # same NAT address), the IP pair alone cannot distinguish the
            # two directions; disambiguate by source port. This branch
            # never fires when the two endpoints have distinct IPs, so
            # Docker captures take the original code path unchanged.
            stream_id = stream_index + "_" + address_pair
            if meta and meta["src_ip"] == meta["dst_ip"]:
                stream_id = stream_id + "_src" + str(meta["src_port"])

            existing_stream = next(
                (s for s in streams if s.id == stream_id), None
            )

            if line[2].startswith(JAVA_MAGIC_NUMBER):
                if not existing_stream:
                    streams.append(
                        ValidStream(
                            stream_id, stream_index, address_pair,
                            float('inf'), [line[2]],
                            src_ip=meta["src_ip"] if meta else "",
                            src_port=meta["src_port"] if meta else 0,
                            dst_ip=meta["dst_ip"] if meta else "",
                            dst_port=meta["dst_port"] if meta else 0,
                            t_first=meta["t_epoch"] if meta else 0.0,
                            t_last=meta["t_epoch"] if meta else 0.0,
                            magic_count=1,
                        )
                    )
            else:
                if existing_stream:
                    existing_stream.data.append(line[2])
                    if existing_stream.firstLine == float('inf'):
                        existing_stream.firstLine = line_index + 1
                    if meta:
                        existing_stream.t_last = max(existing_stream.t_last, meta["t_epoch"])
                else:
                    streams.append(
                        ValidStream(
                            stream_id, stream_index, address_pair,
                            line_index + 1, [line[2]],
                            src_ip=meta["src_ip"] if meta else "",
                            src_port=meta["src_port"] if meta else 0,
                            dst_ip=meta["dst_ip"] if meta else "",
                            dst_port=meta["dst_port"] if meta else 0,
                            t_first=meta["t_epoch"] if meta else 0.0,
                            t_last=meta["t_epoch"] if meta else 0.0,
                            magic_count=0,
                        )
                    )

    # Group streams by TCP stream index (int)
    groups = {}
    for s in streams:
        idx = int(s.streamIndex)
        groups.setdefault(idx, []).append(s)

    if order_map is not None and order_map:
        # Use the order from the properties file
        sorted_groups = []
        for idx, group in groups.items():
            # Sort the two directions within the group by the order_map
            group_sorted = sorted(group, key=lambda s: order_map.get(s.addressPair, 999))
            # The group's overall order is the minimum key among its members
            min_order = min(order_map.get(s.addressPair, 999) for s in group)
            sorted_groups.append((min_order, idx, group_sorted))
        # Sort groups by the custom order (not by TCP stream index)
        sorted_groups.sort(key=lambda x: x[0])
    else:
        # Fallback: sort by firstLine (original behaviour)
        sorted_groups = []
        for idx, group in groups.items():
            non_empty = [s for s in group if len(s.data) > 1]
            if not non_empty:
                continue  # ignore groups with no actual data (shouldn't happen)
            first_line = min(s.firstLine for s in non_empty)
            sorted_groups.append((first_line, idx, group))
        sorted_groups.sort(key=lambda x: x[0])

    # Flatten: for each sorted group, output non-empty first, then empty ones
    result = []
    for _, idx, group in sorted_groups:
        non_empty = [s for s in group if len(s.data) > 1]
        empty = [s for s in group if len(s.data) <= 1]
        # order non-empty first, then empty
        result.extend(non_empty)
        result.extend(empty)

    # After all processing, if no streams were found for the filter, warn
    if stream_filter is not None and not streams:
        print(f"Warning: No data found for TCP stream {stream_filter}. Please check the input file.")
    return result

def read_objects_from_file(input_file, filenameformat, stream_filter=None):
    # This function reads individual serialised objects. However, it works correctly only for streams with a single object.
    # For streams with more than one object, TC_REFERENCE would need to be adjusted for the second and further objects
    
    valid_streams = []
    objs = []
    last_identifier = None
    stream_indices = {}
    index_base = 1 if filenameformat == FileNameFormatType.ANBX else 1

    with open(input_file, "r") as f:
        for line in f:
            line = line.strip().split("\t")
            if len(line) < 3:
                continue

            # Filter by stream if provided
            if stream_filter is not None:
                try:
                    if int(line[0]) != stream_filter:
                        continue
                except ValueError:
                    continue

            stream_id = line[0] + "_" + line[1]
            if line[2].startswith(JAVA_MAGIC_NUMBER):
                if stream_id not in valid_streams:
                    valid_streams.append(stream_id)
                    stream_indices[stream_id] = index_base
                continue
            
            if stream_id in valid_streams:
                if stream_id != last_identifier:
                    obj = PcapObj(stream_id, stream_indices[stream_id], JAVA_MAGIC_NUMBER + line[2])
                    stream_indices[stream_id] += 1
                    objs.append(obj)
                else:
                    objs[-1].data += line[2]  # Concatenate data to the existing object's data
                last_identifier = stream_id

    return objs

def save_streams(output_folder, filenameformat, streams, output_type, fileprefix="", allstreams=False):
    if allstreams:
        # Group streams by TCP stream index
        from collections import defaultdict
        groups = defaultdict(list)
        for stream in streams:
            groups[int(stream.streamIndex)+1].append(stream)
        
        # For each group, the streams are already in the correct order (by channel)
        for stream_idx, group in groups.items():
            for dir_idx, stream in enumerate(group, start=1):
                label = f"{stream_idx}_{dir_idx}"   # e.g., "0_1"
                stream_data = ''.join(stream.data)
                if output_type == OutputType.SER or output_type == OutputType.ALL:
                    save_file(output_folder, OutputFormat.STREAM, filenameformat, label, stream_data, OutputType.SER.value, fileprefix)
                if output_type == OutputType.TXT or output_type == OutputType.ALL:
                    save_file(output_folder, OutputFormat.STREAM, filenameformat, label, stream_data, OutputType.TXT.value, fileprefix)
    else:
        # Original behaviour (single stream mode)
        start_index = START_INDEX_ANBX if filenameformat == FileNameFormatType.ANBX else 1
        for enumeration_count, stream in enumerate(streams, start=start_index):
            stream_data = ''.join(stream.data)
            if filenameformat == FileNameFormatType.ANBX:
                index_label = enumeration_count
            else:
                index_label = stream.id
            if output_type == OutputType.SER or output_type == OutputType.ALL:
                save_file(output_folder, OutputFormat.STREAM, filenameformat, index_label, stream_data, OutputType.SER.value, fileprefix)
            if output_type == OutputType.TXT or output_type == OutputType.ALL:
                save_file(output_folder, OutputFormat.STREAM, filenameformat, index_label, stream_data, OutputType.TXT.value, fileprefix)

def save_objects(output_folder, filenameformat, objs, outformat, outtype, fileprefix="", allstreams=False):
    if allstreams:
        # Group objects by TCP stream index (extracted from obj.stream)
        from collections import defaultdict
        groups = defaultdict(list)
        for obj in objs:
            # obj.stream is like "0_10.0.1.2,10.0.2.2"
            stream_idx = obj.stream.split('_')[0]
            groups[int(stream_idx)+1].append(obj) 
        
        # For each group, objects are already in the order they appear in the stream
        for stream_idx, group in groups.items():
            for dir_idx, obj in enumerate(group, start=1):
                # The step number is obj.index
                label = f"{stream_idx}_{dir_idx}_{obj.index}"   # e.g., "0_1_1"
                if outtype == OutputType.SER or outtype == OutputType.ALL:
                    save_file(output_folder, OutputFormat.SINGLE, filenameformat, label, obj.data, OutputType.SER.value, fileprefix)
                if outtype == OutputType.TXT or outtype == OutputType.ALL:
                    save_file(output_folder, OutputFormat.SINGLE, filenameformat, label, obj.data, OutputType.TXT.value, fileprefix)
    else:
        # Original behaviour (single stream mode)
        start_index = START_INDEX_ANBX if filenameformat == FileNameFormatType.ANBX else 1
        for i, obj in enumerate(objs, start=start_index):
            if filenameformat == FileNameFormatType.ANBX:
                index_label = i
            else:
                index_label = obj.stream + "_" + str(obj.index)
            if outtype == OutputType.SER or outtype == OutputType.ALL:
                save_file(output_folder, OutputFormat.SINGLE, filenameformat, index_label, obj.data, OutputType.SER.value, fileprefix)
            if outtype == OutputType.TXT or outtype == OutputType.ALL:
                save_file(output_folder, OutputFormat.SINGLE, filenameformat, index_label, obj.data, OutputType.TXT.value, fileprefix)

def main(input_file, output_folder=None, filenameformat=FileNameFormatType.DEFAULT,
         fileprefix="", outtype=OutputType.ALL, outformat=OutputFormat.ALL,
         properties_file=None, stream_filter=0, allstreams=False, emit_meta=False,
         pcap_name=""):
    # Check if the input file exists
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        return

    # If the output folder is not specified, we use the same directory of the input file
    if output_folder is None:
        output_folder = os.path.dirname(os.path.abspath(input_file))

    print(f"Input file: {input_file}")
    print(f"Output folder: {output_folder}")

    # Check if the output folder exists
    if not os.path.exists(output_folder):
        print(f"Error: Output folder '{output_folder}' does not exist.")
        return

    # Parse the properties file if provided
    order_map = None
    if properties_file:
        if os.path.exists(properties_file):
            order_map = parse_properties(properties_file)
            print(f"Read channel order from {properties_file}")
        else:
            print(f"Warning: properties file {properties_file} not found. Using default ordering.")

    # If allstreams is True, ignore stream_filter and process all
    if allstreams:
        stream_filter = None
        print("Processing all TCP streams.")

    if outformat == OutputFormat.STREAM or outformat == OutputFormat.ALL:
        # Extract and sort valid streams using the order_map if available
        valid_streams = read_streams_from_file(input_file, order_map, stream_filter)
        print_stream_ids(valid_streams)
        save_streams(output_folder, filenameformat, valid_streams, outtype, fileprefix, allstreams)
        
    if emit_meta and (outformat == OutputFormat.STREAM or outformat == OutputFormat.ALL):
        emit_streams_meta(
            output_folder=output_folder,
            fileprefix=fileprefix,
            streams=valid_streams,
            protocol=fileprefix,
            pcap_name=pcap_name or os.path.basename(input_file),
            allstreams=allstreams,
        )    

    if outformat == OutputFormat.SINGLE or outformat == OutputFormat.ALL:
        #  Read single objects from valid streams
        objs = read_objects_from_file(input_file, filenameformat, stream_filter)
        print("Objects #:", len(objs))
        save_objects(output_folder, filenameformat, objs, outformat, outtype, fileprefix, allstreams)

if __name__ == "__main__":
    # Initialize argparse
    parser = argparse.ArgumentParser(description="Process PCAP data and extract serialised Java objects.")

    # Add an argument for specifying the input file name
    parser.add_argument('--inputfile', required=True, help="Input file name")

    # Add an argument for specifying the output folder (optional)
    parser.add_argument('--outputfolder', help="Output folder name (optional). Default: same as input file")

    # Add a switch for specifying the filename format
    parser.add_argument('--filenameformat', choices=[FileNameFormatType.DEFAULT, FileNameFormatType.ANBX],
                        default=FileNameFormatType.DEFAULT, type=FileNameFormatType,
                        help="Filename format (default|anbx)")

    # Add an optional argument for specifying the file prefix
    parser.add_argument('--fileprefix', default="", help="File prefix (e.g. Protocol Name)")

    # Add an optional argument for specifying the output type
    parser.add_argument('--outtype', choices=[OutputType.SER, OutputType.TXT, OutputType.ALL],
                        default=OutputType.ALL, type=OutputType,
                        help="Output file type (ser|txt|all). Default: all")

    # Add an optional argument for specifying the output format
    parser.add_argument('--outformat', choices=[OutputFormat.SINGLE, OutputFormat.STREAM, OutputFormat.ALL],
                        default=OutputFormat.ALL, type=OutputFormat,
                        help="Output file type (single|stream|all). Default: all")

    # Add an argument for the .properties file
    parser.add_argument('--properties', help="Path to the .properties file for channel order")
    
    # Parse only this stream
    parser.add_argument('--stream', type=int, default=0, help="TCP stream index to process (default: 0)")

    # Process all streams
    parser.add_argument('--allstreams', action='store_true', help="Process all TCP streams (overrides --stream)")

    # Emit meta data
    parser.add_argument('--emit-meta', action='store_true', default=False, help="Emit {Protocol}_streams.json with per-stream metadata")
    
    # PCAP file path
    parser.add_argument('--pcap', default="", help="Path to the original PCAP file")

    args = parser.parse_args()

    main(args.inputfile, args.outputfolder, args.filenameformat,
         args.fileprefix, args.outtype, args.outformat,
         args.properties, args.stream, args.allstreams, args.emit_meta, args.pcap)