#!/usr/bin/env python3

#  Extract hidden "fastboot oem" commands from firmware blobs
#  Copyright (C) 2025 chickendrop89
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import re
import io
import contextlib
import logging
import tempfile

from pathlib import Path
from uefi_firmware import AutoParser

# Common magic bytes for Little Kernel firmware
LK_MAGIC_BYTES = bytes.fromhex('88 16 88 58')

def setup_logging() -> logging.Logger:
    """Configure logging"""

    class PrefixFormatter(logging.Formatter):
        def format(self, record):
            record.msg = f"(x) {record.msg}"
            return super().format(record)

    log = logging.getLogger('oem_extractor')
    log.setLevel(logging.INFO)
    log.propagate = False

    # Custom prefix
    handler = logging.StreamHandler()
    handler.setFormatter(PrefixFormatter('%(message)s'))
    log.addHandler(handler)

    return log

def find_oem_commands(firmware_file: Path) -> None:
    """Extract oem commands from a firmware file"""

    # Matching for "oem <xxx>"
    content = firmware_file.read_bytes()
    strings = re.findall(rb'oem\s+([^\x00\n]+)', content, re.IGNORECASE)

    if strings:
        cmds = sorted(set(
            # (compatibility) pylint: disable=inconsistent-quotes
            f'oem {s.decode("ascii", "ignore").strip()}'
            for s in strings
        ))
        logger.info('Matching \'oem *\' ascii strings')
        print('\n' + '\n'.join(cmds))
    else:
        logger.info('No fastboot oem commands found in %s/%s',
           firmware_file.parent.name, firmware_file.name)

def extract_pe_files(parser: AutoParser) -> bool | list:
    """Extract firmware file and search for portable executables"""

    with tempfile.TemporaryDirectory() as tmpdir:
        logger.info('Extracting firmware...')

        # Stop dump() from writing to stdout
        with contextlib.redirect_stdout(io.StringIO()):
            parser.parse().dump(tmpdir)

        # Glob for files with the extension '.pe' recursively
        pe_files = list(Path(tmpdir).rglob('*.pe'))
        if not pe_files:
            logger.info('No UEFI portable executables found')
            return 1

        logger.info('Found %s UEFI portable executable(s)', len(pe_files))
        for pe in pe_files:
            find_oem_commands(pe)
    return 0

def check_firmware(firmware_file: Path) -> bool | AutoParser:
    """Analyze firmware file for OEM commands"""

    try:
        logger.info('Reading firmware file: %s', firmware_file)

        # Check for little kernel magic bytes, if not found, close
        with open(firmware_file, 'rb') as fh:
            if fh.read(len(LK_MAGIC_BYTES)) == LK_MAGIC_BYTES:
                logger.info('File contains little kernel magic bytes')
                find_oem_commands(Path(firmware_file))
                return 1
        fh.close()

        with open(firmware_file, 'rb') as fh:
            input_data = fh.read()

    except OSError as error:
        logger.info('Cannot read file (%s): %s', firmware_file, str(error))
        return 1

    # Search for firmware structure
    for i in range(0, len(input_data), 32):
        parser = AutoParser(input_data[i:], search=False)
        if parser.type() != 'unknown':
            logger.info('Found valid firmware structure at offset: 0x%x', i)
            break
    else:
        logger.info('Couldn\'t find any firmware structure. Cannot continue')
        return 1

    return extract_pe_files(parser)

def main() -> Path:
    """Main entry point"""

    parser = argparse.ArgumentParser(
        description='Extract hidden "fastboot oem" commands from firmware blobs (ABL, LK)'
    )
    parser.add_argument('file', help='Firmware file to analyze')
    args = parser.parse_args()

    return check_firmware(args.file)

# Initialize logger
logger = setup_logging()

if __name__ == '__main__':
    main()
