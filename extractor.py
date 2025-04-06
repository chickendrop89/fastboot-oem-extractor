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

BL_MAGIC_PATTERNS = [
    bytes.fromhex('88 16 88 58'),  # Little Kernel (LK)
    bytes.fromhex('46 42 50 4B'),  # FBPK container
    bytes.fromhex('7F 45 4C 46'),  # Common ELF binaries
    bytes.fromhex('41 4E 44 52 4F 49 44 21 CC')  # lk1st, lk2nd
]

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
            # Filter only strings containing two words (e.g. "oem xxx")
            if 2 <= len(f'oem {s.decode("ascii", "ignore").strip()}'.split()) <= 3
        ))
        if cmds:
            logger.info('Matching \'oem *\' ascii strings')
            print('\n' + '\n'.join(cmds))
            return 1

    logger.info('No fastboot oem commands found')
    return 1

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
    return 1

def check_firmware(firmware_file: Path) -> bool:
    """Analyze firmware file for OEM commands"""

    # Ensure firmware_file is Path and not String
    firmware_file = Path(firmware_file)

    def check_uefi_structure(data: bytes) -> None:
        """Search for UEFI firmware structure in data"""

        for offset in range(0, len(data), 2048):
            parser = AutoParser(data[offset:], search=False)
            if parser.type() != 'unknown':
                logger.info('Found valid UEFI firmware structure at offset: 0x%x', offset)
                return extract_pe_files(parser)
        return None

    def check_bootloader_magic() -> None:
        """Check for known bootloader magic patterns"""

        with open(firmware_file, 'rb') as fh:
            header = fh.read(max(len(pattern) for pattern in BL_MAGIC_PATTERNS))

            for pattern in BL_MAGIC_PATTERNS:
                if header.startswith(pattern):
                    logger.info('File contains common bootloader magic bytes')
                    return find_oem_commands(firmware_file)
        return None

    try:
        logger.info('Reading firmware file: %s', firmware_file)
        with open(firmware_file, 'rb') as fh:
            input_data = fh.read()
            fh.close()
    except OSError as error:
        logger.error('Cannot read file (%s): %s', firmware_file, str(error))
        return 0

    # Search for UEFI structure
    if check_uefi_structure(input_data):
        del input_data # memory cleanup
        return 1

    # Or, if failed, check for bootloader magic
    if check_bootloader_magic():
        return 1

    logger.error('Could not recognize the provided firmware file')

def main() -> Path:
    """Main entry point"""

    parser = argparse.ArgumentParser(
        description='Extract hidden "fastboot oem" commands from firmware blobs'
    )
    parser.add_argument('file', help='Firmware file to analyze')
    args = parser.parse_args()

    return check_firmware(args.file)

# Initialize logger
logger = setup_logging()

if __name__ == '__main__':
    main()
