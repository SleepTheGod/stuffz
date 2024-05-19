#!/usr/bin/env python
# -*- coding: utf-8 -*-
print("""
#    vtrace-dump_memory.py - Dump memory from a breakpoint.
#
#    vtrace-show_args_function.py - Script for vtrace API for display arguments function before call.
#
#    Syntax : ./vtrace-show_args_function.py <binary> <addr call function> <Numbers of arg>
#    Exemple: ./vtrace-show_args_function.py ./binary 0x8048438 2
#
#    Copyright (C) 2012-06 Jonathan Salwan - http://www.twitter.com/jonathansalwan
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.""")
import vtrace
import sys
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def dump_memory(trace, memory, size):
    """Dump memory from the breakpoint address."""
    breakpoint_address = trace.getRegisterByName("eip")
    logger.info(f"Breakpoint at 0x{breakpoint_address:08x}")
    try:
        dump = trace.readMemory(memory, size)
        dump_file_path = os.path.join(os.getcwd(), "vtrace-memory.dump")
        with open(dump_file_path, "wb") as fd:
            fd.write(dump)
        logger.info("Dump successful. Saved to %s", dump_file_path)
    except Exception as e:
        logger.error("Failed to dump memory: %s", e)


def main(binary, breakpoint, memory, size):
    """Main function to execute tracing and memory dump."""
    trace = vtrace.getTrace()
    try:
        trace.execute(binary)
    except Exception as e:
        logger.error("Failed to execute binary: %s", e)
        return
    try:
        trace.addBreakpoint(breakpoint)
    except Exception as e:
        logger.error("Invalid breakpoint address: %s", e)
        return
    trace.run()
    dump_memory(trace, memory, size)


if __name__ == "__main__":
    if len(sys.argv) == 5:
        main(sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16), int(sys.argv[4]))
    else:
        print("Usage: {} <binary> <addr - breakpoint> <memory addr> <size dump>".format(sys.argv[0]))
        sys.exit(1)

