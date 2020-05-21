#!/usr/bin/python
#
# FLOSS module for FAME (https://github.com/certsocietegenerale/fame)
# 
# Author: Xavier Mertens <xavier@rootshell.be>
# Copyright: GPLv3 (http://gplv3.fsf.org/)
# Feel free to use the code, but please share the changes you've made
#
# Original idea found in:
# https://github.com/capnspacehook/cuckoo/blob/master/cuckoo/processing/strings.py
#

import os
import re

try:
    import vivisect
    HAVE_VIVISECT = True
except ImportError:
    HAVE_VIVISECT = False

try:
    from floss import identification_manager as id_man
    from floss import main
    from floss import stackstrings
    from floss import strings as static
    HAVE_FLOSS = True
except ImportError:
    HAVE_FLOSS = False

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir

MAX_FILESIZE = 16*1024*1024
STRING_SEPARATOR = '_AND_'

class floss_str(ProcessingModule):
    name = "floss"
    description = "Extract (encoded) strings from binaries."

    config = [
        {
            "name": "minimum_string_len",
            "type": "integer",
            "default": 6,
            "description": "Minimum length of strings to report."
        },
        {
            "name": "maximum_string_len",
            "type": "integer",
            "default": 256,
            "description": "Maximum length of strings to report."
        },
        {
            "name": "maximum_strings",
            "type": "integer",
            "default": 5000,
            "description": "Maximum number of strings to report."
        },
        {
            'name': 'interesting_strings_file',
            'type': 'str',
            'description': 'File containing interesting/suspicious strings, you should specify the full path.'
        },
        {
            'name': 'ignored_strings_file',
            'type': 'str',
            'description': 'File containing strings to ignore, you should specify the full path.'
        }
    ]

    interesting_strings = []
    ignored_strings = []

    def initialize(self):
        if not HAVE_VIVISECT:
            raise ModuleInitializationError(self, "Missing dependency: vivisect")
        if not HAVE_FLOSS:
            raise ModuleInitializationError(self, "Missing dependency: floss")

    # Search for IOC's in strings
    def search_ioc(self,strings_array):
        for ioc in self.interesting_strings:
            if STRING_SEPARATOR in ioc:
                # Process a correlation of multiple strings
                simple_ioc = ioc.split(STRING_SEPARATOR)
                l = len(simple_ioc)
                for c in simple_ioc:
                    for string in strings_array:
                        if str(string).find(c) >= 0:
                            l-=1;
                            break
                if l == 0:
                    self.results['warnings'].append('Found suspicious correlation of strings: {}'.format(ioc.replace(STRING_SEPARATOR, ',')))
            else:    
                for string in strings_array:
                    if str(string).find(ioc) >= 0:
                        self.results['warnings'].append('Found suspicious string: {}'.format(ioc))
                        break

    def each(self, target):
        self.results = {
            'warnings': [],
            'static_strings': [],
            'decoded_strings': [],
            'stack_strings': []
        }

        try:
            data = open(target, "r").read(MAX_FILESIZE)
        except (IOError, OSError) as e:
            self.log('error', 'Cannot open file {}'.format(target))
            self.results = None
            return False

        # Load list of IOC's
        try:
            with open(self.interesting_strings_file) as f:
               self.interesting_strings = f.read().splitlines()
            self.log('info', 'Loaded interesting strings from {}'.format(self.interesting_strings_file))
        except:
            # No IOC file, create an empty list           
            self.log('info', 'No file with interesting strings defined')
            self.interesting_strings = []

        # Load list of ignored strings
        try:
            with open(self.ignored_strings_file) as f:
               self.ignored_strings = f.read().splitlines()
            self.log('info', 'Loaded ignored strings from {}'.format(self.ignored_strings_file))
        except:
            # No IOC file, create an empty list           
            self.log('info', 'No file with ignored strings defined')
            self.ignored_strings = []

        # Extract static strings
        static_strings = re.findall("[\x1f-\x7e]{" + str(self.minimum_string_len) + ",}", data)
        for s in re.findall("(?:[\x1f-\x7e][\x00]){" + str(self.minimum_string_len) + ",}", data):
            static_strings.append(s.decode("utf-16le"))

        if self.maximum_string_len != 0:
            for i, s in enumerate(static_strings):
                static_strings[i] = s[:self.maximum_string_len]

        if self.maximum_strings != 0 and len(static_strings) > self.maximum_strings:
            self.log('warning', 'Maximum number of strings reached ({})'.format(str(self.maximum_strings)))
            static_strings = static_strings[:self.maximum_strings]
            static_strings.append("[snip]")

        try:
            # Prepare Floss for extracting hidden & encoded strings
            vw = vivisect.VivWorkspace()
            vw.loadFromFile(target)
            vw.analyze()

            selected_functions = main.select_functions(vw, None)
            decoding_functions_candidates = id_man.identify_decoding_functions(
                 vw, main.get_all_plugins(), selected_functions
            )
        except Exception as e:
            self.log('error','Cannot analyze file {}'.format(target))
            self.results = None
            return False

        # Decode & extract hidden & encoded strings
        try:
            decoded_strings = main.decode_strings(
                vw, decoding_functions_candidates, self.minimum_string_len
            )
            decoded_strs = main.filter_unique_decoded(decoded_strings)

            stack_strings = stackstrings.extract_stackstrings(
                vw, selected_functions, self.minimum_string_len
            )
            stack_strings = list(stack_strings)

            decoded_strings = [x for x in decoded_strs if not x in static_strings]
        except Exception as e:
            self.log('error','Cannot extract strings from {}'.format(target))
            self.results = None
            return False

        # Populate results[] with found strings
        if len(decoded_strings) or len(stack_strings):
            self.log('info', 'Found stack or decoded strings')
            for k, s in enumerate(decoded_strings):
                buffer = main.sanitize_string_for_printing(s.s)
                skip = False
                for ignore in self.ignored_strings:
                   if str(buffer).find(ignore) >= 0:
                     skip = True
                     break
                if not skip:
                    self.results['decoded_strings'].append(buffer)
            self.search_ioc(self.results['decoded_strings'])

            for k, s in enumerate(stack_strings):
                skip = False
                for ignore in self.ignored_strings:
                   if str(s.s).find(ignore) >= 0:
                     skip = True
                     break
                if not skip:
                    self.results['stack_strings'].append(s.s)
            self.search_ioc(self.results['stack_strings'])

        # Populate results[] with static strings
        self.log('info', 'Found static strings')
        for s in static_strings:
            skip = False
            for ignore in self.ignored_strings:
                if str(s).find(ignore) >= 0:
                    skip = True
                    break
            if not skip:
                self.results['static_strings'].append(s)
        self.search_ioc(self.results['static_strings'])

        # Deduplicate warnings
        self.results['warnings'] = list(dict.fromkeys(self.results['warnings']))

        return True
