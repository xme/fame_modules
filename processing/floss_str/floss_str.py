import os
import re

import vivisect
from floss import identification_manager as id_man
from floss import main
from floss import stackstrings
from floss import strings as static

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir

MAX_FILESIZE = 16*1024*1024

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
        }
    ]

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
            self.error('error','Cannot analyze file {}'.format(target))
            self.results = None
            return False

        try:
            # Decode & extract hidden & encoded strings
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

        if len(decoded_strings) or len(stack_strings):
            # convert Floss strings into regular, readable strings
            self.log('info', 'Found stack or decoded strings')
            for idx, s in enumerate(decoded_strings):
                decoded_strings[idx] = main.sanitize_string_for_printing(s.s)
                self.results['decoded_strings'].append(str(main.sanitize_string_for_printing(s.s)))

            for idx, s in enumerate(stack_strings):
                stack_strings[idx] = s.s
                self.results['stack_strings'].append(str(s.s))
        else:
            self.log('info', 'Found static strings')
            for s in static_strings:
                self.results['static_strings'].append(str(s))

        return True
