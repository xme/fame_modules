#!/usr/bin/python3
import os
import sys

try:
    import acefile
except ImportError:
    raise Exception("Missing dependency: acefile")

# Syntax: 
# Arg1 : '--' (from Dockerfile)
# Arg2 : ACE file
# Arg3 : Maximum extracted files
# Arg4 : Maximum automatic analyzis

if len(sys.argv) != 5:
   raise Exception("Incorrect number of arguments ({})".format(len(sys.argv)))
 
target = sys.argv[2]
maximum_extracted_files = int(sys.argv[3])
maximum_automatic_analyses = int(sys.argv[4])

# password_candidates = self.password_candidates.split("\n")

try:
     af = acefile.AceArchive(target)
except:
     raise Exception("Cannot open ACE archive {}".format(target))

members = af.getmembers()

should_extract = len(members) <= maximum_extracted_files
should_analyze = len(members) <= maximum_automatic_analyses

if should_extract:
    for m in members:
        try:
            af.extract(m, path='/data')
            filepath = '/data/'+m.filename
            if os.path.isfile(filepath):
                print("should_analyze: {}".format(filepath))
        except RuntimeError:
            print("warning: Cannot analyze {}".format(filepath))

    if not should_analyze:
        print("warning: Archive contains more than {} files ({}), so no analysis was automatically created.".format(
                maximum_automatic_analyses, len(members)))
else:
    print("warning: Archive contains more than {} files ({}), so they were not extracted.".format(
            maximum_extracted_files, len(members)))
