import os
import rarfile

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir


class Rar(ProcessingModule):
    name = "rar"
    description = "Extract files from RAR archive."
    acts_on = "rar"

    config = [
        {
            "name": "password_candidates",
            "type": "text",
            "default": "malware\ninfected",
            "description": "List of passwords to try when unpacking an encrypted RAR file (one per line)."
        },
        {
            "name": "maximum_extracted_files",
            "type": "integer",
            "default": 5,
            "description": "If there are more files than this value in the archive, files will not be extracted."
        },
        {
            "name": "maximum_automatic_analyses",
            "type": "integer",
            "default": 1,
            "description": "If there are more files than this value in the archive, no analyses will be automatically created for extracted files."
        }
    ]

    def each(self, target):
        self.results = {
            'warnings': []
        }

        tmpdir = tempdir()

        password_candidates = self.password_candidates.split("\n")

        rf = rarfile.RarFile(target)

        filelist = rf.infolist()

        should_extract = len(filelist) <= self.maximum_extracted_files
        should_analyze = len(filelist) <= self.maximum_automatic_analyses

        if should_extract:
            for f in filelist:
                try:
                    filepath = rf.extract(f.filename, path=tmpdir)
                    if os.path.isfile(filepath):
                        self.add_extracted_file(filepath, automatic_analysis=should_analyze)
                except RuntimeError:
                    for password in password_candidates:
                        try:
                            filepath = rf.extract(f.filename, path=tmpdir, pwd=password)
                            if os.path.isfile(filepath):
                                self.add_extracted_file(filepath, automatic_analysis=should_analyze)
                            break
                        except RuntimeError:
                            pass
                    else:
                        self.results['warnings'].append(u'Could not extract {} (password not known)'.format(f.filename))

            if not should_analyze:
                self.results['warnings'].append(
                    "Archive contains more than {} files ({}), so no analysis was automatically created.".format(
                        self.maximum_automatic_analyses, len(filelist)))
        else:
            self.results['warnings'].append(
                "Archive contains more than {} files ({}), so they were not extracted.".format(
                    self.maximum_extracted_files, len(filelist)))

        if self.results['warnings']:
            self.results['files'] = filelist
        else:
            self.results = None

        return True
