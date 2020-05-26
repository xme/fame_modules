import os
from shutil import copyfile

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir

from ..docker_utils import HAVE_DOCKER, docker_client

class ace(ProcessingModule):
    name = "ace"
    description = "Extract files from ACE archive."
    acts_on = "ace"

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

    def initialize(self):
        if not HAVE_DOCKER:
            raise ModuleInitializationError(self, "Missing dependency: docker")
        return True

    def save_output(self, output):
        for line in output.splitlines():
            if line.startswith('warning:'):
                self.results['warnings'].append(line.lstrip('warning: '))
            elif line.startswith('should_analyze:'):
                filepath = os.path.join(self.outdir, os.path.basename(line.lstrip('should_analyze: ')))
                if os.path.isfile(filepath):
                    self.add_extracted_file(filepath)
            else:
                self.log("debug", line)

    def extract(self, file):
        args = '{} {} {}'.format(
            file, self.maximum_extracted_files, self.maximum_automatic_analyses)

        # start the right docker
        return docker_client.containers.run(
            'fame/ace',
            args,
            volumes={self.outdir: {'bind': '/data', 'mode': 'rw'}},
            stderr=True,
            remove=True
        )

    def each(self, target):
        self.results = {
            'warnings': []
        }

        # Create temporary directory to get results
        self.outdir = tempdir()

        copyfile(target, os.path.join(self.outdir, "archive.ace"))
        target = "/data/archive.ace"

        # execute docker container
        output = self.extract(target)

        # save log output from dockerized app, extract potential redirections
        self.save_output(output)

        return True
