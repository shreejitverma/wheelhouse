#!/usr/bin/env python3

import os
import shutil
import sys

from nl_readonly_search import verify_public_clone_claims


def capture_public_clone_provenance(task_path, claims_path, runner_temp=None):
    configured_root = runner_temp or os.environ.get("RUNNER_TEMP", "")
    if not configured_root:
        raise ValueError("RUNNER_TEMP is invalid")
    root = os.path.realpath(configured_root)
    if root == os.path.sep:
        raise ValueError("RUNNER_TEMP is invalid")
    output_dir = os.path.join(root, "wheelhouse-model-output")
    if os.path.lexists(output_dir):
        if os.path.isdir(output_dir) and not os.path.islink(output_dir):
            shutil.rmtree(output_dir)
        else:
            os.unlink(output_dir)
    os.mkdir(output_dir, mode=0o700)
    verify_public_clone_claims(
        task_path,
        claims_path,
        os.path.join(output_dir, "public-clone-provenance.json"),
    )


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: public_clone_provenance.py TASK_PATH CLAIMS_PATH")
    try:
        capture_public_clone_provenance(sys.argv[1], sys.argv[2])
    except Exception as error:
        print(
            "::warning::wheelhouse public-clone provenance unverified: %s: %s"
            % (type(error).__name__, error),
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
