import json
import subprocess


def _record(state_dir, record, broker_executable):
    result = subprocess.run(
        [
            "sudo",
            "-n",
            broker_executable,
            "provenance-record-root",
            state_dir,
        ],
        input=json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise ValueError("trusted public clone provenance recording failed")


def inspect_with_escalation(
    clone,
    state_dir,
    url,
    requested_ref,
    broker_executable="wheelhouse-search",
):
    try:
        output = clone()
        result = json.loads(output)
        _record(
            state_dir,
            {
                "status": "succeeded",
                "source": {
                    "url": result["url"],
                    "requestedRef": requested_ref,
                    "resolvedCommit": result["commit"],
                },
                "manifest": result["manifest"],
                "failure": None,
            },
            broker_executable,
        )
        return output
    except Exception as error:
        _record(
            state_dir,
            {
                "status": "failed",
                "source": {
                    "url": url,
                    "requestedRef": requested_ref,
                    "resolvedCommit": None,
                },
                "manifest": None,
                "failure": type(error).__name__,
            },
            broker_executable,
        )
        raise
