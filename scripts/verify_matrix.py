"""Developer harness: recreate modes, run the HTTP attacker and preserve evidence.

This command resets the generated lab data. The attacker script receives only
the client's credentials; this harness never supplies operator IDs or secrets.
Requires only Python's standard library and Docker Compose on the host.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ("VULN_A01", "VULN_A07", "VULN_A05", "VULN_A10")
CASES = [("vulnerable", None, None), ("fix-a01", "VULN_A01", "T1"),
         ("fix-a07", "VULN_A07", "T2"), ("fix-a05", "VULN_A05", "T3"),
         ("fix-a10", "VULN_A10", "T4"), ("fixed", "all", "T1")]


def compose(args, env, capture=False, check=True):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, env=env,
                          text=True, encoding="utf-8", capture_output=capture, check=check)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    original_env = os.environ.copy()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = ROOT / "evidence" / f"matrix-{run_id}"
    output.mkdir(parents=True, exist_ok=False)
    outcomes = []
    try:
        if not args.skip_build:
            compose(["build"], original_env)
        for name, corrected, stop in CASES:
            env = {**original_env, "LAB_MODE": "1", "APP_DATA_DIR": "/data",
                   **{flag: "0" if corrected in (flag, "all") else "1" for flag in FLAGS}}
            print(f"\nVerificando {name}...", flush=True)
            compose(["up", "-d", "--force-recreate", "--wait"], env)
            compose(["exec", "-T", "web", "flask", "--app", "app", "lab", "reset"], env)
            # Only the initial client credentials leave the initialization step.
            credentials = json.loads(compose(["exec", "-T", "web", "flask", "--app", "app", "lab", "credentials"], env, capture=True).stdout)
            env["LAB_CLIENT_PASSWORD"] = credentials["password"]
            container_output = f"/data/evidence/matrix-{run_id}/{name}"
            command = ["exec", "-T", "-e", "LAB_CLIENT_PASSWORD", "web", "python", "scripts/demo_chain.py",
                       "--username", credentials["username"], "--output", container_output]
            if stop:
                command.extend(["--expect-stop", stop])
            execution = compose(command, env, capture=True, check=False)
            print(execution.stdout, flush=True)
            destination = output / name
            compose(["cp", f"web:{container_output}", str(destination)], env)
            report_path = next(destination.glob("*/report.json"))
            report = json.loads(report_path.read_text(encoding="utf-8"))
            outcomes.append({"case": name, "passed": execution.returncode == 0,
                             "outcome": report["outcome"], "stage": report.get("stage"),
                             "report": str(report_path.relative_to(output))})
            if execution.returncode:
                raise RuntimeError(f"La verificación {name} falló; ver {report_path}.")
    finally:
        (output / "summary.json").write_text(json.dumps(outcomes, indent=2) + "\n", encoding="utf-8")
        print("Restaurando la configuración original y una semilla limpia...", flush=True)
        compose(["up", "-d", "--force-recreate", "--wait"], original_env)
        compose(["exec", "-T", "web", "flask", "--app", "app", "lab", "reset"], original_env)
    print(f"Matriz verificada: {len(outcomes)}/{len(CASES)}. Evidencias: {output}")


if __name__ == "__main__":
    main()
