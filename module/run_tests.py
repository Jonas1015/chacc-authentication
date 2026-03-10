#!/usr/bin/env python3
"""
Script to run tests and development tools for the authentication module.
"""
import subprocess
import sys
import os
import argparse


def setup_venv():
    """Setup virtual environment if it doesn't exist."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    venv_path = os.path.join(project_root, ".venv")
    if not os.path.exists(venv_path):
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)

    # Activate and install dependencies
    activate_script = os.path.join(venv_path, "bin", "activate") if os.name != 'nt' else os.path.join(venv_path, "Scripts", "activate.bat")
    pip_path = os.path.join(venv_path, "bin", "pip") if os.name != 'nt' else os.path.join(venv_path, "Scripts", "pip.exe")

    print("Installing dependencies...")
    subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)
    subprocess.run([pip_path, "install", "pytest", "fastapi", "uvicorn"], check=True)

    return venv_path


def run_tests(venv_path=None):
    """Run the module tests."""
    module_dir = os.path.dirname(__file__)
    tests_dir = os.path.join(module_dir, "tests")

    # Use venv python if available
    python_exe = sys.executable
    if venv_path:
        python_exe = os.path.join(venv_path, "bin", "python") if os.name != 'nt' else os.path.join(venv_path, "Scripts", "python.exe")

    try:
        # Run pytest
        result = subprocess.run([
            python_exe, "-m", "pytest",
            os.path.join(tests_dir, "test_module.py"),
            "-v", "--tb=short"
        ], cwd=module_dir)

        return result.returncode == 0

    except Exception as e:
        print(f"Error running tests: {e}")
        return False


def run_standalone(venv_path=None):
    """Run the module in ChaCC server for development."""
    python_exe = sys.executable
    if venv_path:
        python_exe = os.path.join(venv_path, "bin", "python") if os.name != 'nt' else os.path.join(venv_path, "Scripts", "python.exe")

    try:
        # Run ChaCC server with this module
        module_dir = os.path.dirname(os.path.dirname(__file__))  # plugins/module_name
        plugins_dir = os.path.dirname(module_dir)  # plugins

        subprocess.run([
            python_exe, "-m", "chacc_cli", "server",
            "--modules-dir", plugins_dir,
            "--host", "0.0.0.0",
            "--port", "8000",
            "--debug", "--auto-reload"
        ], cwd=os.path.dirname(__file__))
    except KeyboardInterrupt:
        print("\nShutting down ChaCC server...")


def main():
    parser = argparse.ArgumentParser(description="Authentication Module Development Tools")
    parser.add_argument("command", choices=["test", "standalone", "setup"], help="Command to run")
    parser.add_argument("--no-venv", action="store_true", help="Don't use virtual environment")

    args = parser.parse_args()

    venv_path = None
    if not args.no_venv:
        venv_path = setup_venv()

    if args.command == "test":
        success = run_tests(venv_path)
        sys.exit(0 if success else 1)
    elif args.command == "standalone":
        run_standalone(venv_path)
    elif args.command == "setup":
        print("Setup complete!")


if __name__ == "__main__":
    main()