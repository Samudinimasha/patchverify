# PatchVerify

Verify whether a software update actually fixed what it promised.

## Installation

### From GitHub (Like Nmap)

```bash
# 1. Clone the repository
git clone https://github.com/Samudinimasha/patchverify.git
cd patchverify

# 2. Run the installation script
chmod +x install.sh
./install.sh

# 3. Activate the virtual environment
source .venv/bin/activate

# 4. Run PatchVerify (setup will auto-prompt on first use)
patchverify --help
```

### Optional: Create a System-Wide Alias

Add this to your `~/.zshrc` or `~/.bashrc`:

```bash
alias patchverify='source /path/to/patchverify/.venv/bin/activate && patchverify'
```

Then reload your shell:
```bash
source ~/.zshrc  # or source ~/.bashrc
```

Now you can run `patchverify` from anywhere!

## Quick Start

On first run, you'll be prompted to enter your email for device registration:

```bash
# Scan a package (setup will auto-run if needed)
patchverify --app nessus --old 10.5.0 --new 10.6.0
```

## Usage

```bash
# Scan software for patch verification
patchverify --app django --old 4.1.0 --new 4.2.0

# Scan Nessus
patchverify --app nessus --old 10.5.0 --new 10.6.0

# Skip behavioral probing (faster)
patchverify --app requests --old 2.28.0 --new 2.31.0 --no-probe

# Get JSON output
patchverify --app pillow --old 9.5.0 --new 10.0.0 --json

# View scan history
patchverify --history

# Start web dashboard
patchverify --serve

# Manual setup (optional - auto-runs on first use)
patchverify --setup
```

## Examples

```bash
# Check if Nessus patch fixed vulnerabilities
patchverify --app nessus --old 10.5.0 --new 10.6.0

# Verify Django security updates
patchverify --app django --old 4.1.0 --new 4.2.0 --json

# Quick scan without behavioral testing
patchverify --app flask --old 2.0.0 --new 3.0.0 --no-probe
```

## Requirements

- Python 3.8+
- pip
- Internet connection for package scanning

## Features

- 🔍 Verify patch effectiveness
- 📊 Risk scoring and analysis
- 📧 Email notifications
- 📈 Scan history tracking
- 🌐 Web dashboard (coming soon)
- 🔬 Behavioral probing (coming soon)

## License

MIT License
