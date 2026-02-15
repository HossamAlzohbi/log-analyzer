# Simple Log Analyzer

This is a small Python project that simulates basic log analysis in a SOC-style scenario.

The script reads a login log file, counts failed login attempts per IP address, and highlights suspicious activity based on a chosen threshold.

## What this project demonstrates

- Reading and parsing log files
- Counting failed login attempts
- Detecting repeated failures from the same IP
- Identifying cases where an IP fails multiple times and later logs in successfully
- Structuring Python code using functions

The goal is not to build a full SIEM, but to demonstrate understanding of basic detection logic.

## How it works

1. The script reads `sample_log.txt`
2. It counts failed login attempts per IP
3. It checks if an IP later logs in successfully after multiple failures
4. It generates a simple security report sorted by number of failures

## How to run

Make sure Python 3 is installed.

Run:

python main.py

You will be asked to enter a failure threshold.

## Project Structure

log_analyzer/
│
├── main.py
├── sample_log.txt
└── README.md

## Possible future improvements

- Add time-based detection (e.g., 5 failures within 1 minute)
- Support real-world log formats
- Export the report to a file
- Integrate basic IP reputation checking
