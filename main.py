# Simple log analyzer that looks for possible brute-force behavior.
# It counts failed logins per IP and detects suspicious patterns.


def read_log_file():
    """
    Reads the log file and returns all lines.
    """
    with open("sample_log.txt", "r", encoding="utf-8") as f:
        return f.readlines()


def analyze_log(lines):
    """
    Analyzes the log lines.
    - Counts failed attempts per IP
    - Tracks if an IP eventually logs in successfully after failures
    """
    failed_counts = {}
    success_after_fail = set()

    for line in lines:
        line = line.strip()
        parts = line.split()

        if len(parts) < 4:
            continue  # Skip malformed lines

        ip = parts[2]

        if "LOGIN FAILED" in line:
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

        elif "LOGIN SUCCESS" in line:
            # If IP had previous failures and now succeeds
            if ip in failed_counts and failed_counts[ip] > 0:
                success_after_fail.add(ip)

    return failed_counts, success_after_fail


def generate_report(failed_counts, success_after_fail, threshold):
    """
    Prints a structured security report.
    """
    print("\n=== Login Failure Report ===\n")

    if not failed_counts:
        print("No failed login attempts found.")
        return

    # Sort IPs by number of failures (highest first)
    sorted_ips = sorted(failed_counts.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips:
        if count >= threshold:
            print(f"[ALERT] {ip} triggered {count} failed attempts.")

            if ip in success_after_fail:
                print(f"        → This IP later logged in successfully (possible compromise).")

        else:
            print(f"{ip} had {count} failed attempts.")

    print("\nReport complete.\n")


def main():
    print("Simple Log Analyzer\n")

    try:
        threshold = int(input("Enter failure threshold: "))
    except ValueError:
        print("Invalid input. Using default threshold = 3.")
        threshold = 3

    lines = read_log_file()
    failed_counts, success_after_fail = analyze_log(lines)
    generate_report(failed_counts, success_after_fail, threshold)


if __name__ == "__main__":
    main()
