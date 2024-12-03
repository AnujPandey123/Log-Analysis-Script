import re
import csv
from collections import Counter, defaultdict

# Constants for file paths and thresholds
LOG_FILE = "sample.log"  # The log file to analyze
OUTPUT_CSV = "log_analysis_results.csv"  # Output file for saving the results
FAILED_LOGIN_THRESHOLD = 10  # Threshold for flagging suspicious login attempts

def parse_log_file(file_path):
    """
    Parses the log file to extract IP addresses, endpoints, and failed login attempts.

    Args:
        file_path (str): The path to the log file.

    Returns:
        tuple: Three dictionaries containing:
            - IP address request counts.
            - Endpoint access counts.
            - IPs with failed login attempts.
    """
    ip_requests = Counter()
    endpoint_access = Counter()
    failed_logins = defaultdict(int)

    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Use regex to extract IP, endpoint, and HTTP status code
                match = re.match(r'(\d+\.\d+\.\d+\.\d+).*?"\w+ (/[\w/]+).*?" (\d+)', line)
                if match:
                    ip, endpoint, status_code = match.groups()
                    ip_requests[ip] += 1  # Increment request count for the IP
                    endpoint_access[endpoint] += 1  # Increment access count for the endpoint
                    if status_code == "401":  # Detect failed login attempts
                        failed_logins[ip] += 1
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
        return {}, {}, {}

    return ip_requests, endpoint_access, failed_logins


def find_most_accessed_endpoint(endpoint_access):
    """
    Identifies the most frequently accessed endpoint.

    Args:
        endpoint_access (Counter): Dictionary of endpoint access counts.

    Returns:
        tuple: The most accessed endpoint and its access count.
    """
    return endpoint_access.most_common(1)[0] if endpoint_access else ("None", 0)


def detect_suspicious_activity(failed_logins):
    """
    Flags IPs with failed login attempts exceeding a defined threshold.

    Args:
        failed_logins (dict): Dictionary of IPs and their failed login attempt counts.

    Returns:
        dict: IPs with failed login attempts above the threshold.
    """
    return {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}


def save_to_csv(sorted_ip_requests, most_accessed, suspicious_ips):
    """
    Saves the analysis results to a CSV file.

    Args:
        sorted_ip_requests (list): List of tuples with IP addresses and request counts.
        most_accessed (tuple): The most accessed endpoint and its count.
        suspicious_ips (dict): Suspicious IPs and their failed login counts.
    """
    try:
        with open(OUTPUT_CSV, 'w', newline='') as file:
            writer = csv.writer(file)

            # Write IP request counts
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in sorted_ip_requests:
                writer.writerow([ip, count])
            writer.writerow([])  # Blank line for separation

            # Write most accessed endpoint
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed[0], most_accessed[1]])
            writer.writerow([])

            # Write suspicious activity
            writer.writerow(["Suspicious Activity Detected"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
    except Exception as e:
        print(f"Error writing to CSV: {e}")


def display_results(sorted_ip_requests, most_accessed, suspicious_ips):
    """
    Displays the analysis results in the terminal.

    Args:
        sorted_ip_requests (list): List of tuples with IP addresses and request counts.
        most_accessed (tuple): The most accessed endpoint and its count.
        suspicious_ips (dict): Suspicious IPs and their failed login counts.
    """
    print("\nIP Address Request Counts:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<25}")
    else:
        print("No suspicious activity detected.")


def main():
    """
    Main function to perform log analysis and display/save results.
    """
    print("Starting log analysis...")

    # Parse the log file
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)
    if not ip_requests:
        print("No data to analyze. Exiting.")
        return

    # Sort IP request counts in descending order
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

    # Identify the most accessed endpoint
    most_accessed = find_most_accessed_endpoint(endpoint_access)

    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(failed_logins)

    # Display results
    display_results(sorted_ip_requests, most_accessed, suspicious_ips)

    # Save results to CSV
    save_to_csv(sorted_ip_requests, most_accessed, suspicious_ips)
    print(f"\nAnalysis complete. Results saved to '{OUTPUT_CSV}'.")


if __name__ == "__main__":
    main()
