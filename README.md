
# Log Analysis Script

## Made by: Anuj Pandey

## Project Overview

This script analyzes web server log files to extract meaningful insights such as:
- Counting the number of requests made by each IP address.
- Identifying the most frequently accessed endpoint.
- Detecting suspicious activity, such as potential brute force login attempts.

The results are presented in a user-friendly terminal output and are also saved to a CSV file for further analysis.

---

## What You Did

### Contributions:
- **Defined the Core Requirements**:
  - Counting requests per IP address.
  - Identifying the most accessed endpoint.
  - Detecting suspicious login attempts.
- **Provided a Sample Log File**:
  - Offered realistic log data for testing and validation.
- **Outlined Expected Output**:
  - Detailed output examples for terminal and CSV formats.

---

## Features

1. **Count Requests per IP Address**:
   - Extracts and counts requests for each unique IP in the log file.
   - Results are sorted by the highest request count.

2. **Identify Most Accessed Endpoint**:
   - Analyzes log entries to determine the most frequently accessed endpoint.

3. **Detect Suspicious Activity**:
   - Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).

4. **Output Results**:
   - Results are displayed in the terminal for immediate review.
   - Data is saved to a CSV file named `log_analysis_results.csv`.

---

## Requirements

- Python 3.6 or later
- A web server log file (e.g., Apache or Nginx format).

---

## Usage

1. **Prepare the log file**:
   Save your log file in the same directory as the script. By default, the script expects a file named `sample.log`.

2. **Run the script**:
   Execute the script using:
   ```bash
   python log_analysis.py
   ```

3. **View results**:
   - Results will be displayed in the terminal.
   - A CSV file `log_analysis_results.csv` will be generated in the same directory.

---

## Output Format

### Terminal Output
```bash
IP Address Request Counts:
192.168.1.1          10
203.0.113.5          8

Most Frequently Accessed Endpoint:
/home (Accessed 15 times)

Suspicious Activity Detected:
192.168.1.100        20
```

### CSV File Structure
#### Requests per IP
| IP Address      | Request Count |
|------------------|---------------|
| 192.168.1.1      | 10            |
| 203.0.113.5      | 8             |

#### Most Accessed Endpoint
| Endpoint   | Access Count |
|------------|--------------|
| /home      | 15           |

#### Suspicious Activity
| IP Address      | Failed Login Count |
|------------------|--------------------|
| 192.168.1.100    | 20                 |

---

## How It Works

1. **Parsing Logs**:
   - Uses regular expressions to extract key data like IP addresses, endpoints, and HTTP status codes from each log entry.

2. **Data Analysis**:
   - Counts requests per IP and endpoint accesses using Python's `collections.Counter`.
   - Identifies suspicious activity by flagging excessive failed login attempts.

3. **Results Output**:
   - Outputs results in an organized format to the terminal.
   - Saves all data to a structured CSV file.

---

## Notes

- Ensure the log file adheres to standard web server log formats (e.g., Apache or Nginx).
- The script is modular and can be extended to include additional analysis metrics.

---

## License

This project is released under the MIT License.
