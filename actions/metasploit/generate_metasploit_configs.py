import os
import json

from pymetasploit3.msfrpc import MsfRpcClient
from tqdm import tqdm

def derive_class_name(parts: list) -> str:
    """Derive the class name for each exploit"""
    camelcase_exploit_name = "".join(part.capitalize() for part in parts[2].split("_"))
    return f"Msf{parts[0].capitalize()}{parts[1].capitalize()}{camelcase_exploit_name}Exploit"

def get_msf_client() -> MsfRpcClient:
    """Create and return an MsfRpcClient instance lazily"""
    password = os.environ.get("MSFRPCD_PASSWORD")
    port = int(os.environ.get("MSF_PORT", 55552))
    
    if not password:
        raise ValueError("MSFRPCD_PASSWORD environment variable is required")
    
    return MsfRpcClient(password, port=port)

known_options = {'RHOSTS', 'RHOST', 'RPORT', 'rhost', 'LHOST'}
def requires_only_known(module_name: str, exploit) -> bool:
    """Check if the module can be run when only specifying the host and port"""
    if exploit.default_options:
        return all(required in known_options or required in exploit.default_options for required in exploit.missing_required)
    return all(required in known_options for required in exploit.missing_required)

with open("missing_cves.json", "r") as f:
    missing_cves = json.load(f)
def get_cves(module_name: str, exploit) -> list:
    cves = ["-".join([x[0], str(x[1])]) for x in exploit.info["references"] if x[0] == "CVE"]
    if module_name in missing_cves:
        cves.extend(missing_cves[module_name])
    return cves

if __name__ == "__main__":
    """Generate all exploit actions dynamically"""
    msf_client = get_msf_client()

    success_count = 0
    missing_required = 0
    no_target = 0
    malformatted_name = 0
    configs = []

    main_bar = tqdm(msf_client.modules.exploits, desc=f"Generating Exploit Actions: ✓ {success_count} ✗t {no_target} ✗r {missing_required} ✗p {malformatted_name}", smoothing=0.01)

    for module_name in main_bar:
        parts = module_name.split("/")
        if len(parts) == 3:
            exploit = msf_client.modules.use("exploit", module_name)
            cves = get_cves(module_name, exploit)
            if len(cves):
                if requires_only_known(module_name, exploit):
                    class_name = derive_class_name(parts)
                    configs.append({
                        "name": class_name,
                        "module_name": module_name,
                        "cves": cves
                    })            
                    success_count += 1
                else:
                    # tqdm.write(f"Skipping {module_name} because it requires {set(exploit.missing_required) - set(known_options)}")
                    missing_required += 1
            else:
                # tqdm.write(f"Skipping {module_name} because we have no way to target it (no CVE in the metadata, no entry in missing_cves.json)")
                no_target += 1
        else:
            # tqdm.write(f"Skipping {module_name} because its name is malformatted (wrong number of parts)")
            malformatted_name += 1

        main_bar.set_description(f"Generating Exploit Actions: ✓ {success_count} ✗t {no_target} ✗r {missing_required} ✗p {malformatted_name}")
        main_bar.refresh()

    with open("msfconfigs.json", "w") as f:
        f.write(json.dumps(configs, indent=4))
