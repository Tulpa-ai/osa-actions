from pathlib import Path
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from kg_api import Entity, GraphDB, MultiPattern, Pattern
from action_state_interface.action_utils import shell
from Session import SessionManager

def cmd_fetch_file_http(download_url, savepath):
    if not savepath.exists():
        shell(
            "curl",
            [
                "-v",
                "-s",
                "--output",
                savepath.as_posix(),
                download_url,
            ],
        )

def cmd_get_file_info(filepath) -> tuple[str, str]:
    fileinfo = shell("file", ["-b", "--mime", filepath.as_posix()])
    mime_type, mime_encoding = [x.strip() for x in fileinfo.split(";")]
    return mime_type, mime_encoding

class HttpDownloadFile(Action):
    def __init__(self):
        super().__init__("HttpDownloadFile", "T1567 Exfiltration Over Web Service", "TA0010 Exfiltration", ["quiet", "fast"])
        self.noise = 0
        self.impact = 0.02

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        return [f"Gain knowledge to gain access to {pattern.get('asset').get('ip_address')}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        asset = Entity('Asset', alias='asset')
        port = Entity('OpenPort', alias='port')
        service = Entity('Service', alias='service', protocol='http')
        drive = Entity('Drive', alias='drive')
        directory = Entity('Directory', alias='directory', dirname='database')
        file = Entity('File', alias='file')
        pattern = asset.points_to(port).points_to(service).points_to(drive).points_to(directory).points_to(file)
        return kg.get_matching(pattern)

    def function(self, sessions: SessionManager, pattern: Pattern) -> tuple[str, str]:
        port = pattern.get('port')
        drive = pattern.get('drive')
        directory = pattern.get('directory')
        file = pattern.get('file')
        download_url = f"{drive.get('location').lower()}:{port.get('number')}/{directory.get('dirname')}"
        save_path = Path('..') / Path(file.get('uuid'))
        cmd_fetch_file_http(download_url, save_path)
        mime_type, mime_encoding = cmd_get_file_info(save_path)
        return mime_type, mime_encoding

    def capture_state_change(self, kg: GraphDB, pattern: Pattern, output: tuple[str, str]) -> StateChangeSequence:
        file = pattern.get('file')
        mime_type, mime_encoding = output
        new_file = file.copy()
        new_file.set('mime_type', mime_type)
        new_file.set('mime_encoding', mime_encoding)
        new_file.set('downloaded', True)
        changes: StateChangeSequence = [(pattern, "update", new_file)]
        return changes