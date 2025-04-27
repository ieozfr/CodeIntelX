import pefile
import math
from rich.console import Console

console = Console()

class EncryptionDetector:
    def calculate_entropy(self, data):
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return entropy

    def analyze_file(self, file_path):
        try:
            pe = pefile.PE(file_path)
            entropies = []

            for section in pe.sections:
                entropy = self.calculate_entropy(section.get_data())
                entropies.append((section.Name.decode(errors='ignore').strip('\x00'), entropy))

            average_entropy = sum(e for _, e in entropies) / len(entropies)
            packed_suspected = average_entropy > 7.2

            return {
                "entropies": entropies,
                "average_entropy": average_entropy,
                "packed_suspected": packed_suspected,
                "packer_detected": self.detect_packer(pe)
            }
        except Exception as e:
            console.print(f"[red]Şifreleme algılama hatası:[/red] {e}")
            return None

    def detect_packer(self, pe):
        packer_signatures = {
            "UPX": ["UPX0", "UPX1", "UPX2"],
            "ASProtect": [".aspack", ".adata"],
            "Themida": [".themida"],
            "NSPack": [".nsp1", ".nsp0"],
        }

        found_packers = []

        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            for packer, indicators in packer_signatures.items():
                if name in indicators:
                    found_packers.append(packer)

        return found_packers
