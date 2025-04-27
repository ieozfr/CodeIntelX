import pefile
import magic
from rich.console import Console

console = Console()

class LanguageDetector:
    def __init__(self):
        self.magic_obj = magic.Magic()

    def detect_language(self, file_path):
        try:
            file_type = self.magic_obj.from_file(file_path)
            if "PE32" in file_type or "PE32+" in file_type:
                detailed_lang = self.pe_language_detect(file_path, file_type)
                return detailed_lang
            return file_type
        except FileNotFoundError:
            console.print("[red][Hata][/red] Dosya bulunamadı.")
            return None

    def pe_language_detect(self, file_path, file_type):
        try:
            pe = pefile.PE(file_path)
            imported_dlls = [entry.dll.decode().lower() for entry in pe.DIRECTORY_ENTRY_IMPORT]

            # C# (.NET)
            if 'mscoree.dll' in imported_dlls or b'.NETFramework' in pe.__data__:
                return file_type + " (C# / .NET)"

            # Visual C++ (MSVC)
            msvc_indicators = ['msvcrt.dll', 'msvcp140.dll', 'vcruntime140.dll', 'ucrtbase.dll']
            if any(dll in imported_dlls for dll in msvc_indicators):
                return file_type + " (C++ / MSVC)"

            # Delphi
            if 'rtl' in imported_dlls or 'vcl' in imported_dlls:
                return file_type + " (Delphi)"

            # GoLang
            if any(b'Go build ID' in sec.get_data() for sec in pe.sections):
                return file_type + " (Go)"

            # Rust
            if any(b'rust_eh_personality' in sec.get_data() for sec in pe.sections):
                return file_type + " (Rust)"

            # Python (PyInstaller)
            if any(b'PyInstaller' in sec.get_data() for sec in pe.sections):
                return file_type + " (Python / PyInstaller)"

            # Java (Launch4j veya diğer java wrapperlar)
            if 'jvm.dll' in imported_dlls or 'java.dll' in imported_dlls:
                return file_type + " (Java)"

            return file_type + " (Dil belirlenemedi)"
        except Exception as e:
            console.print(f"[red]PE analizi sırasında hata:[/red] {e}")
            return file_type + " (Analiz Hatası)"

if __name__ == "__main__":
    detector = LanguageDetector()
    file_path = input("Analiz edilecek dosya yolu: ")
    language = detector.detect_language(file_path)
    
    if language:
        console.print(f"[green]Dosya Türü ve Olası Dil:[/green] {language}")
