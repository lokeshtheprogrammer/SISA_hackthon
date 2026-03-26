import io
from typing import Tuple, Optional, Any
from core.file_ingestor import FileIngestor

class InputRouter:
    """
    Responsibilities:
    - Route based on input_type (text, log, chat, sql, file, doc)
    - Handle Docx/PDF extraction using FileIngestor
    - Return processed_text and itype
    """
    
    VALID_INPUT_TYPES = {"text", "log", "chat", "sql", "file", "doc", "pdf"}

    def __init__(self):
        self.ingestor = FileIngestor()

    def route_input(self, input_type: str, content: Any, source: str = "unknown") -> Tuple[str, str, str]:
        """
        Routes and processes input accordingly.
        Returns: (processed_text, itype, source)
        """
        itype = input_type.lower() if input_type else "text"
        
        # 1. DOCX/PDF Handling (if bytes provided)
        if itype in ["doc", "docx", "pdf"] and isinstance(content, bytes):
            try:
                processed = self.ingestor.process(content, itype)
                return processed, itype, source
            except Exception as e:
                return f"[File Extraction Error: {e}]", "error", source

        # 2. String processing for other types
        if isinstance(content, bytes):
            try:
                processed = content.decode("utf-8", errors="replace")
            except:
                processed = str(content)
        else:
            processed = str(content)

        # Basic identity logic
        if itype not in self.VALID_INPUT_TYPES:
            itype = "text" # Fallback

        return processed, itype, source

    def route_json(self, itype: str, content: str, source: str = "json_body") -> Tuple[str, str, str]:
        """Helper for JSON-based input."""
        return self.route_input(itype, content, source)

    async def route_upload(self, file_obj: Any) -> Tuple[str, str, str]:
        """Helper for File Uploads (multipart)."""
        filename = getattr(file_obj, "filename", "uploaded_file")
        content = await file_obj.read()
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        
        if ext in ["docx", "doc"]:
            return self.route_input("doc", content, source=filename)
        elif ext == "pdf":
            return self.route_input("pdf", content, source=filename)
        elif ext == "log":
            return self.route_input("log", content, source=filename)
        elif ext == "sql":
            return self.route_input("sql", content, source=filename)
        else:
            return self.route_input("text", content, source=filename)

    def _heuristic_type(self, text: str, current: str) -> str:
        """Guess type if text seems like SQL or logs."""
        if current != "text": return current
        
        up = text.upper()
        if "SELECT" in up and "FROM" in up: return "sql"
        if "INSERT" in up and "INTO" in up: return "sql"
        
        # Log heuristic: Starts with date pattern
        if any(text[:10].startswith(str(y)) for y in range(1990, 2030)):
            return "log"
            
        return "text"
