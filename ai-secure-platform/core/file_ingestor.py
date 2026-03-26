import io
import pdfplumber
from docx import Document

class FileIngestor:
    """
    Handles PDF and DOCX extraction with clean text normalization.
    """

    @staticmethod
    def extract_docx(content: bytes) -> str:
        """Extract clean text from DOCX."""
        try:
            doc = Document(io.BytesIO(content))
            lines = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
            return "\n".join(lines)
        except Exception as e:
            raise ValueError(f"DOCX extraction failed: {str(e)}")

    @staticmethod
    def extract_pdf(content: bytes) -> str:
        """Extract clean text from PDF using pdfplumber."""
        try:
            text = ""
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                for page in pdf.pages:
                    extracted = page.extract_text()
                    if extracted:
                        text += extracted + "\n"
            return text.strip()
        except Exception as e:
            raise ValueError(f"PDF extraction failed: {str(e)}")

    def process(self, content: bytes, extension: str) -> str:
        """Route to appropriate extractor based on extension."""
        ext = extension.lower().strip(".")
        if ext == "docx":
            return self.extract_docx(content)
        elif ext == "pdf":
            return self.extract_pdf(content)
        else:
            try:
                # Fallback to UTF-8 decoding
                return content.decode("utf-8", errors="ignore")
            except:
                return f"[Unsupported file format: {ext}]"
