import markdown
import pdfkit
from jinja2 import Template
from io import BytesIO
import tempfile
import os

def html_to_pretty_pdf(html_body: str, css_path: str = None, header_text: str | None = None, footer_text: str | None = None, page_number: bool = True) -> BytesIO:

    # Simple HTML template with embedded CSS
    html_template = """
    <html>
    <head>
        <meta charset="utf-8">
    </head>
    <body>
        <div class="content">
        {{ html_body | safe }}
        </div>
    </body>
    </html>
    """

    # Render the final HTML with embedded styling
    template = Template(html_template)
    html = template.render(html_body=html_body)

    # Configure wkhtmltopdf options for page numbering and layout
    options = {
        'page-size': 'A4',
        'margin-top': '0.75in',
        'margin-right': '0.75in',
        'margin-bottom': '0.75in',
        'margin-left': '0.75in',
        'encoding': "UTF-8",
        'no-outline': None,
        'enable-local-file-access': None
    }

    header_html = f"<div class='header'>{header_text}</div>" if header_text else ""
    footer_html = f"<div class='footer'>{footer_text}<br>Page [page] of [toPage]</div>" if footer_text and page_number else (
        f"<div class='footer'>{footer_text}</div>" if footer_text else (
            f"<div class='footer'>Page [page] of [toPage]</div>" if page_number else ""
        )
    )

    # Enable headers and footers
    if header_text:
        options['header-left'] = header_html
        options['header-font-size'] = '9'
        options['header-spacing'] = '5'
        options['margin-top'] = '1.0in'  # Increase top margin to make room for header

    if footer_html:
        options['footer-font-size'] = '9'
        options['footer-spacing'] = '5'
        options['margin-bottom'] = '1.0in'  # Increase bottom margin to make room for footer
        options['footer-center'] = footer_html

    with tempfile.NamedTemporaryFile(delete=True, suffix=".pdf") as temp_file:
        pdfkit.from_string(html, temp_file.name, options=options, css=css_path, verbose=True)
        temp_file.flush()

        with open(temp_file.name, "rb") as f:
            return BytesIO(f.read())
        
def rich_html(html_body: str, css_path: str | None = None, header_text: str | None = None, footer_text: str | None = None, page_number: bool = True) -> str:
    css_content = ""
    if css_path:
        with open(css_path, "r") as f:
            css_content = f.read()

    html_template = """
    <html>
    <head>
        {% if css_content %}
        <style>
        {{ css_content | safe }}
        </style>
        {% endif %}
        <meta charset="utf-8">
    </head>
    <body>
        {% if header_text %}
        <div class="header">
            {{ header_text | safe }}
        </div>
        {% endif %}
        <div class="content">
        {{ html_body | safe }}
        </div>
        {% if footer_text %}
        <div class="footer">
            {{ footer_text | safe }}
        </div>
        {% endif %}
    </body>
    </html>
    """

    # Render the final HTML with embedded styling
    template = Template(html_template)
    html = template.render(
        html_body=html_body, 
        css_content=css_content, 
        header_text=header_text, 
        footer_text=footer_text
    )
    return html

from abc import ABC, abstractmethod

class PdfComponent(ABC):
    @abstractmethod
    def render(self) -> str:
        pass
    
class PdfTitle(PdfComponent):
    def __init__(self, title: str) -> None:
        self.title = title

    def render(self) -> str:
        return f"<h1 style='text-align: center;'>{self.title}</h1>"

class PdfMarkDownBody(PdfComponent):
    def __init__(self, content: str) -> None:
        self.content = content

    def render(self) -> str:
        return f"<div class='markdown-body'>{markdown.markdown(self.content, extensions=['fenced_code', 'codehilite'])}</div>" 

class PdfFactory:
    def __init__(self, header_text: str | None = None, footer_text: str | None = None, page_number: bool = True) -> None:
        self.components: list[PdfComponent] = []
        self.header_text = header_text
        self.footer_text = footer_text
        self.page_number = page_number
 
    def add_component(self, component: PdfComponent) -> None:
        self.components.append(component)

    def render(self) -> str:
        return '\n'.join([
            component.render() 
            for component in self.components
        ])
    
    def to_pdf(self) -> BytesIO:
        css_path = os.path.join(os.path.dirname(__file__), 'assets', 'css', 'pdf-style.css')
        
        return html_to_pretty_pdf(
            self.render(), 
            css_path=css_path,
            header_text=self.header_text, 
            footer_text=self.footer_text, 
            page_number=self.page_number
        )

    def to_html(self) -> str:
        css_path = os.path.join(os.path.dirname(__file__), 'assets', 'css', 'pdf-style.css')
        
        return rich_html(
            self.render(),
            css_path=css_path,
            header_text=self.header_text, 
            footer_text=self.footer_text, 
            page_number=self.page_number
        )