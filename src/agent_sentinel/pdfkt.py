import markdown
import pdfkit
from jinja2 import Template
from io import BytesIO
import tempfile

def markdown_to_pretty_pdf(markdown_text: str, css_path: str = None) -> BytesIO:
    # Convert markdown to HTML
    html_body = markdown.markdown(markdown_text, extensions=['fenced_code', 'codehilite'])

    # Simple HTML template with optional CSS
    html_template = """
    <html>
    <head>
        <meta charset="utf-8">
        {% if css_path %}
        <link rel="stylesheet" href="{{ css_path }}">
        {% endif %}
    </head>
    <body>
        <div class="content">
        {{ html_body | safe }}
        </div>
    </body>
    </html>
    """

    # Render the final HTML with optional styling
    template = Template(html_template)
    html = template.render(html_body=html_body, css_path=css_path)

    with tempfile.NamedTemporaryFile(delete=True, suffix=".pdf") as temp_file:
        pdfkit.from_string(html, temp_file.name)
        temp_file.flush()

        with open(temp_file.name, "rb") as f:
            return BytesIO(f.read())