fixed_app.py 
Purpose: secure version of the same app.
Run only locally for testing: `pip install flask bleach` then `python fixed_app.py`

from flask import Flask, request, render_template_string, make_response, escape
import bleach

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Secure Demo</title>
  </head>
  <body>
    <h1>Search</h1>
    <form method="get" action="/">
      <input name="q" placeholder="type something" />
      <button type="submit">Search</button>
    </form>

    {% if q %}
      <h2>Results for: {{ q }}</h2>
      <p>Imagine these are results from a DB or backend.</p>
    {% endif %}
  </body>
</html>
"""

@app.after_request
def set_csp(response):
    # Simple Content Security Policy: don't allow inline scripts/styles
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'; object-src 'none';"
    return response

@app.route("/")
def index():
    raw_q = request.args.get("q", "")
    # 1) Use Bleach to sanitize any HTML the user may have provided (keeps safe text).
    #    Configure allowed tags/attributes as needed; here we allow none (text only).
    sanitized = bleach.clean(raw_q, tags=[], attributes={}, strip=True)
    # 2) As an extra layer, ensure Flask/Jinja escapes output (default behavior).
    safe_q = escape(sanitized)  # escape any remaining dangerous characters
    resp = make_response(render_template_string(TEMPLATE, q=safe_q))
    return resp

if __name__ == "__main__":
    app.run(debug=True, port=5001)
