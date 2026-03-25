from flask import (
    Blueprint,
    render_template,
    url_for,
    current_app,
    session,
    redirect,
    jsonify,
    request,
)
import asyncio
from app.plugins.askar import AskarStorage
from .forms import CreateSchema

bp = Blueprint("wizard", __name__)


@bp.before_request
def before_request_callback():
    if not session.get("client_id"):
        session["client_id"] = "123"
        return redirect(url_for("wizard.intro"))


@bp.route("/intro")
def intro():
    return render_template("wizard/00_index.jinja")


@bp.route("/claims")
def claims():
    return render_template("wizard/01_claims.jinja")


@bp.route("/schema", methods=["GET", "POST"])
def schema():
    form = CreateSchema()
    form.enumeration_values.choices = [
        ("AB", "Alberta"),
        ("BC", "British Columbia"),
        ("MB", "Manitoba"),
        ("NB", "New Brunswick"),
        ("NL", "Newfoundland and Labrador"),
        ("NT", "Northwest Territories"),
        ("NS", "Nova Scotia"),
        ("NU", "Nunavut"),
        ("ON", "Ontario"),
        ("PE", "Prince Edward Island"),
        ("QC", "Quebec"),
        ("SK", "Saskatchewan"),
        ("YT", "Yukon"),
    ]
    if request.method == "POST":
        pass
    return render_template("wizard/02_schema.jinja", form=form)


@bp.route("/issuer")
def issuer():
    # if request.method == "POST":
    #     return render_template("issuer_json.jinja")
    return render_template("wizard/03_issuer.jinja")


# @bp.route("/issuer_json")
# def issuer_json():
#     return render_template("issuer_json.jinja")
@bp.route("/issue")
def issue():
    return render_template("wizard/04_issue.jinja")

# @bp.route("/credential")
# def credential():
#     if request.method == "POST":
#         pass
#     return render_template("credential.jinja")

# @bp.route("/statements")
# def statements():
#     if request.method == "POST":
#         pass
#     return render_template("statements.jinja")

@bp.route("/present")
def present():
    return render_template("wizard/05_present.jinja")

# @bp.route("/presentation_request")
# def presentation_request():
#     if request.method == "POST":
#         pass
#     return render_template("presentation_request.jinja")

@bp.route("/revoke")
def revoke():
    return render_template("wizard/06_revoke.jinja")

# @bp.route("/presentation")
# def presentation():
#     if request.method == "POST":
#         pass
#     return render_template("presentation.jinja")

@bp.route("/witness-update")
def witness_update():
    return render_template("wizard/07_witness_update.jinja")
