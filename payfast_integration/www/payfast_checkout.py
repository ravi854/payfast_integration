import hashlib
import urllib.parse
import frappe
from frappe import _


PAYFAST_FIELD_ORDER = [
	"merchant_id",
	"merchant_key",
	"return_url",
	"cancel_url",
	"notify_url",
	"name_first",
	"name_last",
	"email_address",
	"cell_number",
	"m_payment_id",
	"amount",
	"item_name",
	"item_description",
	"custom_int1",
	"custom_int2",
	"custom_int3",
	"custom_int4",
	"custom_int5",
	"custom_str1",
	"custom_str2",
	"custom_str3",
	"custom_str4",
	"custom_str5",
	"email_confirmation",
	"confirmation_address",
	"payment_method",
]


def generate_signature(data: dict, passphrase: str = "") -> str:
	pairs = []
	for key in PAYFAST_FIELD_ORDER:
		val = str(data.get(key, "")).strip()
		if val != "":
			pairs.append(f"{key}={urllib.parse.quote_plus(val)}")

	payload_string = "&".join(pairs)
	if passphrase:
		payload_string += f"&passphrase={urllib.parse.quote_plus(passphrase.strip())}"

	return hashlib.md5(payload_string.encode("utf-8")).hexdigest()


def get_context(context):
	request_id = frappe.form_dict.get("request_id")
	if not request_id:
		frappe.throw(_("Missing Payment Request ID"), frappe.ValidationError)

	ir = frappe.get_doc("Integration Request", request_id)
	if ir.status == "Completed":
		frappe.throw(_("This payment request has already been processed."))

	data = frappe.parse_json(ir.data)
	#settings = frappe.get_single("Payfast Settings")
	settings = frappe.get_doc("Payfast Settings", "Payfast")
	base_url = frappe.utils.get_url()

	payer_name = (data.get("payer_name") or "").strip().split(" ", 1)
	first_name = payer_name[0] if payer_name else ""
	last_name = payer_name[1] if len(payer_name) > 1 else ""

	payload = {
		"merchant_id": settings.merchant_id,
		"merchant_key": settings.merchant_key,
		"return_url": data.get("redirect_to") or f"{base_url}/payfast-success",
		"cancel_url": f"{base_url}/payment-cancel",
		"notify_url": f"{base_url}/api/method/payfast_integration.api.itn_webhook",
		"name_first": first_name,
		"name_last": last_name,
		"email_address": data.get("payer_email", ""),
		"m_payment_id": ir.name,
		"amount": f"{float(data.get('amount')):.2f}",
		"item_name": (data.get("description") or f"Payment {ir.name}")[:100],
		"custom_str1": data.get("reference_doctype", ""),
		"custom_str2": data.get("reference_docname", ""),
	}

	# Filter empty values while preserving exact order
	ordered_payload = {
		k: payload[k] for k in PAYFAST_FIELD_ORDER if str(payload.get(k, "")).strip() != ""
	}
	ordered_payload["signature"] = generate_signature(
		ordered_payload, settings.get_password("passphrase")
	)

	context.action_url = (
		"https://" + "sandbox.payfast.co.za/eng/process"
		if settings.sandbox
		else "https://" + "www.payfast.co.za/eng/process"
	)
	context.fields = ordered_payload
	context.no_cache = 1
