import hashlib
import ipaddress
import socket
import urllib.parse
import requests
import frappe


PAYFAST_HOSTS = (
	"www.payfast.co.za",
	"sandbox.payfast.co.za",
	"w1w.payfast.co.za",
	"w2w.payfast.co.za",
	"ips.payfast.co.za",
	"api.payfast.co.za",
	"api.payfast.io",
)

PAYFAST_CIDRS = (
	"197.97.145.144/28",
	"41.74.179.192/27",
	"102.216.36.0/28",
	"102.216.36.128/28",
	"144.126.193.139/32",
	"3.163.232.0/19",
)


def get_valid_payfast_ips() -> set[str]:
	cache_key = "payfast_resolved_ips_v2"
	cached_ips = frappe.cache.get_value(cache_key)
	if cached_ips:
		return set(cached_ips)

	resolved_ips = set()
	for host in PAYFAST_HOSTS:
		try:
			addr_info = socket.getaddrinfo(host, None)
			for info in addr_info:
				resolved_ips.add(info[4][0])
		except socket.gaierror:
			continue

	if resolved_ips:
		frappe.cache.set_value(cache_key, list(resolved_ips), expires_in_sec=3600)

	return resolved_ips


def is_valid_payfast_source_ip(client_ip: str) -> bool:
	if not client_ip:
		return False

	try:
		ip_obj = ipaddress.ip_address(client_ip.strip())
	except ValueError:
		return False

	# 1. Check against Payfast's published static CIDR ranges
	for cidr in PAYFAST_CIDRS:
		if ip_obj in ipaddress.ip_network(cidr, strict=False):
			return True

	# 2. Check against dynamically resolved Payfast DNS A records
	return str(ip_obj) in get_valid_payfast_ips()


@frappe.whitelist(allow_guest=True)
def itn_webhook():
	if frappe.request.method != "POST":
		return "OK"
	#settings = frappe.get_single("Payfast Settings")
	settings = frappe.get_doc("Payfast Settings", "Payfast")
	client_ip = frappe.local.request_ip

	# 0. Source IP Whitelist Check
	if settings.enforce_ip_whitelist and not is_valid_payfast_source_ip(client_ip):
		frappe.log_error(
			title="Payfast ITN Unauthorized Source IP",
			message=f"Rejected ITN request from IP: {client_ip}",
		)
		frappe.throw("Unauthorized source IP address", frappe.PermissionError)

	post_data = frappe.request.form.to_dict()
	if settings.debug_log:
		frappe.log_error(
			title="Payfast ITN Incoming Payload",
			message=f"Source IP: {client_ip}\n{frappe.as_json(post_data)}",
		)

	received_signature = post_data.pop("signature", "")
	post_data.pop("cmd", None)

	# 1. Verify MD5 Signature using incoming parameter order
	pairs = [
		f"{k}={urllib.parse.quote_plus(str(v).strip())}"
		for k, v in post_data.items()
	]
	passphrase = settings.get_password("passphrase")
	if passphrase:
		pairs.append(f"passphrase={urllib.parse.quote_plus(passphrase.strip())}")

	expected_signature = hashlib.md5("&".join(pairs).encode("utf-8")).hexdigest()
	if received_signature != expected_signature:
		frappe.log_error(
			title="Payfast ITN Signature Mismatch",
			message=f"Payload: {'&'.join(pairs)}\nExpected: {expected_signature}\nReceived: {received_signature}",
		)
		frappe.throw("Invalid Payfast ITN signature", frappe.AuthenticationError)

	# 2. Server-to-Server Validation against Payfast
	validate_url = (
		"https://" + "sandbox.payfast.co.za/eng/query/validate"
		if settings.sandbox
		else "https://" + "www.payfast.co.za/eng/query/validate"
	)
	response = requests.post(validate_url, data=post_data, timeout=15)
	if response.text.strip() != "VALID":
		frappe.log_error(
			title="Payfast ITN Validation Failed",
			message=f"Response: {response.text}",
		)
		frappe.throw("Payfast ITN validation failed")

	# 3. Load Integration Request & Enforce Idempotency
	ir_name = post_data.get("m_payment_id")
	ir = frappe.get_doc("Integration Request", ir_name)

	if ir.status == "Completed":
		return "OK"

	ir_data = frappe.parse_json(ir.data)
	expected_amount = f"{float(ir_data.get('amount')):.2f}"
	received_amount = f"{float(post_data.get('amount_gross', 0)):.2f}"

	if (
		post_data.get("payment_status") != "COMPLETE"
		or received_amount != expected_amount
	):
		ir.db_set("status", "Failed")
		ir.db_set("error", frappe.as_json(post_data))
		frappe.db.commit()
		return "FAILED"

	# 4. Authorize Reference Document in ERPNext as Administrator
	original_user = frappe.session.user
	try:
		frappe.set_user("Administrator")
		ref_doctype = (
			ir.reference_doctype
			or ir_data.get("reference_doctype")
			or post_data.get("custom_str1")
		)
		ref_docname = (
			ir.reference_docname
			or ir_data.get("reference_docname")
			or post_data.get("custom_str2")
		)

		if not ref_doctype or not ref_docname:
			frappe.throw(
				f"Missing reference document on Integration Request {ir.name}"
			)

		ref_doc = frappe.get_doc(ref_doctype, ref_docname)
		ref_doc.run_method("on_payment_authorized", "Completed")

		ir.db_set("status", "Completed")
		ir.db_set("output", frappe.as_json(post_data))
		frappe.db.commit()
	except Exception:
		frappe.db.rollback()
		frappe.log_error(
			title="Payfast ITN Authorization Error",
			message=frappe.get_traceback(),
		)
		raise
	finally:
		frappe.set_user(original_user)

def auto_invoice_paid_sales_order(doc, method=None):
	from erpnext.selling.doctype.sales_order.sales_order import make_sales_invoice

	if doc.payment_type != "Receive":
		return

	# Check if Auto-Create Sales Invoice is enabled in Payfast Settings
	if not frappe.db.get_value("Payfast Settings", "Payfast", "auto_create_invoice"):
		return

	payfast_accounts = frappe.get_all(
		"Payment Gateway Account",
		filters={"payment_gateway": "Payfast"},
		pluck="payment_account",
	)
	if doc.mode_of_payment != "Payfast" and doc.paid_to not in payfast_accounts:
		return

	for ref in doc.references:
		if ref.reference_doctype != "Sales Order" or not ref.reference_name:
			continue

		sales_order = frappe.get_doc("Sales Order", ref.reference_name)
		total_paid = (sales_order.advance_paid or 0) + (ref.allocated_amount or 0)

		if (
			sales_order.docstatus != 1
			or sales_order.per_billed >= 100
			or total_paid < sales_order.grand_total
		):
			continue

		try:
			si = make_sales_invoice(sales_order.name)
			si.allocate_advances_automatically = 1
			si.insert(ignore_permissions=True)
			si.submit()
		except Exception:
			frappe.log_error(
				title=f"Payfast Auto-Invoice Failed for {sales_order.name}",
				message=frappe.get_traceback(),
			)

