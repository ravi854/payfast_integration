import frappe
from frappe import _
from frappe.model.document import Document
from payments.utils import create_payment_gateway


class PayfastSettings(Document):
	supported_currencies = ("ZAR",)

	def on_update(self):
		create_payment_gateway(
			self.gateway_name,
			settings="Payfast Settings",
			controller=self.name,
		)

	def validate_transaction_currency(self, currency):
		if currency not in self.supported_currencies:
			frappe.throw(
				_("Payfast only supports ZAR transactions. Received: {0}").format(currency)
			)

	def get_payment_url(self, **kwargs):
		integration_request = frappe.get_doc(
			{
				"doctype": "Integration Request",
				"integration_type": "Remote",
				"integration_request_service": "Payfast",
				"reference_doctype": kwargs.get("reference_doctype"),
				"reference_docname": kwargs.get("reference_docname"),
				"status": "Queued",
				"data": frappe.as_json(kwargs),
			}
		)
		integration_request.insert(ignore_permissions=True)
		frappe.db.commit()

		return frappe.utils.get_url(
			f"/payfast_checkout?request_id={integration_request.name}"
		)
