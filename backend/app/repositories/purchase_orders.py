import secrets
import uuid
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.orm import Session


def create(db: Session, tenant_id: str, *, vendor: str, description: str, amount: Decimal, currency: str,
           department: str, created_by: uuid.UUID) -> dict:
    po_number = "PO-" + secrets.token_hex(4).upper()
    row = db.execute(
        text("INSERT INTO purchase_orders (tenant_id, po_number, vendor, description, amount, currency, "
             "department, created_by) VALUES (:t, :n, :v, :d, :a, :c, :dp, :u) "
             "RETURNING id, po_number, vendor, amount, currency, status, department, created_at"),
        {"t": tenant_id, "n": po_number, "v": vendor, "d": description, "a": amount, "c": currency,
         "dp": department, "u": created_by},
    ).mappings().one()
    return dict(row)
