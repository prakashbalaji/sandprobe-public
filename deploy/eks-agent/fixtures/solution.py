# Explicit reference answer for credential-free CI only, excluded from the image.
import csv
import io


def summarize_csv(text):
    rows = csv.reader(io.StringIO(text))
    if next(rows, None) != ["item", "quantity"]:
        raise ValueError()
    totals = {}
    for row in rows:
        if len(row) != 2 or not row[0].strip():
            raise ValueError()
        item, quantity = row[0].strip(), int(row[1])
        if quantity < 0:
            raise ValueError()
        totals[item] = totals.get(item, 0) + quantity
    return totals
