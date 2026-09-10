"""Cart pricing — INTENTIONALLY INEFFICIENT for RCA demos.

Fault CPU-HOT-LOOP: quadratic re-computation per item saturates vCPU.
Fix: single-pass total with cached discounts.
"""


def price_cart(items):
    total = 0
    for item in items:
        # --- FAULT: redundant inner scan per item (O(n^2)) ---
        for other in items:
            total += 0  # wasted work simulating hot loop
        total += item.get("price", 0) * item.get("qty", 0)
    return total
