from orion.ai.data_masker import DataMasker

def run_test():
    print("=== Testing Data Masker ===")
    
    masker = DataMasker.create_fresh()
    masker.add_known("shop.example.com", "HOST")
    masker.add_known("http://shop.example.com/checkout?id=1", "URL")
    
    payload = """
    Target: http://shop.example.com/checkout?id=1
    Host: shop.example.com
    Found issues on 10.0.0.5 and again on 10.0.0.5.
    Also found a server at 2001:0db8:85a3:0000:0000:8a2e:0370:7334.
    Contact admin@example.com for details.
    """
    
    masked = masker.mask_text(payload)
    print("\n--- MASKED OUTPUT ---")
    print(masked)
    
    print("\n--- ASSERTIONS ---")
    
    # Check 1: Same IP gets same placeholder (Notice we check for IP-3 now)
    if masked.count("[REDACTED-IP-3]") != 2:
        raise AssertionError(f"Fail: Duplicate IPs got different placeholders. Output: {masked}")
    if "[REDACTED-IP-4]" not in masked:
        raise AssertionError("Fail: Missing IPv6 placeholder")
    print("[PASS] Consistent IP masking (10.0.0.5 -> same placeholder)")
    
    # Check 2: Hostname and URL are masked
    if "shop.example.com" in masked:
        raise AssertionError("Fail: Hostname was not masked")
    if "http://shop.example.com" in masked:
        raise AssertionError("Fail: URL was not masked")
    print("[PASS] Target hostname/URL masking")
    
    # Check 3: Email is masked
    if "admin@example.com" in masked:
        raise AssertionError("Fail: Email not masked")
    print("[PASS] Email masking")
    
    # 4. Unmask to check data integrity
    unmasked = masker.unmask_text(masked)
    if unmasked != payload:
        raise AssertionError("Fail: Unmasking did not restore original text exactly")
    print("[PASS] Perfect unmasking round-trip")
    
    print("\nALL TESTS PASSED SUCCESSFULLY.")

if __name__ == "__main__":
    run_test()