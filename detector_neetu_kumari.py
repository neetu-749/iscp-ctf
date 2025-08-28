import pandas as pd
import json
import re


#functions for redaction

def mask_phone(phone):
    return phone[:2] + 'XXXXXX' + phone[-2:]

def mask_aadhar(aadhar):
    return 'XXXX XXXX ' + aadhar[-4:]

def mask_passport(passport):
    return passport[0] + 'XXXXXXX'

def mask_upi(upi):
    if '@' in upi:
        user, domain = upi.split('@', 1)
        return user[:2] + 'XXX' + user[2:] + '@' + domain
    return upi

def mask_name(name):
    parts = name.split()
    masked_parts = [p[0] + 'X'*(len(p)-1) for p in parts]
    return ' '.join(masked_parts)

def mask_address(address):
    return '[REDACTED_ADDRESS]'

def mask_ip(ip):
    return '[REDACTED_IP]'

def mask_device(device):
    return '[REDACTED_DEVICE]'

# PII detection functions
def detect_standalone_pii(record):
    pii_detected = False
    # Phone
    if 'phone' in record and re.fullmatch(r'\d{10}', str(record['phone'])):
        record['phone'] = mask_phone(record['phone'])
        pii_detected = True
    # Aadhar
    if 'aadhar' in record and re.fullmatch(r'\d{12}', str(record['aadhar'])):
        record['aadhar'] = mask_aadhar(record['aadhar'])
        pii_detected = True
    # Passport
    if 'passport' in record and re.fullmatch(r'[A-Z]\d{7}', str(record['passport'])):
        record['passport'] = mask_passport(record['passport'])
        pii_detected = True
    # UPI ID
    if 'upi_id' in record and re.fullmatch(r'[\w\d]+@[\w\d]+', str(record['upi_id'])):
        record['upi_id'] = mask_upi(record['upi_id'])
        pii_detected = True
    return pii_detected

def detect_combinatorial_pii(record):
    combinatorial_fields = ['name', 'email', 'address', 'ip_address', 'device_id']
    present = [f for f in combinatorial_fields if f in record and record[f]]
    if len(present) >= 2:
        for f in present:
            if f == 'name':
                record[f] = mask_name(record[f])
            elif f == 'email':
                record[f] = '[REDACTED_EMAIL]'
            elif f == 'address':
                record[f] = mask_address(record[f])
            elif f == 'ip_address':
                record[f] = mask_ip(record[f])
            elif f == 'device_id':
                record[f] = mask_device(record[f])
        return True
    return False

# Main CSV processing function
def process_csv(input_file, output_file):
    df = pd.read_csv(input_file)
    redacted_rows = []

    for idx, row in df.iterrows():
        try:
            data = json.loads(row['data_json'])
        except json.JSONDecodeError:
            data = {}
        is_pii = False

        # Standalone PII
        if detect_standalone_pii(data):
            is_pii = True
        # Combinatorial PII
        if detect_combinatorial_pii(data):
            is_pii = True

        redacted_rows.append({
            'record_id': row['record_id'],
            'redacted_data_json': json.dumps(data),
            'is_pii': is_pii
        })

    redacted_df = pd.DataFrame(redacted_rows)
    redacted_df.to_csv(output_file, index=False)
    print(f"Redacted CSV saved to {output_file}")


# CLI entry point
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 detector_neetu_kumari.py iscp_pii_dataset.csv")
        sys.exit(1)
    input_csv = sys.argv[1]
    output_csv = "redacted_output_neetu_kumari.csv"
    process_csv(input_csv, output_csv)
