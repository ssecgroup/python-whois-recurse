from whois_recurse import WHOISClient

client = WHOISClient()
result = client.lookup("miro.com")

print(f"Domain: {result['domain']}")
print(f"Registrar: {result['registrar']}")
print(f"Registrar WHOIS: {result['registrar_server']}")
print(f"Emails found: {len(result['all_emails'])}")