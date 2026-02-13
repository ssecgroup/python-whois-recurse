from whois_recurse import WHOISClient

domains = ["google.com", "facebook.com", "github.com", "microsoft.com", "apple.com"]
client = WHOISClient()
results = client.bulk_lookup(domains, concurrency=5)

for result in results:
    print(f"{result['domain']}: {result.get('registrar', 'N/A')}")