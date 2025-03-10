$ORIGIN example.com
$TTL 3600
example.com. IN SOA ns.example.com. admin.example.com. 1719172701 7200 3600 1209600 3600
example.com. IN A 192.0.2.1
example.com. IN AAAA 2001:db8::1 
example.com. IN MX 10 mail.example.net.
example.com. IN TXT "This zone is an example input for SLH-DSA-MTL zone signing"
www.example.com. IN CNAME example.com.
example.com. IN NS ns1.example.net.
example.com. IN NS ns2.example.net.
