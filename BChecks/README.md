BCheck is a way to write scanner checks for Burp Suite Professional and Enterprise. 
See the official article https://portswigger.net/burp/documentation/scanner/bchecks and GitHub repository of PortSwigger https://github.com/PortSwigger/BChecks/tree/main.

Following BChecks were written by Accenture:
|CVE|CVSSv3.1 base score|Vulnerability|Technology|Version|Name|Reference|BCheck|
|-|-|-|-|-|-|-|-|
|CVE-2011-3192|7.5|Denial of Service (DoS)|Apache HTTPD|2.0 - all versions prior to 2.2.20 and prior to 2.0.65|Range header DoS (aka. Apache Killer)|https://httpd.apache.org/security/CVE-2011-3192.txt|[here](CVE-2011-3192_Apache_DoS.bcheck)|
|CVE-2018-15133|8.1|Remote Code Execution (RCE) via deserialization|PHP Laravel|all versions prior to 5.5.40 and 5.6.x through 5.6.29|Laravel RCE|https://packetstormsecurity.com/files/153641/PHP-Laravel-Framework-Token-Unserialize-Remote-Command-Execution.html|[here](CVE-2018-15133-Laravel_RCE.bcheck)|
|CVE-2025-30208|5.3|Arbitrary File Read|Vite|all versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10|Vite file read|https://nsfocusglobal.com/vite-arbitrary-file-read-vulnerability-cve-2025-30208|[here](CVE-2025-30208_Vite_dev_server.bcheck)|

Here are others which do not have CVE:
|CVSSv3.1 base score|Vulnerability|Technology|Name|Reference|BCheck|
|-|-|-|-|-|-|
|9.9|Remote Code Execution (RCE)|Perl|Perl Jam 2|https://www.blackhat.com/docs/asia-16/materials/asia-16-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf|[here](Perl_Jam_2-RCE.bcheck)|
|0.0|Potential RCE or file rewrite|-|Interesting File Error in the Response|-|[here](Interesting_file_error_in_the_response.bcheck)|
|0.0|SSRF|-|CONNECT port scanning|https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/CONNECT|[here](CONNECT_port_scan.bcheck)|
