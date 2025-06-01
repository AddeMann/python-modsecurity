ModSecurity Python Module
====

python-modsecurity is a Python binding for the [libModSecurity][libmodsecurity] C++ library. This module enables Python applications to leverage ModSecurity for real-time HTTP traffic inspection and rule enforcement.
---


Installation
------------

If you already have libModSecurity installed, you can simply run the following commands:
```bash
git clone https://github.com/AddeMann/python-modsecurity.git
cd python-modsecurity
pip install .
```

__NOTE__:
On `Windows`, setup.py will search for the directories `\\build\\win32\\build\\Release` and `\\headers` in your environment variables.

Build from source
----

Build libModSecurity from source by running the following command:
```bash
git clone https://github.com/AddeMann/python-modsecurity.git
cd python-modsecurity
./scripts/build.sh
```

Usage
----

Basic example:
```python
from modsecurity import ModSecurity, Transaction, RulesSet

# Initialize ModSecurity and rules
modsec = ModSecurity()
rules_set = RulesSet()
rules_set.load_from_uri("/etc/modsecurity/modsecurity.conf")

# Create a transaction
transaction = Transaction(modsec, rules_set)
transaction.process_connection("127.0.0.1", 12345, "192.168.1.1", 80)
transaction.process_uri("/test", "GET", "HTTP/1.1")
transaction.add_request_header("User-Agent", "Mozilla/5.0")
transaction.process_request_headers()

intervention = transaction.intervention():
if intervention:
    print("Request blocked by ModSecurity!")
```
Contributing

Contributions are welcome! Please open an issue or submit a pull request.

License

This project is licensed under the MIT License - see the LICENSE file for details.

[libmodsecurity]: https://modsecurity.org/

