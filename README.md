# TeamViewer-Reg-Decrypter

**Decrypt TeamViewer encrypted passwords from Windows `.reg` registry export files**  
Based on [CVE-2019-18988](https://vulmon.com/vulnerabilitydetails?qid=CVE-2019-18988)

---

## Overview

This Python tool extracts and decrypts TeamViewer passwords stored in `.reg` files exported from Windows registries.  
It uses the known AES key/IV from TeamViewer's vulnerability to decrypt various stored password types.

---

## Features

- Parses `.reg` files (UTF-16 LE encoded)
- Extracts multiple TeamViewer password fields
- Decrypts AES-CBC encrypted passwords
- Handles multiline hex values with robust cleaning

---

## Requirements

- Python 3.6+
- [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)

Install PyCryptodome with:

```bash
pip install pycryptodome
````

---

## Usage

```bash
python3 decrypt_teamviewer.py <teamviewer_registry.reg>
```

Example:

```bash
python3 decrypt_teamviewer.py teamviewer.reg
```

---

## Disclaimer

This tool is for educational, testing, and authorized security assessments only.
Unauthorized access or misuse is illegal and unethical.

---

## References

* [https://whynotsecurity.com/blog/teamviewer/](https://whynotsecurity.com/blog/teamviewer/)
* [https://gist.github.com/ctigeek/2a56648b923d198a6e60](https://gist.github.com/ctigeek/2a56648b923d198a6e60)
* [https://vulmon.com/vulnerabilitydetails?qid=CVE-2019-18988](https://vulmon.com/vulnerabilitydetails?qid=CVE-2019-18988)

---

## Author

Created by Mohammad Agha Sulaiman Zai
Feel free to contribute or report issues.
