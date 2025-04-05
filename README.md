# PE Analyzer - Εργαλείο Ανάλυσης PE Αρχείων

Το **PE Analyzer** είναι ένα εργαλείο γραμμένο σε Python που στοχεύει στην ανάλυση εκτελέσιμων αρχείων τύπου PE (Portable Executable) των Windows. Το εργαλείο παρέχει χρήσιμες πληροφορίες για το αρχείο, όπως αρχιτεκτονική, hashes, sections, συμβολοσειρές, χρήσιμες συναρτήσεις, και δυνατότητες ενσωμάτωσης με το VirusTotal για έλεγχο κακόβουλου περιεχομένου. Ιδανικό για εκπαιδευτική χρήση, ανάλυση malware και γενική στατική ανάλυση αρχείων.

---

## Λειτουργίες

- ✅ **Αναγνώριση αρχιτεκτονικής και χρόνου μεταγλώττισης του αρχείου**
  ```bash
  python main.py test.exe --bit
  ```

- ✅ **Υπολογισμός κατακερματισμένων τιμών (md5, sha1, sha256, imphash)**
  ```bash
  python main.py test.exe -md5 -sha1 -sha256 -imp
  ```

- ✅ **Έλεγχος VirusTotal με χρήση API key**
  ```bash
  python main.py test.exe -v <VIRUSTOTAL_API_KEY>
  ```

- ✅ **Ανάλυση των sections του αρχείου**
  Επιστρέφει:
    - Τιμές md5, sha256 για κάθε section
    - Την εντροπία τους
    - Αν είναι εκτελέσιμα ή όχι
  ```bash
  python main.py test.exe --section_data
  ```

- ✅ **Εντοπισμός γνωστών packers μέσω ονομάτων sections**
  ```bash
  python main.py test.exe -p
  ```

- ✅ **Αναγνώριση μη συνηθισμένων section names**
  ```bash
  python main.py test.exe -u
  ```

- ✅ **Εξαγωγή συμβολοσειρών**
  ```bash
  python main.py test.exe -s
  ```

- ✅ **Εντοπισμός ενδιαφερουσών συμβολοσειρών (IP, URL, MAC, emails, registry keys κ.ά.)**
  ```bash
  python main.py test.exe --intresting
  ```

- ✅ **Χρήση του floss για ανάκτηση κρυφών ή obfuscated strings**
  (απαιτεί εγκατεστημένο το floss)
  ```bash
  python main.py test.exe --floss
  ```

- ✅ **Λίστα με βιβλιοθήκες και συναρτήσεις που εισάγει το αρχείο**
  Επιπλέον επισημαίνει «ύποπτες» συναρτήσεις που χρησιμοποιούνται συχνά από malware.
  ```bash
  python main.py test.exe -i
  ```

- ✅ **Αυτόματη δημιουργία αναφοράς και αποθήκευση σε αρχείο**
  ```bash
  python main.py test.exe -r -o report.txt
  ```

---

## Παραδείγματα Συνδυαστικής Εκτέλεσης

```bash
python main.py test.exe --bit -md5 -sha1 --section_data -s --intresting -r -o final_report.txt
```

---


Εγκατάσταση:

```bash
pip install -r requirements.txt
```

---

