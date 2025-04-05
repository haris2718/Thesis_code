# 🔍 PE Analyzer - Εργαλείο Ανάλυσης Εκτελέσιμων Αρχείων Windows

## 📌 Τι είναι τα PE αρχεία;

Τα PE (Portable Executable) είναι η κύρια μορφή εκτελέσιμων αρχείων στο λειτουργικό σύστημα Windows. Περιλαμβάνουν αρχεία όπως `.exe`, `.dll`, `.sys`, κ.ά.  
Περιέχουν πληροφορίες για την εκτέλεση του προγράμματος, sections με κώδικα και δεδομένα, πίνακες imports/exports, headers και metadata.

Η ανάλυση PE αρχείων είναι σημαντική για:
- Ανίχνευση malware
- Reverse engineering
- Κατανόηση της συμπεριφοράς ενός εκτελέσιμου

---

## 🧰 Τι κάνει αυτό το εργαλείο;

Αυτό το εργαλείο εκτελεί **στατική ανάλυση** σε αρχεία PE και παρέχει:
- Εξαγωγή strings (floss)
- Ανίχνευση ύποπτων imports & συναρτήσεων
- Ανάλυση sections (π.χ. RWX flags)
- VirusTotal lookup για hash
- Αναφορά με χρήσιμα ευρήματα για έλεγχο κακόβουλης συμπεριφοράς

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
  
  Αυτή η συνάρτηση αναλύει ένα αρχείο και εντοπίζει «ενδιαφέρουσες» συμβολοσειρές που μπορεί να αποκαλύψουν κακόβουλη ή ύποπτη συμπεριφορά, όπως:
  
    - IPv4 & IPv6 διευθύνσεις (π.χ. 192.168.0.1)
    - URLs (π.χ. http://malicious.site)
    - Email διευθύνσεις (π.χ. hacker@evilcorp.com)
    - MAC addresses (π.χ. 00:0a:95:9d:68:16)
    - Domain names (π.χ. bad-domain.org)
    - Registry keys των Windows (π.χ. HKEY_LOCAL_MACHINE\Software...\Run)

  🧠 Γιατί είναι χρήσιμη:
    - Βοηθά στην αναγνώριση πιθανής κακόβουλης δικτυακής επικοινωνίας.
    - Μπορεί να αποκαλύψει στοιχεία στόχων ή υποδομών που χρησιμοποιεί το αρχείο.
    - Αναδεικνύει πιθανές παρεμβάσεις στο σύστημα, όπως τροποποιήσεις σε registry.
    - Είναι εξαιρετικά χρήσιμη για reverse engineering και ανάλυση κακόβουλου λογισμικού, καθώς παρέχει στοιχεία χωρίς αποσυμβολοποίηση.
    
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
  Ο πίνακας IAT ενός PE αρχείου αποκαλύπτει ποιες συναρτήσεις του Windows API χρησιμοποιεί το πρόγραμμα.
  Αν παρατηρηθούν συναρτήσεις όπως CreateRemoteThread, VirtualAllocEx, LoadLibrary, τότε είναι ένδειξη ότι το πρόγραμμα ίσως να προσπαθεί να:
  -  Ενσωματωθεί σε άλλες διεργασίες (code injection),
  -  Εκτελέσει κακόβουλο κώδικα στη μνήμη,
  -  Παρακάμψει μηχανισμούς ασφαλείας.
  
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

