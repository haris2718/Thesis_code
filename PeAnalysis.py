import argparse
import pefile
import os
import sys
import hashlib
import floss
import re
from terminaltables import SingleTable
import time
import subprocess
from alive_progress import config_handler,alive_bar
import vt
import csv
import validators



FIELD_SIZE = 36

def arguments():
    '''
    Εδώ υλοποιείτε η βιβλιοθήκη argparse
    :return: Ένα αντικέιμενο τύπου parser που περιέχει τα ορίσματα που έχει εισάγαγερι ο χρήστης
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Filename', required=True)
    parser.add_argument("-o", "--out", dest="OUT", metavar="<file>", action="store", help="Save report  to a file")
    parser.add_argument("-r","--report", dest="REPORT", action="store_true", help="The report of the file")
    parser.add_argument("--md5", dest="MD5", action="store_true", help="The md5 hash value")
    parser.add_argument("--sha1", dest="SHA1", action="store_true", help="The sha1 hash value")
    parser.add_argument("--sha256", dest="SHA256", action="store_true", help="The sha256 hash value")
    parser.add_argument("--details", dest="DETAILS", action="store_true", help="Presents in detail the file pe")
    parser.add_argument("--imp", dest="IMPHASH", action="store_true", help="The imphash value")
    parser.add_argument("-i", dest="IMPORT", action="store_true", help="The import entry with suspicious entry marked ")
    parser.add_argument("--bit", dest="BIT", action="store_true", help="The bit version of file")
    parser.add_argument("--ctime", dest="COMPILE", action="store_true", help="The compile time  of file")
    parser.add_argument("--section_data", dest="SECTION", action="store_true", help="The hash value and entropy of sections ")
    parser.add_argument("-p","--packing", dest="PACKING", action="store_true", help="Detect known packed section ")
    parser.add_argument("-u", "--unusual_sevtion", dest="UNUSUAL_SECTION", action="store_true", help="Detects  unusual section in the Pe file")
    parser.add_argument("-s", "--strings", dest="STRINGS", action="store_true", help="Detects strings in the Pe file")
    parser.add_argument( "--intresting", dest="INTRESTING_STRINGS", action="store_true", help="Detects intrestring  strings in the Pe file")
    parser.add_argument("--floss", dest="FLOSS", action="store_true", help="Extract obfuscated, and stack strings with FireEye floss")
    parser.add_argument("-v", "--virusTkey", dest='VIRUSTOTAL', metavar="<api_key>",
                        action="store", help="Specify VT API key")
    parser.add_argument("-q", "--quiet", dest="QUIET", action="store_true", help="Do not print vendor analysis results")
    res = parser.parse_args()

    return res

def file_exists(fileName):
    '''
    επιστρέφει true εάν υπάρχει το αρχείο
    :param fileName:Η θέση του αρχείου
    :return: True or false
    '''
    return os.path.exists(fileName) and os.access(fileName, os.X_OK)

def intresting_strings(filePath):
    '''
    Ελέγχει τις συμβολοσειρές που περιέχει το αρχείο και εμφανίζει συμβολοσειρές που μοίαζουν με ipv4,ipv6 ,url,
    email,mac_address,domain και registy keys
    :param filePath:Η θέση του αρχείου
    :return: Ένα string που περιέχει τα αποτελέσματα της Ανάλυσης
    '''
    url_like_list=""
    email_like_list=""
    mac_address_like_list=""
    domain_like_list=""
    ipv6_like_list=""
    report=""
    with open(filePath, encoding='utf-8',errors='ignore') as f:
        data = f.read()
        f.close()
    list_of_strings=re.findall("[\x1f-\x7e]{3,}", data)
    list_whitout_spaces=clean_list(list_of_strings)
    mylist2 = findipv4(filePath)
    report +=('%-*s: %s\n' % (FIELD_SIZE, '', "intresting strings found"))
    for i in mylist2:
            report += ('%-*s: %s\n' % (FIELD_SIZE, 'ipv4', i))
    for i in list_whitout_spaces:
        if (validators.url(i)):
            url_like_list += ('%-*s: %s\n' % (FIELD_SIZE, 'url like string', i))
        if (validators.email(i)):
            email_like_list += ('%-*s: %s\n' % (FIELD_SIZE, 'email like string', i))
        if(validators.mac_address(i)):
            mac_address_like_list += ('%-*s: %s\n' % (FIELD_SIZE, 'mac address like string', i))
        if (validators.domain(i)):
            domain_like_list += ('%-*s: %s\n' % (FIELD_SIZE, 'domain like string', i))
        if (validators.ip_address.ipv6(i)):
            ipv6_like_list += ('%-*s: %s\n' % (FIELD_SIZE, 'ipv6 like string', i))
    registry = re.findall(r'\w+\\\w+\\\w+\\\w+\\\w+', data)
    for i in registry:
        report += ('%-*s: %s\n' % (FIELD_SIZE, 'registry like string', i))
    report += url_like_list + email_like_list + mac_address_like_list + domain_like_list + ipv6_like_list

    return report

def clean_list(unclean):
    '''
    Επιστρέφει κάθε συμβολοσειρά που χωρίζεται απο τις υπόλοιπές με κενό χαρακτήρα  σε μία νέα λίστα
    π.Χ {one two three,four, ,five} ={one,two,three,four,five}
    :param unclean:Μια λίστα που περιέχει συμβολοσειρές
    :return:Mia νέα λίστα χωρίς κενούς χαρακτήρες
    '''
    ret=[]
    for i in unclean:
        temp=i.strip().split(" ")
        for i in  temp:
            if i!="":
                ret.append(i)
    return ret

def findipv4(filePath):
    '''
    Χρησιμοποιεί κανονικές εκφράσεις προκειμένου να βρεί συμβολοσειρές που να μοίζουν με ip διευθύνσεις
    Με την έκφραση [0<=int(x)<256 for x in re.split('\.',re.match(r'^\d+\.\d+\.\d+\.\d+$',i).group(0))].count(True)==4,
    χωρίζουμε κάθε υποψήφια διεύθυνση (που είναι αποθηκευμένη στην μεταβλητή addresip) σε 4 μέρη ,χρησιμοποιώντας
    την τελεία <.> σαν αναγνωριστικό για το που θα πρέπει να χωρίσουμε τν συμβολοσειρά ( re.split).
    Έπειτα ελέγχουμε κάθε μέρος να είναι μικρότερο από 256 και εάν κάθε μέρος είναι μικρότερο αποθηκεύουμε την διεύθυνσή
    στην μεταβλητή addreipfinal
    :param filePath:Η θέση του αρχείου
    :return:Επιστρέφει μια λίστα με τα αποτελέσματα της Ανάλυσης
    '''
    with open(filePath, encoding='utf-8', errors='ignore') as f:
        data = f.read()
        f.close()
    ret=[]
    mylist = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data)
    for i in mylist:
        if ([0 <= int(x) < 256 for x in re.split('\.', re.match(r'^\d+\.\d+\.\d+\.\d+$', i).group(0))].count(
                True) == 4):
            ret.append(i)

    return ret

def strings(filePath):
    '''
    Βρίσκει συμβολοσειρές μήκους 3 χαρακτήρων και πάνω  που  περιέχονται  στο αρχείο
    :param filePath:Η θέση του αρχείου
    :return: Ένα string που περιέχει τα αποτελέσματα της Ανάλυσης
    '''
    report=""
    with open(filePath, encoding='utf-8',errors='ignore') as f:
        data = f.read()
        f.close()
        list= re.findall("[\x1f-\x7e]{3,}",data)
        if list:
            report+=('%-*s- %s\n' % (FIELD_SIZE, "--" * FIELD_SIZE, "--" * FIELD_SIZE))
        for i  in list:
            report +=('%-*s: %s\n' % (FIELD_SIZE,"", i))

    return  report

def section_data(res):
    '''
    Επιστρέφει τα sections του αρχείου  με την τιμή md5 και sha256 κάθε section,επιπλέον επιστρέφει την εντροπία
    του section , εάν η εντροπία έχει τιμή μεγαλύτερη ή ίση με 7 χρωματίζει την τιμή με κόκκινο χρώμα.
    Τέλος ελέγχει εάν το section είναι εκτελέσιμο και εάν είναι το χρωματίζει την απάντηση με κόκκινο χρώμα.
    :param res:Δέχεται σαν όρισμα τα argument της βιβλιοθήκης  argparse
    :return:Επιστρέφει ένα string με τα αποτελέσματα της Ανάλυσης
    '''
    report=""
    pe = pefile.PE(res.file)
    for sect in pe.sections:
        report +=('%-*s- %s\n' % (FIELD_SIZE, "--" * FIELD_SIZE, "--" * FIELD_SIZE))
        report +=('%-*s: %s\n' % (FIELD_SIZE, 'Section Name', sect.Name.decode('utf-8')))
        report += ('%-*s: %s\n' % (FIELD_SIZE, 'Section md5 value', sect.get_hash_md5()))
        report += ('%-*s: %s\n' % (FIELD_SIZE, 'Section sha256 value', sect.get_hash_sha256()))
        if sect.get_entropy()>=7:
            #report += colored(('%-*s: %s\n' % (FIELD_SIZE, 'Section entropy',sect.get_entropy())),'red')
            report += ('%-*s: %s\n' % (FIELD_SIZE, 'High Section entropy', sect.get_entropy()))
        else:
            report += ('%-*s: %s\n' % (FIELD_SIZE, 'Section entropy', sect.get_entropy()))
        characteristics = getattr(sect, 'Characteristics')
        if characteristics & 0x00000020 > 0 or characteristics & 0x20000000 > 0:
            #report += colored(('%-*s: %s\n' % (FIELD_SIZE, sect.Name.decode('utf-8'), "is executable!")),'red')
            report += ('%-*s: %s\n' % (FIELD_SIZE, sect.Name.decode('utf-8'), "is executable!"))
        else :
            report += ('%-*s: %s\n' % (FIELD_SIZE, sect.Name.decode('utf-8'), "is not executable!"))

        report += ('%-*s- %s\n' % (FIELD_SIZE, '--'*FIELD_SIZE,'--'*FIELD_SIZE ))

    return report

def virus_total(res):
    '''
    Εισάγει την τιμή md5 του εξεταζόμενου αρχείου στον ιστότοπο virus Total χρησιμοποιώντας το κλειδί (api_key) του
    χρήστη και επιστρέφει τα αποτελέσματα. Το public key του virus Total είναι δωρεάν αλλά έχει τον  περιορισμό
    της μίας αναζήτησης την μέρα.
    :param res:Δέχεται σαν όρισμα τα argument της βιβλιοθήκης  argparse
    :return:Επιστρέφει ένα string με τα αποτελέσματα της Ανάλυσης
    '''
    report=""
    api_key = res.VIRUSTOTAL
    client = vt.Client(api_key)
    f = open(res.file, "rb")
    data = f.read()
    f.close()
    try:
        response = client.get_object("/files/"+hashlib.md5(data).hexdigest())
    except:
        print("Total virus daily request limit consumed")
    # response={'harmless': 0, 'type-unsupported': 5, 'suspicious': 0, 'confirmed-timeout': 0, 'timeout': 1, 'failure': 0,
    #  'malicious': 0, 'undetected': 68}
    client.close()
    try:
        report += ('%-*s- %s\n' % (FIELD_SIZE,"--"*FIELD_SIZE,'--'*FIELD_SIZE))
        report += ('%-*s\n' % (FIELD_SIZE,"Virus Total Report"))
        for key,value in response.last_analysis_stats.items():
            report +=('%-*s: %s\n' % (FIELD_SIZE, key,value))
    except:
        print("An exception 2 occurred")

    return report

def detect_abnormal_sections(res):
    '''
    Εισάγει απο το  αρχείο Normal_sections.csv μια λίστα με τα πιο γνωστά ονόματα sections
    και τa αντιπαραβάλει με το  πίνακα sections του εξεταζόμενου αρχείου.
    :param res:Δέχεται σαν όρισμα τα argument της βιβλιοθήκης  argparse
    :return:Επιστρέφει ένα string με τα αποτελέσματα της Ανάλυσης
    '''
    print("finding abnormal sections name")
    matches=""
    Normal_sections={}
    with open('Normal_sections.csv', mode='r') as ps:
        reader = csv.reader(ps)
        for rows in reader:
            k = rows[0]
            v = rows[1]
            Normal_sections[k] = v
    try:
  #parse the files
        pe = pefile.PE(res.file)
        Normal_sections_lower = {x: x for x in Normal_sections.keys()}
        sections = [section.Name.decode(errors='replace', ).rstrip('\x00') for section in pe.sections]
        config_handler.set_global(spinner='stars')
        with alive_bar(sections.__len__()) as bar:
            for i in sections:
                time.sleep(0.2)
                bar()
                if not i in Normal_sections_lower.keys():
                    matches +=('%-*s- %s\n' % (FIELD_SIZE, "--" * FIELD_SIZE, "--" * FIELD_SIZE))
                    matches +=('%-*s: %s\n' % (FIELD_SIZE, 'unusual section found', i))
                    matches += ('%-*s- %s\n' % (FIELD_SIZE, "--" * FIELD_SIZE, "--" * FIELD_SIZE))

        if matches:
            print(('%-*s: %s\n' % (FIELD_SIZE, 'unusual section found', i)))
        else:
            print("unusual sections not found")
    except:
        print('manuel exception')
    return matches

def detect_packing(res):
    '''
    Εισάγει απο το  αρχείο packers_sections.csv μια λίστα με τα πιο γνωστά ονόματα sections απο προγράμματα packer
    και τa αντιπαραβάλει με το  πίνακα sections του εξεταζόμενου αρχείου.
    :param res:Δέχεται σαν όρισμα τα argument της βιβλιοθήκης  argparse
    :return:Επιστρέφει ένα string με τα αποτελέσματα της Ανάλυσης
    '''
    report=""
    print("searching for knowing packer sections")
    packers_sections = {}
    with open('packers_sections.csv', mode='r') as ps:
        reader = csv.reader(ps)
        for rows in reader:
            k = rows[0]
            v = rows[1]
            packers_sections[k] = v
    try:
        pe = pefile.PE(res.file)
        packers_sections_lower = {x.lower(): x for x in packers_sections.keys()}
        sections = [section.Name.decode(errors='replace', ).rstrip('\x00') for section in pe.sections]
        with alive_bar(sections.__len__()) as bar:
            for x in sections:
                if x.lower() in packers_sections_lower.keys():
                    print('packer section found ',packers_sections_lower[x.lower()])
                    report +=('%-*s- %s\n' % (FIELD_SIZE, "--" * FIELD_SIZE, "--" * FIELD_SIZE))
                    report += ('%-*s: %s\n' % (FIELD_SIZE, 'packer section found',packers_sections_lower[x.lower()] ))
                    report += ('%-*s- %s\n' % (FIELD_SIZE, "--" * FIELD_SIZE, "--" * FIELD_SIZE))
                bar()
    except:
        print('manuel exception')

    return  report

def suspicious_import(res):
    '''
    Εισάγει απο το  αρχείο indicators.csv μια λίστα με τις πιο ύποπτες συνατρήσεις που χρησιμοποιούνται απο κακόβουλα προγράμματα
    και τις αντιπαραβάλει με το  πίνακα ΙΑΤ του εξεταζόμενου αρχείου.
    :param res:Δέχεται σαν όρισμα τα argument της βιβλιοθήκης  argparse
    :return:Επιστρέφει ένα string με τα αποτελέσματα της Ανάλυσης
    '''
    pe = pefile.PE(res.file)
    report=""
    count = 0
    Total_count=0
    suspicious_entries = {}
    with open('indicators.csv', mode='r') as ps:
        reader = csv.reader(ps)
        for rows in reader:
            k = rows[0]
            v = rows[1]
            suspicious_entries[k] = v
    report += ('%-*s\n' % (FIELD_SIZE, 'entry import'))

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        report += ('%-*s- %s\n' % (FIELD_SIZE, "--" * FIELD_SIZE, "--" * FIELD_SIZE))
        report += ('%-*s: %s\n' % (FIELD_SIZE, "", entry.dll.decode('utf-8')))

        for fun in entry.imports:
            if fun.name.decode('utf-8') in suspicious_entries:
                report += ('%-*s: %s\n' % (FIELD_SIZE, fun.name.decode('utf-8'), ('\n' + " " * (FIELD_SIZE + 3)).join(
                    re.findall('.{1,100}', suspicious_entries[fun.name.decode('utf-8')]))))
            else:
                report += ('%-*s: %s\n' % (FIELD_SIZE, fun.name.decode('utf-8'), ""))
            count += 1
        report += ('%-*s: %s\n' % (FIELD_SIZE, entry.dll.decode('utf-8'), count))
        report += ('%-*s- %s\n' % (FIELD_SIZE, "--"*FIELD_SIZE,"--"*FIELD_SIZE))
        Total_count+=count
        count=0
    report += ('%-*s: %s\n' % (FIELD_SIZE, "Total functions", Total_count))
    return report


def print_table(report):
    '''
    :param report:Δέχεται σαν όρισμα ένα string που περιέχει τα αποτελέσματα της ανάλυσης
    :return:Επιστρέφει ένα αντικείμενο table που περιέχει τα  αποτελέσματα της Ανάλυσης διαμορφωμένα
    '''
    table_data = [["data"]]
    table_data.append([report])
    table = SingleTable(table_data)
    table.inner_column_border = False
    table.outer_border = False
    table.justify_columns[1] = "center"
    return table

def floss(filePath):
    """
    :param filePath: Δέχεται την θέση του αρχείου
    :return: Επιστρέφει ένα string με τα αποτελέσματα που βρήκε το πρόγραμμα Floss της fireEye
    """
    report =""
    print("Checking for Obfuscated Strings with floss.. ")
    config_handler.set_global(spinner='stars')
    try:
        process=subprocess.Popen(
            [r'floss.exe ', '-q', '--no-static-strings',
             filePath], stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding="utf-8")
    except:
        print("An exception occurred")

    stdout, stderr = process.communicate()
    if stdout:
        for line in stdout.split("\n"):
            print(line)
            if line!="":
                report +=('%-*s: %s\n' % (FIELD_SIZE, 'Floss, string Found', line))
    else:
        report += ('%-*s: %s\n' % (FIELD_SIZE, 'Floss', "no obscured strings were found"))
    print("done with floss")
    return report

def filePe(res):
    '''
    Ανάλογα με το arg που έχει περάσει ο χρήστης, επιστρέφει:
    Το imphash του αρχείου,την αρχιτεκτονική του,την ώρα που έχει μεταγλωττιστεί,το πίνακα με τις συναρτήσεις που
    το εξεταζόμενο αρχείο  εισάγει, με  τις πιο συνηθισμένες  συναρτήσεις που χρησιμοποιούνται από κακόβουλα προγράμματα
    σημειωμένες.
    :param res:Δέχεται σαν όρισμα τα argument της βιβλιοθήκης argparse
    :return:Επιστρέφει ένα string με τα αποτελέσματα της Ανάλυσης
    '''
    report=""
    pe = pefile.PE(res.file)
    if res.IMPHASH or res.REPORT:
        report += ('%-*s: %s\n' % (FIELD_SIZE, 'imphash', pe.get_imphash()))
    if res.BIT or res.REPORT:
        if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b':
            report += ('%-*s \n' % (FIELD_SIZE, 'This is a 32-bit binary'))
        elif hex(pe.OPTIONAL_HEADER.Magic) == '0x20b':
            report += ('%-*s \n' % (FIELD_SIZE, 'This is a 64-bit binary'))
    if res.COMPILE or res.REPORT:
        try:
            time_output = '%s UTC' % time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))
        except:
            time_output = 'Invalid Time'
        report += ('%-*s: %s\n' % (FIELD_SIZE, 'Compiled Time', time_output))
    if res.DETAILS:
        pe.print_info()

    return report


def firstreport(filePath):
    """
    :param filePath: η θέση του αρχείου
    :return: Ένα string που περιέχει το όνομα του αρχείου και το μέγεθος του
    """
    report=""
    data = open(filePath, 'rb').read()
    if not len(data):
        return None
    fname = os.path.split(filePath)[1]
    report += ('%-*s: %s\n' % (FIELD_SIZE, 'File Name', fname))
    report += ('%-*s: %s\n' % (FIELD_SIZE, 'File Size in bytes', '{:,}'.format(os.path.getsize(filePath))))

    return report

def main():
    report = ""
    res = arguments()
    if not file_exists(res.file):
        print("Can not find the file \n[*] Exiting...")
        sys.exit()
    f = open(res.file, "rb")
    data = f.read()
    f.close()
    if res.REPORT:
        report +=firstreport(res.file)
        report += filePe(res)
    if res.MD5 or res.REPORT:
        report +=('%-*s: %s\n' % (FIELD_SIZE, 'MD5', hashlib.md5(data).hexdigest()))
    if res.SHA1 or res.REPORT:
        report +=('%-*s: %s\n' % (FIELD_SIZE, 'SHA1', hashlib.sha1(data).hexdigest()))
    if res.SHA256 or res.REPORT:
        report +=('%-*s: %s\n' % (FIELD_SIZE, 'SHA256', hashlib.sha256(data).hexdigest()))
    if res.PACKING or res.REPORT:
        report +=detect_packing(res)
    if res.UNUSUAL_SECTION or res.REPORT:
        report+=detect_abnormal_sections(res)
    if res.STRINGS:
        report+=strings(res.file)
    if res.FLOSS:
        report +=floss(res.file)
    if res.SECTION or res.REPORT :
        report +=section_data(res)
    if res.INTRESTING_STRINGS or res.REPORT:
        report+=intresting_strings(res.file)
    if res.IMPORT or res.REPORT:
        report+=suspicious_import(res)
    if res.VIRUSTOTAL:
        report+=virus_total(res)
    if (not res.QUIET and len(print_table(report).table_data) != 1 and not res.DETAILS):
        print("\nVendors analysis results:\n")
        print(print_table(report).table)

    if res.OUT:
        with open(res.OUT, "w+") as outfile:
            rep=""
            for i in report:
                i=i.replace('[31m','')
                i=i.replace('[0m','')
                rep+=i
            outfile.write(rep)
            outfile.close()
            print("Saving file "+res.OUT)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
