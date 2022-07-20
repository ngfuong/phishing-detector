import re
import urllib.request
import requests
import socket
import numpy as np
from bs4 import BeautifulSoup

import time
from datetime import date, datetime
from dateutil.parser import parse as date_parse

import whois
import ipaddress
import googlesearch


def generate_features(url):
    """
    index,
    having_IP_Address,
    URL_Length,
    Shortining_Service,
    having_At_Symbol,
    double_slash_redirecting,
    Prefix_Suffix,
    having_Sub_Domain,
    SSLfinal_State,
    Domain_registeration_length,
    Favicon,port,
    HTTPS_token,
    Request_URL,
    URL_of_Anchor,
    Links_in_tags,
    SFH,
    Submitting_to_email,
    Abnormal_URL,
    Redirect,
    on_mouseover,
    RightClick,
    popUpWidnow,
    Iframe,
    age_of_domain,
    DNSRecord,
    web_traffic,
    Page_Rank,
    Google_Index,
    Links_pointing_to_page,
    Statistical_report,
    Result
    """
    # create new record
    record = []

    # get reponse 
    if not re.match(r"https?", url):
        url = "http://" + url

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -999
    
    domain = re.findall(r"://([^/]+)/?", url)[0]
    if re.match(r"www.", domain):
        domain = domain.replace("www.", "")
    
    
    # FEATURE GENERATION
    # 1. having_IP_address
    try:
        ipaddress.ip_address(url)
        record.append(-1)
    except:
        record.append(1)
    
    # 2. URL_Length
    if len(url) < 54:
        record.append(1)
    elif len(url) > 75:
        record.append(-1)
    else:
        record.append(0)
    
    # 3. Shortening_Service
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
    
    record.append(-1 if match else 1)

    # 4. having_@_Symbol
    record.append(-1 if re.findall("@", url) else 1)

    # 5. double_slash_redirecting
    list = [x.start(0) for x in re.finditer('//', url)]
    record.append(-1 if len(list)-1 > 6 else 1)

    # 6. Prefix_Suffix
    record.append(-1 if re.findall(r"https?://[^\-]+-[4^\-]+$", url) else 1)

    # 7. having_Sub_Domain
    sub_domains = len(re.findall("\.", url))
    if sub_domains == 1:
        record.append(1)
    elif sub_domains == 2:
        record.append(0)
    else:
        record.append(-1)
    
    # 8. SSLfinal_State
    try: 
        if response.text:
            record.append(1)
    except:
        record.append(-1)
    
    # 9. Domain_registeration_length
    registration_len = 0
    try:
        whois_response = whois.whois(domain)
        expire_date = whois_response.expiration_date
        expire_date = min(expire_date)
        registration_len = abs(expire_date - time.strftime('%Y-%m-%d').days)
        record.append(-1 if registration_len/365<=1 else 1)
    except:
        whois_response=False
        record.append(-1)
    
    # 10. Favicon
    if soup == -999:
        record.append(-1)
    else:
        try:
            for head in soup.find_all('head'):
                for head.link in soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        record.append(1)
                        raise StopIteration
                    else:
                        record.append(-1)
                        raise StopIteration
        except StopIteration:
            pass
    
    # 11. port
    try:
        port = domain.split(":")[1]
        record.append(-1 if port else 1)
    except:
        record.append(1)

    # 12. HTTPS_token
    record.append(1 if re.findall(r"^https://", url) else -1)

    # 13. Request_URL
    i = 0
    success = 0 
    if soup == -999:
        record.append(-1)
    else:
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if url in img['src'] or domain in img['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for audio in soup.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for embed in soup.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for iframe in soup.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
            if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success/float(i) * 100
            if percentage < 22.0:
                record.append(1)
            elif percentage > 61.0:
                record.append(-1)
            else:
                record.append(0)
        except:
            record.append(1)
    
    # 14. URL_of_Anchor
    percentage = 0
    i = 0
    unsafe = 0
    if soup == -999:
        record.append(-1)
    else:
        for a in soup.find_all('a', href=True):
            # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript 
            # and :: might not be there in the actual a['href']
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                unsafe = unsafe + 1
            i = i + 1

        try:
            percentage = unsafe / float(i) * 100
        except:
            record.append(1)

        if percentage < 31.0:
            record.append(1)
        elif percentage < 67.0:
            record.append(-1)
        else:
            record.append(0)

    # 15. Links_in_tags
    i = 0
    success = 0
    #TODO: check this
    if soup == -999:
        # Links_in_tags
        record.append(-1)
        # SFH
        record.append(0)
    else:
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or domain in link['href'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or domain in script['src'] or len(dots) == 1:
                success = success + 1
            i = i+1
        try:
            percentage = success / float(i) * 100
        except:
            record.append(1)

        if percentage < 17.0:
            record.append(1)
        elif percentage > 81.0:
            record.append(-1)
        else:
            record.append(0)

        # 16. SFH
        if len(soup.find_all('form', action=True))==0:
            record.append(1)
        else :
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    record.append(-1)
                    break
                elif url not in form['action'] and domain not in form['action']:
                    record.append(0)
                    break
                else:
                    record.append(1)
                    break

    # 17. Submitting_to_email
    if response == "":
        record.append(-1)
    else:
        record.append(-1 if re.findall(r"[mail\(\)|mailto:?]", response.text) else 1)

    # 18. Abnormal_URL
    if response == "":
        record.append(-1)
    else:
        record.append(1 if response.text == whois_response else -1)

    # 19. Redirect
    if response == "":
        record.append(-1)
    else:
        if len(response.history) <= 1:
            record.append(-1)
        elif len(response.history) <= 4:
            record.append(0)
        else:
            record.append(1)

    # 20. on_mouseover
    if response == "":
        record.append(-1)
    else:
        record.append(1 if re.findall("<script>.+onmouseover.+</script>", response.text) else -1)

    # 21. RightClick
    if response == "":
        record.append(-1)
    else:
        record.append(1 if re.findall(r"event.button ?== ?2", response.text) else -1)

    # 22. popUpWidnow
    if response == "":
        record.append(-1)
    else:
        record.append(1 if re.findall(r"alert\(", response.text) else -1)

    # 23. Iframe
    if response == "":
        record.append(-1)
    else:
        record.append(1 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else -1)

    # 24. age_of_domain
    if response == "":
        record.append(-1)
    else:
        try:
            registration_date = re.findall(
                    r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
            today = date.today()
            month_diff = (today.year - date_parse(registration_date).year)*12 + today.month - registration_date.month
            record.append(-1 if month_diff >= 6 else 1)
        except:
            record.append(1)

    # 25. DNSRecord
    dns = 1
    try:
        d = whois.whois(domain)
    except:
        dns = -1
    if dns == -1:
        record.append(-1)
    else:
        record.append(-1 if registration_len/ 365 <= 1 else 1)

    # 26. web_traffic
    try:
        rank = BeautifulSoup(urllib.request.urlopen(
            "http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank = int(rank)
        record.append(1 if rank<100000 else 0)
    except :
        record.append(-1)

    # 27. Page_Rank
    # get page rank
    rank_check_url = "https://www.checkpagerank.net/index.php"
    rank_checker_res = requests.post(rank_check_url, { "name": domain})
    try:
        global_rank = int(re.findall(
            r"Global Rank: ([0-9]+)", rank_checker_res.text)[0])

    except:
        global_rank = -1
    try:
        if global_rank > 0 and global_rank < 100000:
            record.append(1)
        else:
            record.append(-1)
    except:
        record.append(1)

    # 28. Google_Index
    site = googlesearch.search(url, 5)
    record.append(1 if site else -1)

    # 29. Links_pointing_to_page
    if response == "":
        record.append(-1)
    else:
        number_of_links = len(re.findall(r"<a href=", response.text))
        if number_of_links == 0:
            record.append(1)
        elif number_of_links <= 2:
            record.append(0)
        else:
            record.append(-1)

    # 30. Statistical_report
    url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    try:
        ip_address = socket.gethostbyname(domain)
        ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                             '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                             '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                             '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                             '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                             '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
        if url_match:
            record.append(-1)
        elif ip_match:
            record.append(-1)
        else:
            record.append(1)
    except:
        print('Connection problem: Name or service not known. Check your URL availability.')
        return False
    
    return np.array(record)


def features_to_dict(features):
    features_ls = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon,port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
    ]

    dct = {}
    for key, value in zip(features_ls, list(features)):
        # print(f"{key}:{value}")
        dct[key] = value 
    return dct

    
