import logging
from datamodel.search.Shamli_datamodel import ShamliLink, OneShamliUnProcessedLink
from spacetime.client.IApplication import IApplication
from spacetime.client.declarations import Producer, GetterSetter
from lxml import html,etree
import re, os
from time import time
## from uuid import uuid4
from urlparse import urlparse, urljoin ##parse_qs
import json
import os.path
from time import strftime

'''
Logger
'''
logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"

'''
Load configurations
'''
with open('config.json') as F:
    config_data = json.loads(F.read())
    
'''
Regex Matchers for URLs
'''
invalid_types_matcher = re.compile('.*\\.(css|js|bmp|gif|jpe?g|ico' + '|png|tiff?|mid|mp2|mp3|mp4' + '|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf' + '|ps|eps|tex|ppt|pptx|pps|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|sql' + '|thmx|mso|arff|rtf|jar|csv' + '|rm|smil|wmv|swf|wma|zip|rar|gz|pdf|ipynb|bib|java|py|txt|bam|class|sql|r|m|lif)$' + '|mat|raw|fig|log|rtf|js|sh')
content_del_matcher = re.compile('^.*(/misc|/sites|/all|/themes|/modules|/profiles|/css|/field|/node|/theme){3}.*$')
length_matcher = re.compile('^.*/[^/]{100,}$')
keywords_matcher = re.compile('^.*(calendar|files|directory|build|ds_store|gang|private|repository|project|archive|release|dataset)+.*$')
repeatition_matcher = re.compile('.*?([^\\/\\&?]{4,})(?:[\\/\\&\\?])(.*?\\1){3,}.*')
domain_matcher = re.compile('^(http(s)?(:\\/\\/))?(www\\.)?.*\\.ics\\.uci\\.edu(\\/.*)?$')


'''
Load last run state
'''
saved_state = {'invalid_urls': [], 'crawled': [], 'subdomains': {}, 'maxoutlinks': 0, 'maxoutlinksdomain': '', 'redirects':[]}
if os.path.isfile('saved_state.json'):
    with open('saved_state.json') as F:
        saved_state = json.loads(F.read())


@Producer(ShamliLink)
@GetterSetter(OneShamliUnProcessedLink)
class CrawlerFrame(IApplication):
    app_id = "Shamli"

    def __init__(self, frame):
        self.app_id = "Shamli"
        self.frame = frame
        self.starttime = time()

    def initialize(self):
        self.count = 0
        links = self.frame.get_new(OneShamliUnProcessedLink)
        if len(links) > 0:
            print("Resuming from the previous state.")
            self.download_links(links)
        else:
            l = ShamliLink("http://www.ics.uci.edu/")
            print(l.full_url)
            self.frame.add(l)

    def update(self):
        try:
            unprocessed_links = self.frame.get_new(OneShamliUnProcessedLink)
            if unprocessed_links:
                self.download_links(unprocessed_links)
        except:
            save_state_and_print_analytics()
            raise
            
    def download_links(self, unprocessed_links):
        for link in unprocessed_links:
            if len(saved_state['crawled']) >= config_data['URLThreshold']:
                save_state_and_print_analytics()
                print('\n****************************************************\n')
                print ('Stopping the crawler as the crawling limit has reached: ', len(saved_state['crawled']))
                print('\n****************************************************\n')
                self.done = True
            else:
                print ('Got a link to download:', link.full_url)
                downloaded = link.download()
                links, final_url = extract_next_links(downloaded)
                subdomain = extract_subdomain(final_url)
                valid_links = []
                for l in links:
                    if is_valid(l):
                        valid_links.append(l)
                        self.frame.add(ShamliLink(l))

                if subdomain not in saved_state['subdomains']:
                    saved_state['subdomains'][subdomain] = {'outlinks': list(set(links)),
                     'valid_outlinks': list(set(valid_links)),'visits':1,'originurl':downloaded.url}
                else:
                    saved_state['subdomains'][subdomain] = {'outlinks': list(set(saved_state['subdomains'][subdomain]['outlinks']).union(set(links))),
                     'valid_outlinks': list(set(saved_state['subdomains'][subdomain]['valid_outlinks']).union(set(valid_links))), "visits" : saved_state['subdomains'][subdomain]['visits'] + 1}
                    
                olen = len(saved_state['subdomains'][subdomain]['outlinks'])
                saved_state['subdomains'][subdomain]['outlinkscount'] = olen
                
                if subdomain != 'www.ics.uci.edu' and saved_state['maxoutlinks'] < olen:
                    saved_state['maxoutlinks'] = olen
                    saved_state['maxoutlinksdomain'] = subdomain

    def shutdown(self):
        print (
            "Time time spent this session: ",
            time() - self.starttime, " seconds.")
    
'''
rawDataObj is an object of type UrlResponse declared at L20-30 datamodel/search/server_datamodel.py the return of this function should be a list of urls in their absolute form Validation of link via is_valid function is done later (see line 42).
Duplicates are not removed as the frontier takes care of that.
'''
def extract_next_links(rawDataObj):
    outputLinks = []
    content = rawDataObj.content
    if content == None and content == "":
        return outputLinks
    downloaded_url = rawDataObj.url
    if rawDataObj.is_redirected == True:
        downloaded_url = rawDataObj.final_url
        saved_state['redirects'].append(downloaded_url + " -- " + rawDataObj.url)
    saved_state['crawled'].append(downloaded_url)
    if rawDataObj.http_code <= 400 and rawDataObj.content:
        if rawDataObj.headers != None and 'Content-Type' in rawDataObj.headers:
            contentType = rawDataObj.headers['Content-Type']
            if contentType != None and contentType != "" and 'iso-8859-1' in contentType.lower():
                content = content.decode('iso-8859-1').encode('utf8')
        try:
            html_doc = html.fromstring(content)
            anchors = html_doc.xpath('//a')
            for anchor in anchors:
                href = anchor.get('href')
                if href != None and len(href) > 0:
                    abs_url = urljoin(downloaded_url, href)
                    if abs_url != downloaded_url:
                        outputLinks.append(abs_url)
        except etree.ParserError as e:
            print("ParserError",e)
    return (outputLinks, downloaded_url)

def is_valid(url):
    """
    Function returns True or False based on whether the url has to be downloaded or not. Robot rules and duplication rules are checked separately. This is a great place to filter out crawler traps.
    """
    parsed = urlparse(url)
    if parsed.scheme not in set(['http', 'https']):
        return False
    try:
        return validate_against_matchers(parsed, url)
    except TypeError:
        print ('TypeError for ', parsed)
        return False


def validate_against_matchers(parsed, url):
    """
    Validates against various matchers to make sure url doesn't contain traps and belong to a valid domain
    """
    no_invalid_types = invalid_types_matcher.match(parsed.path.lower()) == None
    no_cdn_url = content_del_matcher.match(parsed.path.lower()) == None
    not_exceed_length = length_matcher.match(url) == None
    not_keyword_trap = keywords_matcher.match(url.lower()) == None
    no_repeats = repeatition_matcher.match(url.lower()) == None
    is_valid_domain = domain_matcher.match(url.lower()) != None
    not_dynamic_url = True
    if config_data['filterDynamicURLs'] == True:
        not_dynamic_url = parsed.query == None or parsed.query == ''
    saved_state['invalid_urls'] = [url,is_valid_domain, no_invalid_types, no_cdn_url, not_exceed_length, not_keyword_trap, no_repeats, not_dynamic_url]
    return is_valid_domain and no_invalid_types and no_cdn_url and not_exceed_length and not_keyword_trap and no_repeats and not_dynamic_url


def extract_subdomain(url):
    parsed = urlparse(url)
    subdomain = parsed.netloc
    if subdomain not in config_data['allowedDomains']:
        subdomain = subdomain.replace('.ics.uci.edu', '')
        subdomain = subdomain.replace('www.', '')
    return subdomain


def save_state_and_print_analytics():
    print('*****SAVING THE PROGRESS...*******')
    with open('saved_state.json', 'w') as F:
        json.dump(saved_state, F)
    with open('analytics' + strftime('%Y%m%d') + '.txt', 'w') as analytics:
        analytics.write('Most out links found by domain: ' + saved_state['maxoutlinksdomain'] + ' count: ' + str(saved_state['maxoutlinks']))
        for subdomain in saved_state['subdomains']:
            analytics.write('\nVisited Subdomain ' + subdomain + " " +str(saved_state['subdomains'][subdomain]['visits']) + ' times' + ', Found ' + str(saved_state['subdomains'][subdomain]['outlinkscount']) + ' URLs in the pages from this domain and out of them ' + str(len(saved_state['subdomains'][subdomain]['valid_outlinks'])) + " valid links were detected")
        analytics.write('\n****************Redirects**************************')
        for redirect in saved_state['redirects']:
            analytics.write('\n' + redirect)
