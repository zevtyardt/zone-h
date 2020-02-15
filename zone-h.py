import requests
import html
import re
import threading
import queue
import logging
import signal
import socket
import random
import sys
from collections import OrderedDict

zonehome = 'http://www.zone-h.org/'
logging.basicConfig(format="%(threadName)s: %(message)s..", level=logging.INFO)
thread_lokal = threading.local()
q = queue.Queue()
urls = []

run = True

class CaptchaError(Exception):
    pass

def get_request():
    thread_lokal.sess = requests.Session()
    thread_lokal.sess.headers.update({
        'User-Agent': random.choice(('Mozilla/6.0 (Windows NT 6.2; WOW64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1',
                                     'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1',
                                     'Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1',
                                     'Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 Firefox/15.0a2',
                                     'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.16) Gecko/20120427 Firefox/15.0a1',
                                     'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20120427 Firefox/15.0a1',
                                     'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:15.0) Gecko/20120910144328 Firefox/15.0.2',
                                     'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:15.0) Gecko/20100101 Firefox/15.0.1',
                                     'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1',
                                     'Mozilla/5.0 (Windows NT 6.1; rv:14.0) Gecko/20120405 Firefox/14.0a1',
                                     'Mozilla/5.0 (Windows NT 5.1; rv:14.0) Gecko/20120405 Firefox/14.0a1',
                                     'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
                                     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_5_8) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535',
                                     'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/17.0.963.65 Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.04 Chromium/17.0.963.65 Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/10.10 Chromium/17.0.963.65 Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/17.0.963.65 Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
                                     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_4) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11'))
    })
    return thread_lokal.sess


def bypassTestCookie(jscode):
    logging.info("bypassing test-cookie protection")
    zhe = requests.post("http://zvtyrdt.000webhostapp.com/",
                        data={"jscode": jscode})
    assert zhe
    return {"ZHE": zhe.text.split("=")[1]}


class ZoneH(object):
    def register(self):
        self.sess = get_request()
        self.sess.cookies.update(cookies)

    def current_cookies(self, key=None):
        c = self.sess.cookies.get_dict()
        if key:
            return {key: c[key]}
        return c

    def make_request(self, *args, method="get", **kwargs):
        self.register()
        success = False
        html_response = ""
        tried = 0
        while not success:
            with getattr(self.sess, method)(*args, **kwargs) as resp:
                html_response = resp.text
                if "src=\"/captcha.py\"" in html_response or 'name="captcha"' in html_response:
                    raise CaptchaError(
                        "CaptchaError: please complete Captcha in the browser. url %s" % resp.url)
                elif "slowAES.decrypt(c,2,a,b))" in html_response and tried < 2:
                    cookie = bypassTestCookie(html_response)
                    self.sess.cookies.update(cookie)
                    logging.info("current cookies: %s",
                                 self.sess.cookies.get_dict())
                    tried += 1
                elif "/logout" not in html_response:
                    raise CaptchaError("SessionError: PHPSESSID is no longer valid")
                else:
                    success = True
        return resp

    def archive(self, fatal=True, **kwargs):
        try:
            url = zonehome + "archive/" + \
                  '/'.join('='.join(map(str, i)) for i in kwargs.items())
            logging.info("scrape %r", url)
            response = self.make_request(url).text

            if re.search(r"(?si)total.+?<b>0</b>", response):
                return None
            items = re.findall(r"(?si)\/archive\/notifier\=(?P<notifier>[^/\"]+).*?<td>(?P<url>\w+\.[\w.]+)[/.]", response)
            if kwargs.get("page"):
                logging.info("page %s got %s urls", kwargs["page"], len(items))
            for item in items:
                notifier, url = map(html.unescape, item)
                urls.append(url)
                yield notifier, url
        except Exception as e:
            if fatal:
                raise

    def all_archive(self, notifier=None, pagenum=None, fatal=True, **kwargs):
        # cannot use threading because threading is being used by another function
        if notifier:
            kwargs.update({"notifier": notifier})
        page = 1
        while page < (pagenum or 999999) + 1:
            kwargs.update({"page": page})
            arc = list(self.archive(fatal=fatal, **kwargs))
            if not arc:
                logging.info("no url found!")
                break
            for n, i in arc:
                yield i
            page += 1



class reverse_ip:
    @classmethod
    def run_all(self, url):
        for func in dir(self):
            if func.endswith("_lookup"):
                tmp_urls, err = getattr(self, func)(url)
                if tmp_urls:
                    urls.extend(tmp_urls)
                    msg = "%s got %s urls" % (url, len(tmp_urls))
                    logging.info("%s: queue %s: %s", func[:-7], q.qsize(), msg)
                else:
                    msg = 'failed: %s' % err
                    logging.debug("%s: queue %s: %s", func[:-7], q.qsize(), msg)

    @classmethod
    def hackertarget_lookup(self, url):
        with get_request().get("https://api.hackertarget.com/reverseiplookup/?q=" + url) as resp:
            x = re.findall(r"title>(.+?)</title",
                           resp.text) or resp.text.splitlines()
            if len(x) == 1 and not re.search(r"[\w\s.]+\.\w+", x[0]):
                return [None, x[0]]
            else:
                return [x, None]

    @classmethod
    def yougetsignal_lookup(self, url):
        with get_request().post("https://domains.yougetsignal.com/domains.php", data={"remoteAddress": url, "key": "", "_": ""}) as resp:
            js = resp.json()
            if js['status'] != 'Success':
                return [None, re.sub(r"<.+?>", "", js["message"])]
            else:
                return [[i[0] for i in js['domainArray']], None]

    @classmethod
    def bing_lookup(self, url):
        urls = []
        page = 1
        try:
            host = socket.gethostbyname(url)
            while True:
                with get_request().get("https://www.bing.com/search?q=ip:%s&page=%s" % (host, page)) as resp:
                    content = resp.text
                    if len(content) > 0:
                        urls.extend(re.findall(r"<cite>https?://([\w\d.]+\.\w+)</cite>", content))
                        page += 1
                    else:
                        break
            return [urls, "page blank!"]
        except Exception as e:
            return [None, str(e)]

    @classmethod
    def viewdns_lookup(self, url):
        with get_request().get("https://viewdns.info/reverseip/?host=%s&t=1" % url) as resp:
            all_dom = re.findall(r"<td>([\w\d.]+\.\w+)</td>", resp.text)
            if not all_dom:
                return [None, "Page blank!"]
            return [all_dom, None]


def write_f():
    if urls:
        logging.info("removing duplicate")
        sorted_url = OrderedDict().fromkeys(urls)
        logging.info("write %s urls to %s", len(sorted_url), args.output)
        with open(args.output, "a") as f:
            f.write("\n".join(sorted_url) + "\n")


def thread_worker(func):
    while run:
        item = q.get()
        func(item)
        q.task_done()

def sigint_handler(signum, frame):
    logging.info('Shutting down')
    run = False
    write_f()
    sys.exit(0)


signal.signal(signal.SIGINT, sigint_handler)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=70)
    )

    parser.add_argument("notifier", nargs="+", help="*notifier name")
    parser.add_argument("-c", "--phpsessid", metavar="VALUE",  help="valid Cookies[phpsessid]", required=True)
    pg = parser.add_mutually_exclusive_group(required=True)
    pg.add_argument("-p", "--page", metavar="NUM", type=int, help="Page archive, 1 - NUM")
    pg.add_argument("-a", "--all-archive", action="store_true", help="Scrape all archive, 1 ~")
    parser.add_argument("-t", "--threadnum", metavar="NUM", type=int, default=10, help="Thread num (default %(default)s)")
    parser.add_argument("-o", "--output", metavar="FILE", default="domains.txt", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")

    args = parser.parse_args()

    logging.info("\n\n\t@author     Val\n\t@facebook   https://fb.com/zvtyrdt.id\n\n")

    cookies = {"PHPSESSID": args.phpsessid}
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    zone = ZoneH()
    for _ in range(args.threadnum):
        th = threading.Thread(target=thread_worker, args=(reverse_ip.run_all,))
        th.daemon = True
        th.start()
    logging.info("%s threads started" % (_ + 1))

    try:
        for notify in args.notifier:
            for url in zone.all_archive(notifier=notify, pagenum=args.page):
                q.put(url)
    except Exception as e:
        run = False
        logging.error(e)

    q.join()
    write_f()  # KAORI MATI
