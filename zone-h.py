import requests
import html
import re
import threading
import queue
import logging
import signal
import socket
import random
import os
import sys
from urllib.parse import quote
from collections import OrderedDict

zonehome = 'http://www.zone-h.org/'
logging.basicConfig(format="%(threadName)s: %(message)s", level=logging.INFO)
thread_lokal = threading.local()
q = queue.Queue()
proxies = queue.Queue()
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
        self.update_proxies()

    def current_cookies(self, key=None):
        c = self.sess.cookies.get_dict()
        if key:
            return {key: c[key]}
        return c

    def update_proxies(self):
        if not proxies.empty():
            proxy = proxies.get()
            self.sess.proxies.update({
                "http": "http://" + proxy,
                "https": "https://" + proxy
            })
            proxies.task_done()
        else:
            logging.error("clearing proxies")
            self.sess.proxies.clear()

    def make_request(self, *nargs, method="get", **kwargs):
        self.register()
        success = False
        tried = 0
        html_response = ""
        while not success:
            try:
              with getattr(self.sess, method)(*nargs, **kwargs) as resp:
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
                    raise CaptchaError(
                        "SessionError: PHPSESSID is no longer valid")
                else:
                    success = True
            except requests.exceptions.ProxyError:
                logging.error("cannot connect to proxy: %s", self.sess.proxies["http"])
                self.update_proxies()
            except (requests.exceptions.InvalidProxyURL, requests.exceptions.InvalidURL) as e:
                logging.error(e)
                self.update_proxies()
        return resp

    def safe_url(self, **kwargs):
        params = "/".join("=".join((param, quote(quote(str(value), safe=""))))
            for param, value in kwargs.items() if value is not None)
        return zonehome + "archive/" + params

    def archive(self, fatal=True, **kwargs):
        try:
            url = self.safe_url(**kwargs)
            logging.info("scrape %r", url)
            response = self.make_request(url).text
            if re.search(r"(?si)total.+?<b>0</b>", response):
                return None
            items = re.findall(
                r"(?si)<td>\s*(?P<url>[\w\d.]+)[/.]\s*", response)
            if kwargs.get("page"):
                logging.info("page %s got %s urls", kwargs["page"], len(items))
            for url in items:
                urls.append(url)
                yield url
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
                break
            for i in arc:
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
                    logging.debug("%s: queue %s: %s",
                                  func[:-7], q.qsize(), msg)

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
                        urls.extend(re.findall(
                            r"<cite>https?://([\w\d.]+\.\w+)</cite>", content))
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
    with threading.Lock():
        while run:
            item = q.get()
            func(item)
            q.task_done()

def add_proxy(l):
    logging.info("setting up %s proxies", len(l))
    for p in l:
        proxies.put(p)

def sigint_handler(signum, frame):
    logging.info('shutting down')
    run = False
    write_f()
    sys.exit(0)


signal.signal(signal.SIGINT, sigint_handler)

if __name__ == '__main__':
    import argparse

    logging.info("\n\n\t@author     Val\n\t@facebook   https://fb.com/zvtyrdt.id\n\n")

    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog, max_help_position=70)
    )

    parser.add_argument("notifier", nargs="*", help="*notifier name, default random.", default=[None])
    parser.add_argument("-c", "--phpsessid", metavar="VALUE", help="valid Cookies[PHPSESSID].", required=True)
    parser.add_argument("-s", "--special", action="store_true", help="Special defacements only.")
    parser.add_argument("-u", "--unpublished", action="store_true", help="Onhold (Unpublished) only.")
    pg = parser.add_mutually_exclusive_group(required=True)
    pg.add_argument("-p", "--page", metavar="NUM", type=int, help="Page archive, 1 - NUM.")
    pg.add_argument("-a", "--all-archive", action="store_true", help="Scrape all pages, 1 ~.")
    parser.add_argument("-t", "--threadnum", metavar="NUM", type=int, default=10, help="Thread num (default %(default)s).")
    pr = parser.add_mutually_exclusive_group(required=False)
    pr.add_argument("-x", "--proxy", metavar="IP:PORT", help="Use the specified HTTP/HTTPS/SOCKS proxy.")
    pr.add_argument("-X", "--proxies", metavar="FILE", help="Use the specified HTTP/HTTPS/SOCKS proxy list.")
    parser.add_argument("-o", "--output", metavar="FILE", default="domains.txt", help="Output file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode.")

    args = parser.parse_args()

    cookies =  {"PHPSESSID": args.phpsessid}
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    zone = ZoneH()
    for _ in range(args.threadnum):
        th = threading.Thread(target=thread_worker, args=(reverse_ip.run_all,))
        th.daemon = True
        th.start()
    logging.info("%s threads started" % (_ + 1))

    try:
        if args.proxy:
            add_proxy([args.proxy])
        elif args.proxies:
            add_proxy(open(args.proxies).read().splitlines())
        logging.info("notifier selected: %s", "random" if not args.notifier[0] and len(args.notifier) == 1 else ", ".join(args.notifier))
        for notify in args.notifier:
            for url in zone.all_archive(notifier=notify, pagenum=args.page,
                                        special=1 if args.special else None,
                                        published=0 if args.unpublished else None):
                q.put(url)
    except Exception as e:
        run = False
        logging.critical(e)

    q.join()
    write_f()  # KAORI MATI
