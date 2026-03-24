# -*- coding:utf-8 -*-
import time
import socket
import random
import dns
import numpy as np
from dns.resolver import NoMetaqueries, NoAnswer, NoNameservers, YXDOMAIN, NXDOMAIN, Answer, Resolver
from dns.edns import ECSOption
import threading
import csv

class EdnsResolver(Resolver):
    def __init__(self):
        super().__init__()
        self.edns = 0

    def query(self, qname, rdtype=dns.rdatatype.AAAA, rdclass=dns.rdataclass.IN,
              tcp=False, source=None, raise_on_no_answer=True, source_port=0,
              lifetime=15, edns_option=None, name_servers=None):
        """
        支持edns的query
        :param qname: 同原query
        :param rdtype: 同原query
        :param rdclass: 同原query
        :param tcp: 同原query
        :param source: 同原query
        :param raise_on_no_answer: 同原query
        :param source_port: 同原query
        :param lifetime: 同原query
        :param edns_option: EDNS选项，参考dns.edns.Option
        :param name_servers: 指定dns服务器
        :return: 同原query
        """
        if isinstance(qname, str):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if dns.rdatatype.is_metatype(rdtype):
            # raise NoMetaqueries
            print(NoMetaqueries)
            return None
        if isinstance(rdclass, str):
            rdclass = dns.rdataclass.from_text(rdclass)
        if dns.rdataclass.is_metaclass(rdclass):
            # raise NoMetaqueries
            print(NoMetaqueries)
            return None
        qnames_to_try = []
        if qname.is_absolute():
            qnames_to_try.append(qname)
        else:
            if len(qname) > 1:
                qnames_to_try.append(qname.concatenate(dns.name.root))
            if self.search:
                for suffix in self.search:
                    qnames_to_try.append(qname.concatenate(suffix))
            else:
                qnames_to_try.append(qname.concatenate(self.domain))
        all_nxdomain = True
        nxdomain_responses = {}
        start = time.time()
        _qname = None  # make pylint happy
        for _qname in qnames_to_try:
            if self.cache:
                answer = self.cache.get((_qname, rdtype, rdclass))
                if answer is not None:
                    if answer.rrset is None and raise_on_no_answer:
                        # raise NoAnswer(response=answer.response)
                        print(answer.response)
                        return None
                    else:
                        return answer
            request = dns.message.make_query(_qname, rdtype, rdclass)
            if self.keyname is not None:
                request.use_tsig(self.keyring, self.keyname,
                                 algorithm=self.keyalgorithm)
            request.use_edns(options=edns_option)
            if self.flags is not None:
                request.flags = self.flags
            response = None
            #
            # make a copy of the servers list so we can alter it later.
            #
            if name_servers:
                nameservers = name_servers
            else:
                nameservers = self.nameservers[:]
            errors = []
            if self.rotate:
                random.shuffle(nameservers)
            backoff = 0.10
            while response is None:
                if len(nameservers) == 0:
                    # raise NoNameservers(request=request, errors=errors)
                    print(errors)
                    continue
                for nameserver in nameservers[:]:
                    try:
                        timeout = self._compute_timeout(start, lifetime)
                    except dns.exception.Timeout as ex:
                        response = None
                        continue
                    port = self.nameserver_ports.get(nameserver, self.port)
                    try:
                        tcp_attempt = tcp
                        if tcp:
                            response = dns.query.tcp(request, nameserver,
                                                     timeout, port,
                                                     source=source,
                                                     source_port=source_port)
                        else:
                            response = dns.query.udp(request, nameserver,
                                                     timeout, port,
                                                     source=source,
                                                     source_port=source_port)
                            if response.flags & dns.flags.TC:
                                # Response truncated; retry with TCP.
                                tcp_attempt = True
                                try:
                                    timeout = self._compute_timeout(start, lifetime)
                                except dns.exception.Timeout as ex:
                                    response = None
                                    continue
                                response = \
                                    dns.query.tcp(request, nameserver,
                                                  timeout, port,
                                                  source=source,
                                                  source_port=source_port)
                    except (socket.error, dns.exception.Timeout) as ex:
                        #
                        # Communication failure or timeout.  Go to the
                        # next server
                        #
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        response = None
                        continue
                    except dns.query.UnexpectedSource as ex:
                        #
                        # Who knows?  Keep going.
                        #
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        response = None
                        continue
                    except dns.exception.FormError as ex:
                        #
                        # We don't understand what this server is
                        # saying.  Take it out of the mix and
                        # continue.
                        #
                        nameservers.remove(nameserver)
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        response = None
                        continue
                    except EOFError as ex:
                        #
                        # We're using TCP and they hung up on us.
                        # Probably they don't support TCP (though
                        # they're supposed to!).  Take it out of the
                        # mix and continue.
                        #
                        nameservers.remove(nameserver)
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        response = None
                        continue
                    rcode = response.rcode()
                    if rcode == dns.rcode.YXDOMAIN:
                        ex = YXDOMAIN()
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        # raise ex
                        continue
                    if rcode == dns.rcode.NOERROR or \
                            rcode == dns.rcode.NXDOMAIN:
                        break
                    #
                    # We got a response, but we're not happy with the
                    # rcode in it.  Remove the server from the mix if
                    # the rcode isn't SERVFAIL.
                    #
                    if rcode != dns.rcode.SERVFAIL or not self.retry_servfail:
                        nameservers.remove(nameserver)
                    errors.append((nameserver, tcp_attempt, port,
                                   dns.rcode.to_text(rcode), response))
                    response = None
                if response is not None:
                    break
                #
                # All nameservers failed!
                #
                if len(nameservers) > 0:
                    #
                    # But we still have servers to try.  Sleep a bit
                    # so we don't pound them!
                    #
                    try:
                        timeout = self._compute_timeout(start, lifetime)
                    except dns.exception.Timeout as ex:
                        continue
                    sleep_time = min(timeout, backoff)
                    backoff *= 2
                    time.sleep(sleep_time)
            if response.rcode() == dns.rcode.NXDOMAIN:
                nxdomain_responses[_qname] = response
                continue
            all_nxdomain = False
            break
        if all_nxdomain:
            return None
            # raise NXDOMAIN(qnames=qnames_to_try, responses=nxdomain_responses)
        answer = Answer(_qname, rdtype, rdclass, response,
                        raise_on_no_answer)
        if self.cache:
            self.cache.put((_qname, rdtype, rdclass), answer)
        return answer

    def ecs_query(self, qname, address, name_servers=None, srclen=56, rdtype=dns.rdatatype.AAAA):
        """
        基于ecs封装了一下query，建单实现ecs查询
        :param qname: 带解析域名
        :param address: ecs地址
        :param name_servers: 指定dns
        :param srclen: ecs地址的子网掩码
        :param rdtype: 解析方式
        :return: 同原query
        """
        try:
            ecs = ECSOption(address, srclen)  # 子网掩码必须填写32(默认是24)，部分dns不支持解析24的C段
        except dns.exception.SyntaxError as ex:
            print(ex)
            print("Input is malformed, skipping...")
            return None
        return self.query(qname, rdtype, edns_option=[ecs], name_servers=name_servers)
# !/usr/bin/python
# -*- coding: UTF-8 -*-

import threading
import time

exitFlag = 0


class myThread(threading.Thread):  # 继承父类threading.Thread
    def __init__(self, domain_list, num):
        threading.Thread.__init__(self)
        self.domain_list = domain_list
        self.num = num

    def run(self):  # 把要执行的代码写到run函数里面 线程在创建后会直接运行run函数
        '''
        esc_list = ["2001:250:03ff:0002::", "2001:250:05ff:0005::", "2001:250:09ff:000f::", "2001:250:0cff:0015::",
                    "2001:250:0cff:0241::", "2001:250:1000:0548::", "2001:250:14ff:0751::", "2001:250:18ff:3671::",
                    "2001:250:1cff:0312::", "2001:250:1eff:0002::", "2001:250:20ff:0712::", "2001:250:24ff:1234::",
                    "2001:250:28ff:0571::", "2001:250:2cff:0314::", "2001:250:2eff:000a::", "2001:250:30ff:0341::",
                    "2001:250:34ff:1324::", "2001:250:38ff:0002::", "2001:250:3cff:0124::", "2001:250:40ff:0071::",
                    "2001:250:44ff:000f::", "2001:250:48ff:000f::", "2001:250:50ff:000f::", "2001:250:54ff:f000::",
                    "2001:250:58ff:0012::", "2001:250:60ff:0342::", "2001:250:64ff:1320::", "2001:250:68ff:1020::",
                    "2001:250:6cff:0032::", "2001:250:70ff:2610::", "2001:250:74ff:0021::", "2001:250:78ff:0004::",
                    "2409:8a00::0001", "2409:8a02::0001", "2409:8a04::0001", "2409:8a0c::0001", "2409:8a10::0001",
                    "2409:8a14::0001", "2409:8a18::0001", "2409:8a1a::0001", "2409:8a1e::0001", "2409:8a20::0001",
                    "2409:8a28::0001", "2409:8a30::0001", "2409:8a34::0001", "2409:8a38::0001", "2409:8a3c::0001",
                    "2409:8a44::0001", "2409:8a4c::0001", "2409:8a50::0001", "2409:8a54::0001", "2409:8a74::0001",
                    "2409:8a5c::0001", "2409:8a5e::0001", "2409:8a60::0001", "2409:8a62::0001", "2409:8a78::0001",
                    "2409:8a6a::0001", "2409:8a6c::0001", "2409:8a7e::0001", "2409:8a70::0001", "2409:8a7a::0001", "2409:8a7c::0001",
                    "2606:9580:438:32::b02e", "2001:0600:438:32::b02a", "2409:8900:9cd1:854d:b8ce:b5b8:f59f:8078", "fe80::11e0:31b4:c8d5:60c2"]
                    
        '''
        esc_list = ["2606:9580:438:32::b02e", "2001:0600:438:32::b02a", "2409:8900:9cd1:854d:b8ce:b5b8:f59f:8078", "2408:8638:118:14:145f:7e45:d76d:8fef"]
        server_list = ['2001:4860:4860::8888', '240e:4c:4008::1', '2400:3200::1', '240C::6666']
        results = []


        for domain in self.domain_list:
            print(domain)
            resolver = EdnsResolver()
            for i in range(2000):
                for esc in esc_list:
                    a = resolver.ecs_query(domain, address=esc, name_servers=server_list)
                    if a and a.response:
                        for i in a.response.answer:
                            for j in i.items:
                                if [str(j), domain] not in results:
                                    results.append([str(j), domain])
                                    with open("./sn_result{}.csv".format(self.num), "a") as csvfile:
                                        writer = csv.writer(csvfile)
                                        writer.writerow([str(j),domain])
                                    csvfile.close()

if __name__ == '__main__':

    # # 文件输入
    # domain_file = 'white (no).txt'  # 前台需要传递的参数
    # with open(domain_file) as f:
    #     # 读取每一行并去除行尾的换行符
    #     domain_list = [line.strip() for line in f]

    domain_list = [["pornhub.com"], ["tiktok.com"], ["eBay.com"], ["Amazon.com"], ["Instagram.com"], ["LinkedIn.com"], ["Netflix"]]
    # temp = myThread(domain_list, 0)
    # temp.start()
    # 创建新线程
    thread_list = []
    max_thread = 7
    # slice = int(len(domain_list) / 20)
    for i in range(max_thread):
        thread_list.append(myThread(domain_list[i], i))
    for i in range(max_thread):
        thread_list[i].start()