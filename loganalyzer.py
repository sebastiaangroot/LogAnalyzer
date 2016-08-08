#!/usr/bin/env python3

import subprocess, re, configparser, sys, json, time, smtplib, socket, fcntl, os, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SLEEP_INTERVAL = 0.5
PUBLIC_ADDR = "8.8.8.8"
PUBLIC_PORT = 53

def get_routable_addr():
  # backup
  ip = socket.gethostbyname(socket.gethostname())
  # better, but more prone to failure
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((PUBLIC_ADDR, PUBLIC_PORT))
    ip = s.getsockname()[0]
    s.close()
  except:
    pass
  return ip

def fatal(msg = '', code=1):
  print(msg)
  sys.exit(code)

def usage():
  print('usage: %s <config_file>' % (sys.argv[0],))
  print('example config file:')
  print('  [Config]')
  print('  LogFile = /var/log/example.log')
  print('  OutFile = /path/to/loganalyzer/example.log')
  print('  SMTPHost = smtp.example.org')
  print('  SMTPPort = 587')
  print('  SMTPTLS = yes')
  print('  APPEmail = example@example.org')
  print('  APPPassword = apikey')
  print('  Rules = [')
  print('      [ ".*regex.*to.*match", "rule name" ],')
  print('      [ ".*another.*rule"   , "second rule" ]')
  print('    ]')
  sys.exit(1)

def send_mail(msg, subject, config):
  s = None
  email = config.get('Config', 'APPEmail')
  mime_msg = MIMEMultipart()
  mime_msg['From'] = email
  mime_msg['To'] = email
  mime_msg['Subject'] = '[LogAnalyzer][%s] %s' % (get_routable_addr(), subject)
  mime_msg.attach(MIMEText(msg, 'plain'))
  try:
    s = smtplib.SMTP(config.get('Config', 'SMTPHost'), int(config.get('Config', 'SMTPPort')))
    if config.getboolean('Config', 'SMTPTLS'):
      s.starttls()
    s.login(email, config.get('Config', 'APPPassword'))
    s.sendmail(email, email, mime_msg.as_string())
  except:
    print('failed to sent mail')
  finally:
    if s:
      s.quit()

def matches_rules(line, rules):
  for rule, name in rules:
    if re.match(rule, line):
      return name
  return None

def monitor_logfile(filename, nonblocking = True):
  args = []
  args.append('tail')
  args.append('-f')
  args.append('-n')
  args.append('0')
  args.append(filename)
  try:
    tail = subprocess.Popen(
      args,
      stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if nonblocking:
      flags = fcntl.fcntl(tail.stdout, fcntl.F_GETFL)
      fcntl.fcntl(tail.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
  except:
    fatal('Error on call: tail -f -n 0 %s' % (filename,))
  return tail

def send_mailbuffer(mailbuffer, config):
  body = ''
  subj = ''

  for text, rule in mailbuffer:
    body += text
    if len(subj) == 0:
      subj = rule
    elif subj != rule:
      subj = 'mutliple rules'
  subj += ' (%d)' % (len(mailbuffer),)
  send_mail(body, subj, config)

def get_line(prog, logfile):
  try:
    if prog.poll() != None:
      fatal('tail -f -n 0 %s unexpectedly terminated' % (logfile,))
    line = prog.stdout.readline().decode('ascii', 'ignore')
  except KeyboardInterrupt:
    raise
  except OSError:
    return None
  except:
    fatal('Error reading from %s' % (logfile,))
  return line

def worker_monitor(config):
  # mail buffer
  last_sent = time.time()
  last_heartbeat = 0.0
  mailbuffer = []

  # Extract config items
  logfile = config.get('Config', 'LogFile')
  outfile = config.get('Config', 'OutFile')
  rules = json.loads(config.get('Config', 'Rules'))
  # Open file monitoring
  tail = monitor_logfile(logfile, nonblocking = True)
  # Start monitoring
  print('monitoring thread for %s started' % (logfile,))
  try:
    while True:
      time.sleep(SLEEP_INTERVAL)
      line = get_line(tail, logfile)
      if line:
        matched_rule = matches_rules(line, rules)
        if matched_rule:
          try:
            print('[LogAnalyzer] %s' % (matched_rule,))
            print(line, end='')
            with open(outfile, 'a') as f:
              f.write(line)
          except KeyboardInterrupt:
            raise
          except:
            fatal('Error writing to %s' % (outfile,))
          mailbuffer.append((line, matched_rule))
      if len(mailbuffer) > 0 and time.time() - last_sent > 60.0:
        try:
          send_mailbuffer(mailbuffer, config)
        except KeyboardInterrupt:
          raise
        except:
          fatal('Error sending mail')
        mailbuffer = []
        last_sent = time.time()
      if time.time() - last_heartbeat > 14400.0:
        send_mail(datetime.datetime.now().strftime('%Y-%m-%d %H:%M') + ' heartbeat', 'heartbeat', config)
        last_heartbeat = time.time()
  finally:
    if len(mailbuffer) > 0:
      print('sending %d stored events' % (len(mailbuffer),))
      send_mailbuffer(mailbuffer, config)
      mailbuffer = []

def validate_config(config):
  if not 'Config' in config:
    fatal('ConfigError: [Config] not present')
  if not 'LogFile' in config['Config']:
    fatal('ConfigError: LogFile not under [Config]')
  if not 'OutFile' in config['Config']:
    fatal('ConfigError: OutFile not under [Config]')
  if not 'Rules' in config['Config']:
    fatal('ConfigError: Rules not under [Config]')
  if not 'SMTPHost' in config['Config']:
    fatal('ConfigError: SMTPHost not under [Config]')
  if not 'SMTPPort' in config['Config']:
    fatal('ConfigError: SMTPPort not under [Config]')
  if not 'SMTPTLS' in config['Config']:
    fatal('ConfigError: SMTPTLS not under [Config]')
  if not 'APPEmail' in config['Config']:
    fatal('ConfigError: APPEmail not under [Config]')
  if not 'APPPassword' in config['Config']:
    fatal('ConfigError: APPPassword not under [Config]')
  try:
    json.loads(config.get('Config', 'Rules'))
  except:
    fatal('ConfigError: Unable to parse Rules\nFormat: Rules = [\n    ["regex", "rule name"]\n  ]')
  try:
    int(config.get('Config', 'SMTPPort'))
  except ValueError:
    fatal('ConfigError: [Config] SMTPPort should be a number')
  try:
    config.getboolean('Config', 'SMTPTLS')
  except ValueError:
    fatal('ConfigError: [Config] SMTPTLS should be boolean (yes/no, true/false)')

def launch_log_monitor(filepath):
  config = configparser.ConfigParser()
  config.read(filepath)
  validate_config(config)
  worker_monitor(config)

def main():
  if len(sys.argv) != 2 or sys.argv[1] == '-h' or sys.argv[1] == '--help':
    usage()
  launch_log_monitor(sys.argv[1])


if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print('Goodbye')
