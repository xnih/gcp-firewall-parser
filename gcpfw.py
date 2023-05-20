import json

#https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
wellKnownProtocols = {
  1:"ICMP",
  4:"IPv4",
  6:"TCP",
  17:"UDP",
  41:"IPv6",
  58:"IPv6-ICMP"
}

f = open('gcp/project1.firewall.json')
data = json.load(f)
print('Receive TimeStamp, TimeStamp, Rule Name, Source IP, Source Port, Dest IP, Dest Port, Protocol, Action, Resource Labels, Resource Type, Instance, Geo, VPC')
for i in data:
  ID = i['insertId']
  jsonPayload = i['jsonPayload']
  log = i['logName']
  rtimestamp = i['receiveTimestamp']
  resource = i['resource']
  timestamp = i['timestamp']

  connection = jsonPayload['connection']
  disposition = jsonPayload['disposition']
  instance = jsonPayload['instance']
  geo = jsonPayload['remote_location']
  rule = jsonPayload['rule_details']
  vpc = jsonPayload['vpc']

  sip = connection['src_ip']
  dip = connection['dest_ip']
  dport = connection['dest_port']
  sport = connection['src_port']
  protocol = connection['protocol']
  try:
    proto = wellKnownProtocols[protocol]
  except:
    proto = protocol

  action = rule['action']
  direction = rule['direction']
  portInfo = rule['ip_port_info']
  priority = rule['priority']
  name = rule['reference']
  sourceRange = rule['source_range']

  print('%s,%s,%s,%s,%s,%s,%s,%s,%s,"%s","%s","%s","%s","%s"' % (rtimestamp, timestamp, name, sip, sport, dip, dport, proto, disposition, resource['labels'], resource['type'], instance, geo, vpc))
f.close()
