curl -X POST 'http://localhost:49200/_security/user/kibana/_password' --user elastic:pwelastic \
  -H 'Content-Type:application/json'\
  -d '{"password" : "pwkibana"}'

curl -X POST 'http://localhost:49200/_security/user/logstash_system/_password' --user elastic:pwelastic \
  -H 'Content-Type:application/json'\
  -d '{"password" : "pwlogstash_system"}'
