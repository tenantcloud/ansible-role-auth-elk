input {
  beats {
    port => 5044
    host => "0.0.0.0"
    ssl => true
    ssl_certificate => "/etc/logstash/ssl/logstash.crt"
    ssl_key => "/etc/logstash/ssl/logstash8.key"
  }
}

filter {
  if [type] == "laravel" {
    grok {
      match => { "message" => "\[%{TIMESTAMP_ISO8601:logtime}\] %{DATA:env}\.%{DATA:severity}: %{DATA:logmessage}" }
      overwrite => [ "message" ]
    }
  }
  if [type] == "horizon_email" {
    grok {
      match => { "message" => "\[%{TIMESTAMP_ISO8601:logtime}\] %{DATA:env}\.%{DATA:severity}: %{DATA:user_id} %{DATA:email} %{GREEDYDATA:notification}" }
      overwrite => [ "message" ]
    }
  }
  if [type] == "horizon_queue" {
    grok {
      match => { "message" => "\[%{TIMESTAMP_ISO8601:logtime}\] %{DATA:env}\.%{DATA:severity}: %{INT:success} %{DATA:connection} %{DATA:queue} %{INT:size} %{GREEDYDATA:php_class}" }
      overwrite => [ "message" ]
    }
  }
  if [type] == "mysql_lag" {
    grok {
      match => { "message" => "\[%{TIMESTAMP_ISO8601:logtime}\] %{DATA:env} %{NUMBER:lagtime}" }
      overwrite => [ "message" ]
    }
    mutate {
      convert => ["lagtime", "integer"]
    }
  }
  if [type] == "nginx_access" {
    grok {
      patterns_dir => "/etc/logstash/patterns"
      match => { "message" => "%{NGINXACCESS}"}
      overwrite => [ "message" ]
    }
    mutate {
      convert => ["response", "integer"]
      convert => ["bytes", "integer"]
      convert => ["responsetime", "float"]
    }
    geoip {
      source => "remote_ip"
      target => "geoip"
      add_tag => [ "nginx-geoip" ]
    }
    date {
      match => [ "timestamp" , "dd/MMM/YYYY:HH:mm:ss Z" ]
      remove_field => [ "timestamp" ]
    }
    useragent {
      source => "agent"
    }
  }
  if [type] == "nginx_error" {
    grok {
      patterns_dir => "/etc/logstash/patterns"
      match => { "message" => "%{NGINXERROR}"}
    }
  }
  if [type] == "syslog" {
    grok {
      patterns_dir => "/etc/logstash/patterns"
      match => { "message" => "%{SYSLOGS}"}
      overwrite => [ "message" ]
    }
  }
  if [type] == "ws_message" {
    grok {
      match => { "message" => "\[%{TIMESTAMP_ISO8601:timestamp}\] %{DATA:env}\.%{LOGLEVEL:severity}: %{DATA:application} %{INT:wsint}" }
    }
    mutate {
      convert => ["wsint", "integer"]
    }
  }
  if [type] == "ws_peak" {
    grok {
      match => { "message" => "\[%{TIMESTAMP_ISO8601:timestamp}\] %{DATA:env}\.%{LOGLEVEL:severity}: %{DATA:application} %{INT:wsint}" }
    }
    mutate {
      convert => ["wsint", "integer"]
    }
  }
  if [type] == "ws_api" {
    grok {
      match => { "message" => "\[%{TIMESTAMP_ISO8601:timestamp}\] %{DATA:env}\.%{LOGLEVEL:severity}: %{DATA:application} %{INT:wsint}" }
    }
    mutate {
      convert => ["wsint", "integer"]
    }
  }
  if [type] == "full_nginx_access" {
    grok {
      patterns_dir => "/etc/logstash/patterns"
      match => { "message" => "%{FULLNGINX}"}
      overwrite => [ "message" ]
    }
    mutate {
      convert => ["response_code", "integer"]
      convert => ["body_bytes_sent", "integer"]
      convert => ["requst_time", "float"]
      convert => ["tc_user_id", "integer"]
      remove_field => [ "log" ]
      gsub => [ "request_body", "\\x22", '"']
      gsub => [ "request_body", "\\x0A", " "]
      gsub => [ "request_body", "\\n", " "]
    }
    geoip {
      source => "remote_ip"
      target => "geoip"
      add_tag => [ "nginx-geoip" ]
    }
    date {
      match => [ "timestamp" , "dd/MMM/YYYY:HH:mm:ss Z" ]
      remove_field => [ "timestamp" ]
    }
    useragent {
      source => "agent"
    }
  }
}

output {
  if [type] == "laravel" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "laravel-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "horizon_email" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "horizon-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "horizon_queue" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "horizon-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "mysql_lag" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "mysql-lag-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "nginx_access" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "nginx-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "nginx_error" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "nginx-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "full_nginx_access" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "full-nginx-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "syslog" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "syslog-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "ws_message" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "websocket-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "ws_peak" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "websocket-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
  if [type] == "ws_api" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "websocket-%{+YYYY.MM.dd}"
      user => ["{{ creds[0].username }}"]
      password => ["{{ creds[0].password }}"]
    }
  }
}
