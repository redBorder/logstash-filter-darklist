# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"

require_relative "util/memcached_config"

class LogStash::Filters::Darklist < LogStash::Filters::Base

  config_name "darklist"
  config :memcached_server,          :validate => :string, :default => nil,                            :required => false

  public
  def register
    @memcached_server = @memcached_server || MemcachedConfig::servers
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0, :value_max_bytes => 4000000})
  end

  def filter(event)

    src = event.get("lan_ip")
    dst = event.get("wan_ip")
  
    eventData = {}  
    eventData['darklist_direction'] = "clean"
    eventData['darklist_category'] = "clean"
    
    srcData = @memcached.get("darklist-#{src}") if src
    dstData = @memcached.get("darklist-#{dst}") if dst
  
    if srcData and dstData then
      eventData = (srcData['darklist_score'].to_i > dstData['darklist_score'].to_i) ? srcData : dstData
      eventData['darklist_direction'] =  "both"
    elsif srcData
      eventData = srcData
      eventData['darklist_direction'] = "source"
    elsif dstData  
      eventData = dstData
      eventData['darklist_direction'] = "destination"
    end 
          
    eventData.each {|k,v| event.set(k,v)}
    
    filter_matched(event)
    #yield event
  end  # def filter
end    # class Logstash::Filter::DarkList
