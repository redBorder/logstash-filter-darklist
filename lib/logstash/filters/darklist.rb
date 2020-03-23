# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"

class LogStash::Filters::Darklist < LogStash::Filters::Base

  config_name "darklist"

  # Path allows you to indicate the path to the document that you want to load into memory for the creation of the hash.
  config :path, :validate => :path, :default => "/opt/rb/share/darklist.json", :required => false

  public
  def register
    # comprobar que el fichero existe 
    @ipCache = nil 
    if File.exist?(@path) then
      begin
        darklist_list = JSON.parse(File.read(@path))
        @ipCache = darklist_list.map { |n| [n["ip"], n["enrich_with"]] }.to_h
      rescue
         @ipCache = nil 
      end 
    end 
  end

  def filter(event)
    if @ipCache
      src = event.get("lan_ip")
      dst = event.get("wan_ip")
    
      eventData = {}  
      eventData['darklist_direction'] = "clean"
      eventData['darklist_category'] = "clean"
      
      srcData = @ipCache[src] if src 
      dstData = @ipCache[dst] if dst 
    
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
    end
    filter_matched(event)
    #yield event
  end  # def filter
end    # class Logstash::Filter::DarkList
