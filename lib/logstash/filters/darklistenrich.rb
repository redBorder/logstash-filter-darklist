# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"

class LogStash::Filters::DarklistEnrich < LogStash::Filters::Base

  config_name "darklist"

  # Path allows you to indicate the path to the document that you want to load into memory for the creation of the hash.
  config :path, :validate => :path, :default => "/opt/rb/share/darklist.json", :required => false

  public
  def register
    # comprobar que el fichero existe 
    if File.exist?(@path) then
      darklist_list = JSON.parse(File.read(@path))
      @ipCache = darklist_list.map { |n| [n["ip"], n["enrich_with"]] }.to_h
    end
  end

  def filter(event)
    src = event.get("lan_ip")
    dst = event.get("wan_ip")
    if !src.nil? && !dst.nil? then
      srcData = @ipCache['src']
      dstData = @ipCache['dst']
      if !srcData.nil? && !dstData.nil? then
        srcScore = srcData['darklist_score'].to_i
        dstScore = dstData['darklist_score'].to_i
        if (srcScore > dstScore) then
          srcData.each {|k,v| event.set(k,v)}
        else
          dstData.each {|k,v| event.set(k,v)}
        end
        event.set("darklist_direction", "both")
      elsif !srcData.nil? then
        srcData.each {|k,v| event.set(k,v)}
        event.set("darklist_direction", "source")
      elsif !dstData.nil? then
        dstData.each {|k,v| event.set(k,v)}
        event.set("darklist_direction", "destination")
      else
        event.set("darklist_direction", "clean")
        event.set("darklist_category", "clean")
      end
    elsif !src.nil? then
      srcData = @ipCache['src']
      if !srcData.nil? then
        srcData.each {|k,v| event.set(k,v)}
        event.set("darklist_direction", "source")
      else
        event.set("darklist_direction", "clean")
        event.set("darklist_category", "clean")
      end
    elsif !dst.nil? then
      dstData = @ipCache['dst']
      if !dstData.nil? then
        dstData.each {|k,v| event.set(k,v)}
        event.set("darklist_direction", "destination")
      else
        event.set("darklist_direction", "clean")
        event.set("darklist_category", "clean")
      end
    else
      event.set("darklist_direction", "clean")
      event.set("darklist_category", "clean")
    end
    filter_matched(event)
    #yield event
  end  # def filter
end    # class Logstash::Filter::DarkList
