#!/usr/bin/ruby
require 'iconv'
require 'pathname'
require 'pp'
require 'time'

require 'rubygems'
require 'bit-struct'
require 'builder'

module ICQ
class FormatError < Exception; end

module CustomPrinter
  def pretty_print(q)
    q.object_address_group(self) {
      q.seplist(pretty_print_instance_variables, lambda { q.text ',' }) { |v|
        q.breakable
        q.text v
        q.text '='
        q.group(1) {
          q.breakable ''
          meth = "pp_#{v}".to_sym
          if respond_to? meth
            q.text send(meth, v)
          else
            q.pp(send(v))
          end
        }
      }
    }
  end
  alias :inspect :pretty_print_inspect
end

class PageHeader < BitStruct
  vector(:magic, 5) { unsigned :m, 32 }
  signed :next, 32
  pad :pad, 32
  unsigned :slot_size, 32
  unsigned :free_frags, 32
  unsigned :free_slots, 32
  pad :pad2, 10 * 32
  char :bitmap, 125 * 8
  
  def self.read(*args)
    r = new(*args)
    raise FormatError.new("Index header") unless
      r.magic.map { |x| x.m } == [201, 0, 0, 0, 0]
    return r
  end
end

class Index
  class Header < BitStruct
    vector(:magic, 3) { unsigned :m, 32 }
    unsigned :root, 32
    unsigned :version, 32
    
    def self.read(*args)
      r = new(*args)
      raise FormatError.new("Index header") unless
        r.magic.map { |x| x.m } == [4, 20, 8]
      return r
    end
  end
  
  class Page
    class Slot < BitStruct
      signed :status, 32
      unsigned :dat_id, 32
      signed :next, 32
      signed :prev, 32
      signed :dat_off, 32
      
      attr_reader :pos
      def initialize(io)
        @pos = io.pos if io.respond_to? :pos
        super(io)
      end
      
      include CustomPrinter
      def pretty_print_instance_variables
        %w[status dat_id next prev dat_off pos]
      end
    end
    
    attr_reader :header, :slots
    def initialize(io)
      @header = PageHeader.read(io)
      @slots = []
      @header.bitmap.unpack('B*').first.split(//).each_with_index do |b, i|
        s = Slot.new(io)
        @slots << s if b == '1'
      end
    end
  end
  
  attr_reader :header, :linked, :slots
  def initialize(file)
    file = open(file) unless file.respond_to?(:eof?)
    @header = Header.read(file)
    @pages = []
    @pages << Page.new(file) until file.eof?
    
    @missing = {}
    @pages.each do |p|
      p.slots.each { |s| @missing[s.pos] = s }
    end
    @slots = @missing.values
    @linked = []
    epos = @header.root
    while epos != -1
      e = @missing.delete(epos)
      epos = e.next
      @linked << e
    end
  end
end

class Database
  class Header < BitStruct
    vector(:magic, 2) { unsigned :m, 32 }
    
    def self.read(*args)
      r = new(*args)
      raise FormatError.new("Index header") unless
        r.magic.map { |x| x.m } == [4, 8]
      return r
    end
  end
  
  class Page
   class Slot < BitStruct
      unsigned :length, 32
      signed :type, 32
      unsigned :dat_id, 32
      
      attr_reader :pos, :data, :padlen, :sig
      def initialize(io)
        @pos = io.pos if io.respond_to? :pos
        super(io)
        return unless io.respond_to? :read
        
        hdrlen = 8
        @data = io.read(length - hdrlen)
        @sig = @data[0, 4].reverse
        
        contentlen = length + 4
        align = 64
        q, r = contentlen.divmod(align)
        @padlen = (q + (r > 0 ? 1 : 0)) * align
        io.read(@padlen - contentlen)
      end
      
      def inspect
        include CustomPrinter
        def pretty_print_instance_variables
          %w[length type dat_id pos sig]
        end
      end
    end
    
    attr_reader :header, :slots
    def initialize(io)
      @header = PageHeader.read(io)
      @slots = []
      
      align = @header.slot_size
      skip = 0
      @header.bitmap.unpack('B*').first.split(//).each_with_index do |b, i|
        if b != '1'
          io.read(align)
        elsif skip.zero?
          s = Slot.new(io)
          skip = (s.padlen / align) - 1
          @slots << s
        else
          skip -= 1
        end
      end
    end
  end
  
  class Message < BitStruct
    char :type, 32
    char :subtype, 32
    pad :pad, 32
    unsigned :epoch, 32, :endian => :little
    unsigned :sender, 32, :endian => :little
    unsigned :recipient, 32, :endian => :little
    # What's in flags? Auth-request indicator?
    unsigned :flags, 32, :endian => :little
    unsigned :flags2, 32, :endian => :little
    unsigned :msglen, 16, :endian => :little
    rest :rest
    
    attr_reader :slot, :message
    def initialize(slot)
      return unless slot.respond_to? :data
      super(slot.data)
      @slot = slot
      self.type = type.reverse if type
      self.subtype = subtype.reverse if subtype
      
      # msglen may be offset by one (why?)
      mstart = 0
      # heuristic
      if (msglen & 0xff) == 0 && (rest[0] < 0x20 || msglen > 0xa00) 
        mstart = 1
        self.msglen = (rest[0] << 8) + ((msglen & 0xff00) >> 8)
      end
       
      # Message may contain multiple fields for auth requests?
      @message = rest[mstart, msglen - 1] # null terminated
      
      # some messages are unicode and have a fake msglen of 256
      if msglen == 256 && @message[0] == 0
        # 14 bytes of header: includes some kind of sequence number?
        len = 2 * (rest[14, 2].unpack('v').first - 1)
        @message = Iconv.conv('UTF8', 'UTF-16BE', rest[16, len])
      end
    end
    
    # Time is stored as epoch + offset, wtf?
    def timestamp
      t = Time.at(epoch)
      t - Time.zone_offset(t.zone)
    end
    def dat_type; slot.type; end
    def method_missing(meth, *args); slot.send(meth, *args); end
    
    include CustomPrinter
    def pretty_print_instance_variables
      %w[dat_type dat_id pos subtype timestamp sender recipient
        flags flags2 message]
    end
    
    def pp_flags(fld)
      "%#x" % send(fld)
    end
    alias :pp_flags2 :pp_flags
  end
  
  class Contact < BitStruct
    char :type, 32
    pad :pad, 32
    unsigned :uid, 32, :endian => :little
    unsigned :namelen, 16, :endian => :little
    rest :rest
    
    attr_reader :slot, :name
    def initialize(slot)
      return unless slot.respond_to? :data
      super(slot.data)
      @slot = slot
      self.type = type.reverse if type
      @name = rest[0, namelen - 1] # null term
    end
    
    def dat_type; slot.type; end
    def method_missing(meth, *args); slot.send(meth, *args); end
    
    include CustomPrinter
    def pretty_print_instance_variables
      %w[dat_type dat_id pos uid name]
    end
  end
  
  def by_sig(sig)
    @slots.select { |s| s.sig == sig }
  end
  
  # for debugging
  def count(msgs, fld, &disp)
    c = {}
    msgs.each do |m|
      k = m.send(fld)
      k = disp[k] if disp
      c[k] ||= 0
      c[k] += 1
    end
    pp c.sort
  end
  
  attr_reader :header, :slots, :messages, :contacts
  def initialize(file)
    file = open(file) unless file.respond_to?(:eof?)
    @header = Header.read(file)
    @pages = []
    @pages << Page.new(file) until file.eof?
    @slots = @pages.inject([]) { |a,p| a.concat(p.slots) }
    @messages = by_sig('Mira').map { |s| Message.new(s) }
    @contacts = by_sig('UAls').map { |s| Contact.new(s) }
  end
end

class Feedbag
  Contact = Struct.new(:uid, :name)
  
  def initialize(file)
    file = open(file) unless file.respond_to?(:eof?)
    @data = file.read
    
    # Use heuristics to find contact ids, names
    @contacts = {}
    @data.scan(/(\d{3,})\000/) do |uid,|
      # UID should be preceded by byte count
      next unless $`.size >= 2
      usize = $`[-2, 2].unpack('n').first
      next unless usize == uid.size
      
      # Ten chars later should be counted name
      next unless $'.size >= 12
      nsize = $'[9, 2].unpack('n').first
      # Size should be reasonable
      next if nsize == 0 or nsize > 256
      
      # Name should be nul-terminated
      next unless $'[11 + nsize, 1] == "\000"
      name = $'[11, nsize]
      # Should have reasonable contents
      next if /[\x00-\x1f]/.match(name)
      
      uid = uid.to_i
      c = Contact.new(uid, name)
      @contacts[uid] = c
    end
  end
    
  def contacts; @contacts.values; end
  def by_id(uid); @contacts[uid.to_i]; end
  def name(uid); c = by_id(uid); c && c.name; end
end

class HistoryExporter
  class Chat
    def timestamp; @messages.first.timestamp; end
    def contact; @namesrc.name(@cid) || @cid.to_s; end
    
    def initialize(myuid, cid, messages, namesrc)
      @messages, @myuid, @cid, @namesrc = messages, myuid, cid, namesrc
    end
    
    # Export to Adium ULF
    def ulf
      x = Builder::XmlMarkup.new(:indent => 4)
      x.instruct!
      x.chat(:xmlns => "http://purl.org/net/ulf/ns/0.4-02",
          :service => "ICQ",
          :account => @myuid) do |x|
        @messages.each do |msg|
          uid = msg.sender
          attrs = { :sender => uid, :time => msg.timestamp.xmlschema }
          cname = @namesrc.name(uid)
          attrs[:alias] = cname if cname
          x.message(attrs) { |x| x.div { |x| x.span(msg.message) } }
        end
      end
      x.target!
    end
  end
  
  def name(uid)
    (uid == @uid) ? @mynick : @feedbag.name(uid)
  end
  
  attr_reader :chats
  def initialize(dir, uid = nil, mynick = nil)
    dir = Pathname.new(dir)
    @uid = (uid ? uid : dir.basename.to_s).to_i
    @mynick = mynick
    @db = Database.new(dir + (@uid.to_s + '.db.dat'))
    @feedbag = Feedbag.new(dir + (@uid.to_s + '.fdb'))
    
    by_contact = {}
    @db.messages.each do |msg|
      contact = msg.sender
      contact = msg.recipient if contact == @uid
      (by_contact[contact] ||= []) << msg
    end
    
    addchat = proc do |msgs, cid|
      @chats << Chat.new(uid, cid, msgs, self)
    end
    
    # Messages more than an hour apart are in different chats
    @chats = []
    by_contact.each do |contact, msgs|
      last = nil
      chat = []
      msgs.sort_by { |m| m.timestamp }.each do |msg|
        if last && msg.timestamp - last > 60 * 60
          addchat[chat, contact]
          chat = []
        end
        chat << msg
        last = msg.timestamp
      end
      addchat[chat, contact]
    end
  end
  
  def adium(dir)
    dir = Pathname.new(dir)
    @chats.each do |chat|
      contact = chat.contact
      base = "%s (%s)" % [contact, chat.timestamp.xmlschema]
      STDERR.puts base
      file = dir + contact + (base + '.chatlog') + (base + '.xml')
      file.dirname.mkpath
      file.open('w') { |f| f.write(chat.ulf) }
    end
  end
end
end

if __FILE__ == $0
  require 'optparse'
  mynick = nil
  uid = nil
  OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename($0)} OUTDIR DATADIR UID [options]"
    opts.on('-n', '--nick NICK', "Nick of owning user") { |n| mynick = n }
    opts.on('-u', '--uid UID', "ICQ ID of owning user") { |u| uid = u }
  end.parse!
  outdir, indir = *ARGV
  exporter = ICQ::HistoryExporter.new(indir, uid, mynick)
  exporter.adium(outdir)
end
