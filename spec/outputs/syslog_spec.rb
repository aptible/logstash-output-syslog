require 'logstash/devutils/rspec/spec_helper'
require 'logstash/outputs/syslog'

describe LogStash::Outputs::Syslog do
  subject do
    plugin = LogStash::Plugin.lookup('output', 'syslog').new(
      'host' => @host, 'port' => @port,
      'facility' => 'user-level', 'severity' => 'informational',
      'protocol' => protocol, 'ssl_verify' => ssl_verify
    )
    plugin.register
    plugin
  end

  context 'tls-tcp' do
    let(:protocol) { 'tls-tcp' }
    let(:queue) { Queue.new }

    before(:all) do
      name = OpenSSL::X509::Name.new.add_entry('CN', '127.0.0.1')

      @key = OpenSSL::PKey::RSA.new(2048)
      @crt = OpenSSL::X509::Certificate.new
      @crt.serial = 1
      @crt.subject = name
      @crt.issuer = name
      @crt.not_before = Time.now
      @crt.not_after = Time.now + 3600
      @crt.public_key = @key.public_key
      @crt.sign @key, OpenSSL::Digest::SHA256.new
    end

    before do
      tcp_server = TCPServer.new('127.0.0.1', 0)

      ssl_ctx = OpenSSL::SSL::SSLContext.new
      ssl_ctx.cert = @crt
      ssl_ctx.key = @key
      ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, ssl_ctx)

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = @crt
      ef.issuer_certificate = @crt

      r, @close_pipe = IO.pipe

      [
        ef.create_extension('subjectAltName', 'DNS:127.0.0.1', false),
        ef.create_extension('basicConstraints', 'CA:TRUE', true)
      ].each { |ext| @crt.add_extension(ext) }

      # This server only accepts one message per connection

      Thread.new do
        loop do
          readable, = IO.select([ssl_server, r])
          break if readable.include?(r)
          next unless readable.include?(ssl_server)

          begin
            connection = ssl_server.accept
          rescue OpenSSL::SSL::SSLError => e
            queue << e
          else
            Thread.new { connection_handler.call(connection) }
          end
        end
      end

      @protocol = 'tls-tcp'
      @host = '127.0.0.1'
      @port = tcp_server.addr[1]
    end

    after do
      @close_pipe << 'x'
    end

    context 'without SSL verification' do
      let(:ssl_verify) { false }

      context 'with a server that hangs up' do
        let(:connection_handler) do
          proc do |connection|
            message = connection.gets
            queue << message
            connection.close
          end
        end

        it 'sends events' do
          10.times do |i|
            e = LogStash::Event.new('message' => "m#{i}", 'host' => 'h1')
            subject.receive(e)
          end

          # We're going to fail sending 50% of events due to an EOFError (but
          # Logstash would retry those), and we're going to inevitably miss a
          # few because syslog doesn't have acks, but overall we should still
          # be sending *some* events rather than reusing a dead connection.
          # NOTE: using Timeout.timeout isn't great, but it'll do for a test.
          Timeout.timeout(5) { 3.times { queue.pop } }
        end
      end

      context 'with a server that replies' do
        let(:connection_handler) do
          proc do |connection|
            loop do
              message = connection.gets
              queue << message
              connection.puts 'a' * 2048
            end
          end
        end

        it 'sends events' do
          10.times do |i|
            e = LogStash::Event.new('message' => "m#{i}", 'host' => 'h1')
            subject.receive(e)
          end

          Timeout.timeout(5) { 10.times { queue.pop } }
        end
      end
    end

    context 'with SSL verification' do
      let(:ssl_verify) { true }

      it 'does not connect' do
        20.times do |i|
          e = LogStash::Event.new('message' => "m#{i}", 'host' => 'h1')
          subject.receive(e)
        end

        loop do
          begin
            m = queue.pop(true)
          rescue ThreadError
            break
          else
            expect(m).to be_a(OpenSSL::SSL::SSLError)
          end
        end
      end
    end
  end
end
