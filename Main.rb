def get_10_IP(data)
	hash = Hash.new 
	for line in data
		ip=line[/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/]
		if hash.key?(ip)
			hash[ip]+=1
		else hash[ip]=1
		end
	end
	hash.sort_by{|key, value|value}.reverse
	array=Array.new
	for i in 0..9
		array.push(hash.keys[i].to_s)
	end
	array 
end
	
	
def get_suspicious_requests(data)
	array = Array.new
	for line in data
		number_of_signs=0
		if line[/((Windows NT 5.1)(.*)(rv:))|(Macintosh)|(Intel)/]
			number_of_signs+=1
		end
		if line[/Python-urllib\/2../]
			number_of_signs+=1
		end
		if line[/(HTTP\/1.1)(.*)(WEBDAV|MSIE 8.0|Telesphoreo)/]
			number_of_signs+=1
		end
		if line[/(\\x[0-9A-Z][0-9A-Z]){2,}/]
			number_of_signs+=1
		end
		if line[/(GET|POST|HEAD|PROPFIND|OPTIONS)(.*)(499 0 "-")/]
			number_of_signs+=1
		end
		if number_of_signs >= 2
			array.push(line)
		end
	end
	array
end
	
	file= File.open("access.log")
	fele_data=file.readlines.map(&:chomp)
	puts get_10_IP(fele_data)
	puts get_suspicious_requests(fele_data)