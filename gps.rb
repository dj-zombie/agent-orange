#!/bin/ruby

tail = `head -n 7 gps.log`
latitude = tail.split("\n").grep(/Latitude:/)[0].split(' ')[2]
longitude = tail.split("\n").grep(/Longitude:/)[0].split(' ')[2]
binding.irb
puts "Lat: #{ latitude }"
puts "Lo: #{ longitude }"