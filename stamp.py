################################################################################
#  Copyright (C) 2011-2012 Tempest Solutions <tempest AT klingebiel DOT com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  For a copy of the GNU General Public License write to:
#  Free Software Foundation, Inc.
#  59 Temple Place, Suite 330
#  Boston, MA  02111-1307  USA
################################################################################

import sys
import os
from shutil import copy2
from argparse import ArgumentParser
from datetime import datetime, timedelta
from re import match, search
from struct import unpack
from fnmatch import fnmatch
	
class MetadataFile:
	
	def __init__(self, path):
		# File system
		self.path = path
		self.directory, self.filename = os.path.split(path)
		self.filename_without_extension, self.extension = os.path.splitext(self.filename)
		self.file_datetime = datetime.fromtimestamp(os.path.getmtime(path))
		self.size = os.path.getsize(path)
		# DCF
		self.has_dcf_filename = (match(r'[0-9A-Za-z_]{4}[0-9]{4}\.[0-9A-Za-z]{3}$', self.filename) is not None)
		if self.has_dcf_filename:
			dcf_match = search(r'([0-9]{4,8})\.[0-9A-Za-z]{3}$', self.filename)
			self.dcf_volume = dcf_match.group(1)
			self.dcf_batch = self.filename[:(8-len(self.dcf_volume))]
			if self.dcf_batch.endswith("_"):
				self.dcf_batch = self.dcf_batch[:-1]
		else:
			self.dcf_batch = ""
			self.dcf_volume = ""
		# Metadata
		self.error = ""
		self.format = ""
		self.meta_datetime = datetime.min
		self.datetime = self.file_datetime
		self.sequence_num = 1
		self._minimum_year = 1990
	
	def build_filename(self):
		result = '{{DT={0}}}'.format(self.datetime.strftime('%Y-%m-%d @%H-%M-%S'))
		if self.sequence_num > 0:
			result += '{{SN={0:0>3}}}'.format(self.sequence_num)
		if len(self.dcf_volume) == 0:
			result += '{{CO={0}}}'.format(self.filename_without_extension)
		elif len(self.dcf_batch) > 0:
			result += '{{BA={0}}}{{VO={1}}}'.format(self.dcf_batch, self.dcf_volume)
		else:
			result += '{{VO={0}}}'.format(self.dcf_volume)
		result += self.extension.lower()
		return result
			
	def parse(self):
		# Open file
		try:
			self._file = open(self.path, "rb")
			# Get internal format
			try:
				self._get_format()
				# Get metadata date
				try:
					if self.format == "JPEG":
						self._parse_jpeg()
					elif self.format == "TIFF":
						self._parse_tiff()
					elif self.format == "RIFF":
						self._parse_riff()
					elif self.format == "CIFF":
						self._parse_ciff()
					elif self.format == "RAF":
						self._parse_raf()
					elif self.format == "QuickTime":
						self._parse_quicktime()
					# Validate date
					if self.meta_datetime.year < self._minimum_year:
						self.error = '{0}: metadata does not contain a valid date'.format(self.format)
				except Exception:
					self.error = '{0}: Unable to parse metadata: {1}'.format(self.format, sys.exc_value)
			except Exception:
				self.error = 'Unable to determine file format: {0}'.format(sys.exc_value)
		except Exception:
			self.error = 'Unable to open file: {0}'.format(sys.exc_value)
		finally:
			self._file.close()
	
	def _get_format(self):
		self._file.seek(0)
		data = self._file.read(8)
		if len(data) == 8:
			if data.startswith(chr(255) + chr(216)):
				self.format = "JPEG"
			elif (data.startswith("II") or data.startswith("MM")) and data.endswith("HE"):
				self.format = "CIFF"
			elif data.startswith("II" + chr(42) + chr(0)) or data.startswith("MM" + chr(0) + chr(42)):
				self.format = "TIFF"
			elif data.startswith("RIFF"):
				self.format = "RIFF"
			elif data.startswith("FUJIFILM"):
				self.format = "RAF"
			elif unpack(">L", data[0:4])[0] >= 8 and (data.endswith("ftyp") or data.endswith("pnot")):
				self.format = "QuickTime"
			else:
				raise Exception('File does not begin with a recognized metadata header')
		else:
			raise Exception('File is too short to be a recognized metadata file')
	
	def _parse_raf(self, offset=0):
		self._file.seek(offset)
		data = self._file.read(256)
		jpeg_offset = data.find(chr(255) + chr(216))
		if jpeg_offset < 0:
			raise Exception('RAF file does not contain a valid JPEG header within first 256 bytes')
		self._parse_jpeg(jpeg_offset)

	def _parse_ciff(self, offset=0):
		self._file.seek(offset)
		# Read 2 byte CIFF header
		data = self._file.read(2)
		if len(data) < 2:
			raise Exception('CIFF header should be 2 bytes long')
		# Get byte alignment from bytes 1-2
		if data.startswith("II"):
			# Intel = LittleEndian byte alignment
			self._byte_align = "<"
		elif data.startswith("MM"):
			# Motorola = BigEndian byte alignment
			self._byte_align = ">"
		else:
			raise Exception('CIFF header does not begin with II or MM')
		# Parse heap structure beginning with byte 27
		self._parse_ciff_heap(26, self.size - 26)
	
	def _parse_ciff_heap(self, offset, length):
		# Get table offset from last 4 bytes of heap
		self._file.seek(offset + length - 4)
		table_offset = unpack(self._byte_align + 'L', self._file.read(4))[0]
		# Get record count from first 2 bytes of table
		self._file.seek(offset + table_offset)
		num_records = unpack(self._byte_align + 'H', self._file.read(2))[0]
		# Parse 10 byte records
		record_offset = table_offset + 2
		while record_offset < (table_offset + 2 + num_records * 10) and self.meta_datetime.year < self._minimum_year:
			# Get record type from first 2 bytes of record
			self._file.seek(offset + record_offset)
			record_type = unpack(self._byte_align + 'H', self._file.read(2))[0]
			# Get record data offset, length
			if (record_type & 49152) == 0:
				# Record stored in heap space
				data_length = unpack(self._byte_align + 'L', self._file.read(4))[0]
				data_offset = unpack(self._byte_align + 'L', self._file.read(4))[0]
			elif (record_type & 49152) == 16384:
				# Record stored in offset table
				data_length = 8
				data_offset = record_offset + 2
			else:
				raise Exception('CIFF heap table contains invalid record type')
			# Process record
			if (record_type & 14336) == 10240 or (record_type & 14336) == 12288:
				# Recurse subheap
				self._parse_ciff_heap(offset + data_offset, data_length)
			elif (record_type & 2047) == 14:
				# Number of seconds since 1970-01-01 00:00:00 in bytes 1-4
				self._file.seek(offset + data_offset)
				seconds = unpack(self._byte_align + 'L', self._file.read(4))[0]
				self.meta_datetime = datetime(1970, 1, 1, 0, 0, 0) + timedelta(0, seconds)
			record_offset += 10

	def _parse_riff(self, offset=0, length=0):
		if length == 0:
			length = self.size
		endoffset = offset + length
		while offset < endoffset:
			self._file.seek(offset)
			# Read 8 byte chunk header + first 4 bytes of chunk data
			data = self._file.read(12)
			if len(data) < 12:
				raise Exception('RIFF chunk should be at least 12 bytes long')
			type = data[0:4]
			size = unpack('<L', data[4:8])[0]
			subtype = data[8:12]
			if type == 'RIFF' or (type == 'LIST' and subtype in ('INFO', 'exif', 'hdrl', 'strl')):
				# Recurse subchunks
				self._parse_riff(offset + 12, size - 4)
			elif type == 'IDIT':
				self._file.seek(offset + 8)
				data = self._file.read(size)
				if len(data) == 18:
					# Unknown source AVI uses format "YYYY/MM/DD HH:MM??" with no padding zeros and ?? = AM/PM
					self.meta_datetime = datetime.strptime(data.replace('/ ', '/0').replace('  ', ' 0').replace(': ', ':0'), '%Y/%m/%d %I:%M%p')
				elif len(data) > 23:
					# Canon AVI chunk uses format "DDD MMM DD HH:MM:SS YYYY" followed by null(s)
					self.meta_datetime = datetime.strptime(data[:24], '%a %b %d %H:%M:%S %Y')
			elif type == 'ICRD':
				# Exif 2.1 WAV AVI chunk uses format "YYYY-MM-DD" followed by null(s)
				self._file.seek(offset + 8)
				data = self._file.read(size)
				self.meta_datetime = datetime.strptime(data[:10], '%Y-%m-%d')
			elif type == 'etim':
				# Exif 2.1 WAV AVI chunk uses format "HH:NN:SS.FFFFFF" followed by null(s)
				self._file.seek(offset + 8)
				data = self._file.read(size)
				self.meta_datetime = datetime.combine(self.meta_datetime.date(), datetime.strptime(data[:8], '%H:%M:%S').time())
			elif type == 'LIST' and subtype == 'Cdat':
				# Scenalyzer AVI chunk uses format "YYYYMMDD HH.NN.SS" in bytes 13-29
				self._file.seek(offset + 8)
				data = self._file.read(size)
				self.meta_datetime = datetime.strptime(data[12:29], '%Y%m%d %H.%M.%S')
			elif type == 'strd':
				self._file.seek(offset + 8)
				# Fuji AVI chunk uses format "YYYY:MM:DD HH:NN:SS" in the middle of a long narrative
				data = self._file.read(size)
				self.meta_datetime = datetime.strptime(search(r'\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}', data).group(0), '%Y:%m:%d %H:%M:%S')
			offset = offset + 8 + size

	def _parse_jpeg(self, offset=0):
		while True:
			self._file.seek(offset)
			# Read 2-byte JPEG APPx marker and optional 2-byte tag size
			data = self._file.read(4)
			if len(data) < 2:
				raise Exception('JPEG marker should be 2 bytes long')
			marker = data[0:2]
			if (marker == chr(255) + chr(216)) or (marker == chr(255) + chr(217)):
				# FFD8, FFD9 are valid 2-byte SOI, EOI tags
				offset = offset + 2
				continue
			if len(data) < 4:
				raise Exception('JPEG markers other than SOI, EOI should be followed by 2-byte size')
			size = unpack('>H', data[2:4])[0]
			if size < 2:
				raise Exception('JPEG tag should have minimum size of 2 including 2-byte size')
			if marker == chr(255) + chr(225):
				# FFE1 is APP1 marker
				data = self._file.read(4)
				if data == "Exif":
					# Rest of APP1 data is in TIFF format
					self._parse_tiff(offset + 10)
					# Stop parsing JPEG tags
					break
				else:
					raise Exception('JPEG APP1 data should begin with "Exif"')
			else:
				offset = offset + size + 2

	def _parse_tiff(self, offset=0):
		self._file.seek(offset)
		# Read 8 byte TIFF header
		data = self._file.read(8)
		if len(data) < 8:
			raise Exception('TIFF header should be 8 bytes long')
		# Get byte alignment from bytes 1-2
		if data.startswith("II"):
			# Intel = LittleEndian byte alignment
			self._byte_align = "<"
		elif data.startswith("MM"):
			# Motorola = BigEndian byte alignment
			self._byte_align = ">"
		else:
			raise Exception('TIFF header does not begin with II or MM')
		# Get IFD0 offset from bytes 5-8
		ifd_offset = unpack(self._byte_align + 'L', data[4:8])[0]
		# Initialize dates
		self._tiff_datetime_modified = datetime.min
		self._tiff_datetime_original = datetime.min
		self._tiff_datetime_digitized = datetime.min
		# Parse IFD0
		self._parse_tiff_ifd(offset, ifd_offset)
		# Evaluate dates
		if self._tiff_datetime_original.year >= self._minimum_year:
			self.meta_datetime = self._tiff_datetime_original
		elif self._tiff_datetime_digitized.year >= self._minimum_year:
			self.meta_datetime = self._tiff_datetime_digitized
		elif self._tiff_datetime_modified.year >= self._minimum_year:
			self.meta_datetime = self._tiff_datetime_modified
	
	def _parse_tiff_ifd(self, tiff_offset, ifd_offset):
		self._file.seek(tiff_offset + ifd_offset)
		# Get IFD entry count from bytes 1-2
		data = self._file.read(2)
		if len(data) < 2:
			raise Exception('TIFF IFD should begin with 2-byte entry count')
		ifd_entries = unpack(self._byte_align + 'H', data)[0]
		# Parse entries (tolerate invalid IFD entry count, limit to 100)
		for entry in range(min(ifd_entries, 100)):
			self._file.seek(tiff_offset + ifd_offset + 2 + entry * 12)
			# Read 12-byte IFD entry
			data = self._file.read(12)
			if len(data) < 12:
				# Tolerate invalid IFD entry count, stop if reach EOF
				break
			# Get tag number from bytes 1-2
			tag_number = unpack(self._byte_align + 'H', data[0:2])[0]
			# Get offset to tag data from bytes 9-12
			tag_offset = unpack(self._byte_align + 'L', data[8:12])[0]
			if tag_number == 306:
				# DateTime Modified
				if self._tiff_datetime_modified.year < self._minimum_year:
					self._tiff_datetime_modified = self._parse_tiff_date(tiff_offset + tag_offset)
			if tag_number == 36867:
				# DateTime Original
				if self._tiff_datetime_original.year < self._minimum_year:
					self._tiff_datetime_original = self._parse_tiff_date(tiff_offset + tag_offset)
			if tag_number == 36868:
				# DateTime Digitized
				if self._tiff_datetime_digitized.year < self._minimum_year:
					self._tiff_datetime_digitized = self._parse_tiff_date(tiff_offset + tag_offset)
			elif tag_number == 34665:
				# Exif Offset (pointer to SubIFD)
				self._parse_tiff_ifd(tiff_offset, tag_offset)

	def _parse_tiff_date(self, offset):
		self._file.seek(offset)
		# Read 20 byte date string
		data = self._file.read(20)
		# Convert to datetime value
		try:
			return datetime.strptime(data[0:19], '%Y:%m:%d %H:%M:%S')
		except Exception:
			return datetime.min
			
	def _parse_quicktime(self, offset=0):
		while True:
			size = self._parse_quicktime_atom(offset)
			if size < 8:
				break
			offset = offset + size
	
	def _parse_quicktime_atom(self, offset):
		self._file.seek(offset)
		# Read first 8 bytes = simple atom header
		data = self._file.read(8)
		if len(data) < 8:
			# Atom should be at least 8 bytes long
			return len(data)
		else:
			size = unpack('>L', data[0:4])[0]
			type = data[4:8]
			if type == "moov":
				# Movie atom: parse child atoms
				self._parse_quicktime(offset + 8)
			if type == "mvhd":
				# Movie header atom: bytes 13-16 = seconds since 1904/01/01 00:00:00
				self._file.seek(offset + 12)
				seconds = unpack('>L', self._file.read(4))[0]
				self.meta_datetime = datetime(1904, 1, 1, 0, 0, 0) + timedelta(0, seconds)
				return 0
		return size

def main():

	# Get arguments
	argparser = ArgumentParser(description='Stamp 3.0.26 - timestamp digital camera media files')
	argparser.add_argument('SOURCE', help='directory containing files to be processed')
	argparser.add_argument('OUTPUT', help='directory into which processed files will be placed')
	argparser.add_argument('-s', '--simulate', help='simulate processing without actually changing any files', action='store_true', default=False)
	argparser.add_argument('-v', '--verbose', help='display detailed information about each file', action='store_true', default=False)
	argparser.add_argument('-c', '--copy', help='copy files to outdir rather than moving', action='store_true', default=False)
	arg_dir_group = argparser.add_argument_group('subdirectories')
	arg_dir_group.add_argument('-i', '--ignore', help='ignore subdirectories within SOURCE', dest='subdirs', action='store_const', const='Ignore')
	arg_dir_group.add_argument('-f', '--flatten', help='flatten SOURCE subdirectories into OUTPUT (default)', dest='subdirs', action='store_const', const='Flatten')
	arg_dir_group.add_argument('-p', '--preserve', help='preserve SOURCE subdirectories within OUTPUT', dest='subdirs', action='store_const', const='Preserve')
	argparser.set_defaults(subdirs='Flatten')
	arg_filter_group = argparser.add_argument_group('filter')
	arg_filter_group.add_argument('-m', '--metadata', help='use file system dates when metadata missing', action='store_true', default=False)
	arg_filter_group.add_argument('-d', '--dcf', help='tolerate non-DCF filenames', action='store_true', default=False)
	arg_filter_group.add_argument('-r', '--readonly', help='tolerate read-only files', action='store_true', default=False)
	arg_exclude_group = argparser.add_argument_group('exclude')
	arg_exclude_group.add_argument('--exclude', metavar='LIST', help='file or directory patterns (example: *.ctg;*.ind;*.log)', action='store', default='*/.*;*.CTG;*.IND;*.LOG;*.TXT')
	arg_exclude_group.add_argument('--include', metavar='LIST', help='file or directory patterns (example: *.jpg;*.mov;*.avi)', action='store', default='')
	args = argparser.parse_args()

	# Validate arguments
	try:
		if not os.path.exists(args.SOURCE):
			raise Exception('SOURCE directory does not exist: ' + args.SOURCE)
		if os.path.islink(args.SOURCE) or not os.path.isdir(args.SOURCE):
			raise Exception('SOURCE is not a directory: ' + args.SOURCE)
		if not os.path.exists(args.OUTPUT):
			raise Exception('OUTPUT directory does not exist: ' + args.OUTPUT)
		if os.path.islink(args.OUTPUT) or not os.path.isdir(args.OUTPUT):
			raise Exception('OUTPUT is not a directory: ' + args.OUTPUT)
		testdir = os.path.abspath(args.OUTPUT)
		while testdir != os.path.abspath(os.path.join(testdir, '..')):
			testdir = os.path.abspath(os.path.join(testdir, '..'))
			if testdir == os.path.abspath(args.SOURCE):
				raise Exception('OUTPUT directory may not be contained within SOURCE directory')
	except Exception:
		print sys.exc_value
		return 1

	# Initialize
	num_dirs = 0
	num_files = 0
	num_success = 0
	num_readonly_fail = 0
	num_dcf_fail = 0
	num_meta_fail = 0
	num_move_fail = 0
	chronkeys = set()

	# Process files
	for srcdir, subdirs, files in os.walk(args.SOURCE):
		# Directories
		if args.subdirs == 'Ignore' and os.path.abspath(srcdir) != os.path.abspath(args.SOURCE):
			continue
		num_dirs += 1
		# Files
		for filename in files:
			srcfil = os.path.normpath(os.path.join(srcdir, filename))
			# Exclude
			if len(args.exclude) > 0:
				include = True
				for pattern in args.exclude.split(';'):
					if fnmatch(os.path.abspath(srcfil), pattern):
						include = False
						break
				if not include:
					continue
			# Include
			if len(args.include) > 0:
				include = False
				for pattern in args.include.split(';'):
					if fnmatch(os.path.abspath(srcfil), pattern):
						include = True
						break
				if not include:
					continue
			# Source file
			num_files += 1
			# Read only
			if (not args.readonly):
				if not os.access(srcfil, os.W_OK):
					num_readonly_fail += 1
					if args.verbose:
						print '   {0}: Read-only'.format(srcfil)
					else:
						print '   {0}'.format(srcfil)
					continue
			# DCF
			mfile = MetadataFile(srcfil)
			if (not args.dcf) and (not mfile.has_dcf_filename):
				num_dcf_fail += 1
				if args.verbose:
					print '   {0}: Not a valid DCF filename'.format(srcfil)
				else:
					print '   {0}'.format(srcfil)
				continue
			# Date
			mfile.parse()
			if mfile.error == '':
				mfile.datetime = mfile.meta_datetime
			else:
				if args.metadata:
					mfile.datetime = mfile.file_datetime
				else:
					num_meta_fail += 1
					if args.verbose:
						print '   {0}: {1}'.format(srcfil, mfile.error)
					else:
						print '   {0}'.format(srcfil)
					continue
			# Output directory
			if args.subdirs == 'Preserve':
				outdir = os.path.join(args.OUTPUT, os.path.relpath(srcdir, args.SOURCE))
			else:
				outdir = args.OUTPUT
			# Output filename
			while True:
				outfil = os.path.normpath(os.path.join(outdir, mfile.build_filename()))
				chronkey = '{0}{1:0>3}{2}'.format(mfile.datetime.strftime('%Y%m%d%H%M%S'), mfile.sequence_num, mfile.extension.lower())
				if (not os.path.exists(outfil)) and (not chronkey in chronkeys):
					break
				mfile.sequence_num += 1
			chronkeys.add(chronkey)
			# Action
			if not args.simulate:
				try:
					# Output directory
					if not os.path.isdir(outdir):
						if os.path.isfile(outdir):
							raise Exception('Unable to create output directory: Output directory path refers to an existing file: {0}'.format(outdir))
						try:
							os.makedirs(outdir)
						except Exception:
							# Replace poor error message when makedirs fails due to file existing at intermediate directory path
							raise Exception('Unable to create output directory: {0}'.format(outdir))
					# Output file
					if args.copy:
						copy2(srcfil, outfil)
					elif os.stat(srcdir)[2] == os.stat(outdir)[2]:
						# Move to new location on same device
						os.rename(srcfil, outfil)
					else:
						# Copy to temp file on output device, verify, move into place, then remove from source device
						outtmp = os.path.normpath(os.path.join(outdir, '~stamp_temp'))
						copy2(srcfil, outtmp)
						if os.path.getsize(srcfil) == os.path.getsize(outtmp):
							os.rename(outtmp, outfil)
							os.remove(srcfil)
						else:
							raise Exception('Unable to copy source file: {0}'.format(srcfil))
				except Exception:
					num_move_fail += 1
					if args.verbose:
						print '   {0}: Unable to move/copy file: {1}'.format(srcfil, sys.exc_value)
					else:
						print '   {0}'.format(srcfil)
					continue
			# Report progress
			if args.verbose:
				print ' * {0}: {1}: {2} --> {3}'.format(srcfil, mfile.format, mfile.meta_datetime, outfil)
			else:
				print ' * {0}'.format(srcfil)
			num_success += 1
	
	# Report results
	if num_files == 0:
		print 'No files meet criteria in SOURCE: {0}'.format(args.SOURCE)
	elif num_success == num_files == 1:
		print '1 file successfully timestamped'
	elif num_success == num_files == 2:
		print 'Both files successfully timestamped'
	elif num_success == num_files:
		print 'All {0:,} files successfully timestamped'.format(num_success)
	else:
		# Fixed width digits
		digits = len('{0:,}'.format(max(num_files, num_dirs)))
		if num_success == 1:
			print ('{0:>' + str(digits) + ',} file successfully timestamped').format(num_success)
		else:
			print ('{0:>' + str(digits) + ',} files successfully timestamped').format(num_success)
		if num_readonly_fail > 1:
			print ('{0:>' + str(digits) + ',} files marked as read-only').format(num_readonly_fail)
		elif num_readonly_fail > 0:
			print ('{0:>' + str(digits) + ',} file marked as read-only').format(num_readonly_fail)
		if num_dcf_fail > 1:
			print ('{0:>' + str(digits) + ',} files do not have valid DCF filenames').format(num_dcf_fail)
		elif num_dcf_fail > 0:
			print ('{0:>' + str(digits) + ',} file does not have a valid DCF filename').format(num_dcf_fail)
		if num_meta_fail > 1:
			print ('{0:>' + str(digits) + ',} files do not have valid metadata dates').format(num_meta_fail)
		elif num_meta_fail > 0:
			print ('{0:>' + str(digits) + ',} file does not have a valid metadata date').format(num_meta_fail)
		if num_move_fail > 1:
			print ('{0:>' + str(digits) + ',} files could not be moved/copied').format(num_move_fail)
		elif num_move_fail > 0:
			print ('{0:>' + str(digits) + ',} file could not be moved/copied').format(num_move_fail)
		print '-' * digits
		if num_dirs > 1:
			print ('{0:>' + str(digits) + ',} total file' + ('' if num_files == 1 else 's') + ' in {1:,} directories').format(num_files, num_dirs)
		else:
			print ('{0:>' + str(digits) + ',} total file' + ('' if num_files == 1 else 's') + ' in {1}').format(num_files, os.path.normpath(args.SOURCE))
	if args.simulate:
		print '(simulation)'
	return 0

if __name__ == "__main__":
    sys.exit(main())
