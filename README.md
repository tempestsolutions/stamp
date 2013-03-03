# Stamp

Stamp is a utility that timestamps picture, audio, and video files from digital
cameras so that they sort chronologically. Stamp does this by figuring out when
files were originally recorded and then renaming them so that their filenames
begin with a date/time label. Stamp is safe because all it does is rename files
and move them from one place to another - it will never alter or corrupt the
contents of your files. After you run Stamp on a group of files, you can sort
the files alphabetically by filename and they will arrange themselves in
chronological order.

## Usage

    usage: stamp.py [-h] [-s] [-v] [-c] [-i] [-f] [-p] [-m] [-d] [-r]
                      [--exclude LIST] [--include LIST]
                    SOURCE OUTPUT

    Stamp 3.0.26 - timestamp digital camera media files

    positional arguments:
      SOURCE          directory containing files to be processed
      OUTPUT          directory into which processed files will be placed

    optional arguments:
      -h, --help      show this help message and exit
      -s, --simulate  simulate processing without actually changing any files
      -v, --verbose   display detailed information about each file
      -c, --copy      copy files to outdir rather than moving

    subdirectories:
      -i, --ignore    ignore subdirectories within SOURCE
      -f, --flatten   flatten SOURCE subdirectories into OUTPUT (default)
      -p, --preserve  preserve SOURCE subdirectories within OUTPUT

    filter:
      -m, --metadata  use file system dates when metadata missing
      -d, --dcf       tolerate non-DCF filenames
      -r, --readonly  tolerate read-only files

    exclude:
      --exclude LIST  file or directory patterns (example: *.ctg;*.ind;*.log)
      --include LIST  file or directory patterns (example: *.jpg;*.mov;*.avi)

## Reference

Original Windows [binary](http://www.klingebiel.com/tempest/hd/stamp.php4).

Original, in depth [user guide](http://www.klingebiel.com/tempest/hd/Stamp_2.8_User_Guide.htm).



