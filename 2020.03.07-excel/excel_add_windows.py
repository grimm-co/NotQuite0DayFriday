#!/usr/bin/env python3
# This python script modifies an Excel workbook file to open more Excel windows.
# This version uses string replacement rather than parsing the XML. When I tried
# using an XML parser to rewrite the Excel xml files, Excel refused to parse the
# new xlsx file, as its XML reader is very fragile.
import argparse
import os
import sys
import tempfile
import uuid

################################################################################
## Helper Functions ############################################################
################################################################################

def read_file(filename):
  fd = open(filename, "r")
  content = fd.read()
  fd.close()
  return content

def write_file(filename, content):
  fd = open(filename, "w")
  fd.write(content)
  fd.close()

def find_item(content, start_tag, end_tag, allow_fail = False):
  start = content.find(start_tag)
  if start < 0:
    print("Could not find {} item".format(start_tag))
    if allow_fail:
      return None, None
    sys.exit(1)
  end = content.find(end_tag, start + len(start_tag))
  end += len(end_tag)
  return content[start:end], end

################################################################################
## Main Execution ##############################################################
################################################################################

parser = argparse.ArgumentParser(description="Adds Window to an Excel workbook")
parser.add_argument("input", help="The input Excel workbook file")
parser.add_argument("output", help="IP output Excel workbook file")
parser.add_argument("-n", "--num-windows", default=10, type=int,
                    help="The number of windows to add")
args = parser.parse_args()

temp = tempfile.TemporaryDirectory()
if os.system("unzip {} -d {}/ > /dev/null".format(args.input, temp.name)) != 0:
  print("unzip failed")
  sys.exit(1)

# Parse the workbook.xml file
workbook_file = os.path.join(temp.name, "xl/workbook.xml")
content = read_file(workbook_file)
workbookview, after_workbookview = find_item(content, "<workbookView", "/>")
workbookview_uuid, after_uuid = find_item(workbookview, 'uid="', '"', True)
if workbookview_uuid != None:
  new_workbood_id = 'uid="{{{}}}"'
else:
  workbookview_uuid, after_uuid = find_item(workbookview, "uid='", "'")
  new_workbood_id = "uid='{{{}}}'"

# Duplicate the workbookView
for n in range(args.num_windows):
  new_uuid = new_workbood_id.format(uuid.uuid4().urn[9:].upper())
  new_view = workbookview.replace(workbookview_uuid, new_uuid)
  content = content[:after_workbookview]+new_view+content[after_workbookview:]

# Write back the new workbook.xml
write_file(workbook_file, content)

# Parse the sheet1.xml file
sheet_file = os.path.join(temp.name, "xl/worksheets/sheet1.xml")
content = read_file(sheet_file)
sheetview, after_sheetview = find_item(content, "<sheetView ", "/>")
sheetview_id, after_sheetview_id = find_item(sheetview, 'workbookViewId="', '"',
                                             True)
if sheetview_id != None:
  new_workbood_id = 'workbookViewId="{}"'
else:
  sheetview_id, after_sheetview_id = find_item(sheetview,"workbookViewId='","'")
  new_workbood_id = "workbookViewId='{}'"

# Duplicate the sheetView
for n in range(args.num_windows):
  new_view = sheetview.replace(sheetview_id, new_workbood_id.format(n+1))
  content = content[:after_sheetview] + new_view + content[after_sheetview:]

# Write back the new workbook.xml
write_file(sheet_file, content)

# zip the edited xlsx file
if os.system("cd {}; zip {} -r . > /dev/null".format(temp.name, os.path.abspath(args.output))):
  print("zip failed")
  sys.exit(1)

