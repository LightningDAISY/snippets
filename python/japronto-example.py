#
#   sudo apt install libleveldb-dev libleveldb1v5 libsnappy1v5
#   sudo pip install plyvel
#   japronto --script THIS!!.py --worker=1
#
from japronto import Application
import plyvel

leveldb_path = "/var/www/db"
port_number = 12221
host_name = "0.0.0.0"

def open_leveldb(path):
  return plyvel.DB(path, create_if_missing=True)

def env(request):
  result =  "remote_addr: " + request.remote_addr + "\n" + \
            "hostname: " + request.hostname + "\n" + \
            "port: " + str(request.port) + "\n\n"
  if request.headers:
    for name,value in request.headers.items():
      result += "  {0}: {1}\n".format(name,value)
  return request.Response(text=result)

def db(request):
  result = "open"
  if DB.closed:
    result = "closed"
  else:
    DB.close()
    result = "close the DB"
  return request.Response(text=result)

DB = open_leveldb(leveldb_path)

app = Application()
app.router.add_route("/env", env)
app.router.add_route("/db", db)

app.run(debug=True, host=host_name, port=port_number)


