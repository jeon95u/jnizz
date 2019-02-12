from flask import Flask, render_template, request, g
import sqlite3
import os
import time, datetime
import json
import logging

app = Flask(__name__)
app.logger.disabled = True

log = logging.getLogger('werkzeug')
log.disabled = True

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')

start_unix = time.time()
start_date = datetime.datetime.fromtimestamp(start_unix).strftime('%Y.%m.%d')
start_time = datetime.datetime.fromtimestamp(start_unix).strftime('%H:%M:%S') 


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def getCrash():
    cs = get_db().cursor()
    
    cs.execute("SELECT count(*) FROM crash;")
    crash_cnt = cs.fetchall()[0][0]

    cs.execute("SELECT count(*) FROM crash WHERE exploitable='Exploitable';")
    exp_cnt = cs.fetchall()[0][0]

    cs.execute("SELECT count(*) FROM crash WHERE exploitable='Probably Exploitable';")
    pro_exp_cnt = cs.fetchall()[0][0]

    cs.execute("SELECT count(*) FROM crash WHERE exploitable='Probably Not Exploitable';")
    pro_not_exp_cnt = cs.fetchall()[0][0]

    cs.execute("SELECT count(*) FROM crash WHERE exploitable='Not Exploitable';")
    not_exp_cnt = cs.fetchall()[0][0]

    return [crash_cnt, exp_cnt, pro_exp_cnt, pro_not_exp_cnt, not_exp_cnt]


@app.route('/')
def index():
    crash = getCrash()
    return render_template('index.html', start=[start_date, start_time, start_unix], crash_cnt=crash[0], exploitable_cnt=[crash[1], crash[2], crash[3], crash[4]])


@app.route('/crash')
def crash():
    id = request.args.get('id')
    cs = get_db().cursor()
    if id is None:
        crash_list = []
        cs.execute("SELECT * FROM crash;")
        all_rows = cs.fetchall()
        for i in all_rows:
            id = i[0]
            pkg_name = i[1]
            tomb_txt = i[2]
            func_name = i[3] 
            args = i[4]
            exploitable = i[5]
            time = i[6]
            
            date_time = datetime.datetime.fromtimestamp(int(time.split('.')[0])).strftime('%Y.%m.%d %H:%M:%S')
            crash_list.append([pkg_name, func_name, exploitable, date_time, id])

        return render_template('crash.html', crash_list=crash_list)
    else:
        cs.execute("SELECT * FROM crash WHERE id=?;", (id,))
        all_rows = cs.fetchall()
        # print(all_rows[0][2])
        return (all_rows[0][2].replace('\n', '<br>'))


@app.route('/fuzzer')
def fuzzer():
    state = request.args.get('s')
    if state == "start":
        print_state = "Fuzzer1 Runing..."
    else:
        print_state = "No Running Fuzzer"
    return render_template('fuzzer.html', state=print_state)


@app.route('/api/getCrash')
def _getcrash():
    return json.dumps(getCrash())
    

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=8000)
