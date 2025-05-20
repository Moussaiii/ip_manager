from flask import Flask, render_template, request, redirect, session, url_for
from flask_mysqldb import MySQL
from scapy.all import ARP, Ether, srp
import socket

app = Flask(__name__)
app.secret_key = 'super_secret_key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'ipmanager'

mysql = MySQL(app)


@app.route('/')
def accueil():
    return render_template('accueil.html')


@app.route('/login/admin')
def login_admin():
    session['role'] = 'admin'
    return redirect(url_for('dashboard'))

@app.route('/login/user')
def login_user():
    session['role'] = 'user'
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if session.get('role') in ['admin', 'user']:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM addresse")
        data = cur.fetchall()
        cur.close()
        return render_template('index.html', ips=data)
    return redirect(url_for('accueil'))

@app.route('/add', methods=['POST'])
def add():
    if request.method == 'POST':
        cidr = request.form['cidr']
        try:
            scanned_ips = scan_network(cidr)
            cur = mysql.connection.cursor()
            for ip, etat, mac, hostname in scanned_ips:
                cur.execute("INSERT INTO addresse (ip, etat, mac, hostname) VALUES (%s, %s, %s, %s)", (ip, etat, mac, hostname))
            mysql.connection.commit()
            cur.close()
        except ValueError:
            return "CIDR invalide"
    return redirect('/dashboard')

@app.route('/update/<int:id>', methods=['POST'])
def update(id):
    if session.get('role') != 'admin':
        return redirect('/dashboard')

    cur = mysql.connection.cursor()
    cur.execute("SELECT etat FROM addresse WHERE id = %s", (id,))
    current_status = cur.fetchone()[0]
    new_status = 'Occupé' if current_status == 'Libre' else 'Libre'
    cur.execute("UPDATE addresse SET etat = %s WHERE id = %s", (new_status, id))
    mysql.connection.commit()
    cur.close()
    return redirect('/dashboard')

@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    if session.get('role') != 'admin':
        return redirect('/dashboard')

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM addresse WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    return redirect('/dashboard')

@app.route('/deleteAll', methods=['POST'])
def deleteAll():
    if session.get('role') != 'admin':
        return redirect('/dashboard')

    try:
        cur = mysql.connection.cursor()
        cur.execute("TRUNCATE TABLE addresse")
        mysql.connection.commit()
        cur.close()
    except:
        return "Erreur"
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('accueil'))

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def scan_network(cidr):
    arp_request = ARP(pdst=cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    responses = srp(packet, timeout=3, verbose=0)[0]

    scanned_ips = []
    for sent, received in responses:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip)
        etat = 'Occupée'
        scanned_ips.append((ip, etat, mac, hostname))

    return scanned_ips

@app.route('/login', methods=['GET', 'POST'])
def login():
    erreur = None
    if request.method == 'POST':
        email = request.form['email']
        mot_de_passe = request.form['mot_de_passe']

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, nom, mot_de_passe, role FROM utilisateur WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and user[2] == mot_de_passe:
            session['user_id'] = user[0]
            session['nom'] = user[1]
            session['role'] = user[3]
            return redirect(url_for('dashboard'))
        else:
            erreur = "Identifiants invalides"
    
    return render_template('login.html', erreur=erreur)

if __name__ == '__main__':
    app.run(debug=True)
