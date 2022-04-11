import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request

#extras para auth google cache
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask("mynameapp")
app.secret_key = "mysecretkeyforflaskapp"

#myconfig
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

#google-config mis datos de google - cloudconsele debes crear un proyecto en google console APICREDENCIALES
GOOGLE_CLIENT_ID = "358612075404-v5km2rmat54ud6ojvpcv1gdj0s1mnh0m.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


#FUNCION MANUAL PARA SEGURIDAD - PROTECCION DE URLS
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()
    return wrapper


#PAGE GOOGLE DATOS LOGIN
@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    print('Token,Este es el de inicio: '+session["state"])
    return redirect(authorization_url)


#SOLICITUD DE DATOS - ASYNC CUIDADO CON EL RETORNO POR SI DA FALLOS
@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    #VALIDO TOKEN EN CONSOLA
    print('Token,Este es el de respuesta   '+request.args["state"])
    #credenciales para ingresar a paginas bloqueadas
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    
    #guardo en session de flask datos de sesion
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")

#elimino datos de sesion, recuerda que se guardan datos en cache para no estar iniciado sesion
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

#
@app.route("/")
def index():
    return """Hola, proyecto para iniciar sesion 
    con google en nuestra web, flask: -> 
        <a href='/login'>
            <button>Iniciar sesion con google</button>
        </a>
    
    """
@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"""
        <h1>Hola, iniciaste sesion con exito: </h1>
        {session['name']}! 

        <br/> 
        <a href='/logout'>
            <button>Cerrar sesion</button>
        </a>


        <br/> 
        <h1>Recuerda que se guarda datos en cache para no estar iniciado sesion,has test en modo incognito</h1>"""

if __name__ == "__main__":
    app.run(debug=True)
