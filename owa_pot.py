import os
import json
import logging
from functools import wraps
from flask import Flask, redirect, render_template, request, send_from_directory, Response, make_response

log_file = 'dumpass.log'
logger = logging.getLogger('honeypot')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(log_file)
fh.setLevel(logging.DEBUG)

# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)


def create_app(test_config=None):

    app = Flask(__name__, instance_relative_config=True)

    @app.errorhandler(404)
    def page_not_found(e):
        # note that we set the 404 status explicitly
        return render_template('404.html'), 404


    @app.errorhandler(403)
    def page_no_access(e):
        # note that we set the 404 status explicitly
        return render_template('403.html'), 403


    @app.errorhandler(401)
    def page_auth_required(e):
        # note that we set the 404 status explicitly
        return render_template('401.html'), 401
    

    app.register_error_handler(404, page_not_found)
    app.register_error_handler(403, page_no_access)
    app.register_error_handler(401, page_auth_required)
    app.config.from_mapping(
        SECRET_KEY='dev',
    )
    print(app.static_folder)
    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass


    def check_auth(username, password):
        logger.info(f"{request.base_url}|{username}:{password}")
        return False

    def authenticate():
        """Sends a 401 response that enables basic auth"""
        return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

    def requires_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not auth or not check_auth(auth.username, auth.password):
                return authenticate()
            return f(*args, **kwargs)
        return decorated
	

    def add_response_headers(headers={}):
        """This decorator adds the headers passed in to the response"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                resp = make_response(f(*args, **kwargs))
                h = resp.headers
                for header, value in headers.items():
                    h[header] = value
                return resp
            return decorated_function
        return decorator


    def changeheader(f):
        return add_response_headers({"Server": "Microsoft-IIS/7.5", 
            "X-Powered-By": "ASP.NET"})(f)


    @app.route('/Abs/')
    @app.route('/aspnet_client/')
    @app.route('/Autodiscover/')
    @app.route('/AutoUpdate/')
    @app.route('/CertEnroll/')
    @app.route('/CertSrv/')
    @app.route('/Conf/')
    @app.route('/DeviceUpdateFiles_Ext/')
    @app.route('/DeviceUpdateFiles_Int/')
    @app.route('/ecp/')
    @app.route('/Etc/')
    @app.route('/EWS/')
    @app.route('/Exchweb/')
    @app.route('/GroupExpansion/')
    @app.route('/Microsoft-Server-ActiveSync/')
    @app.route('/OAB/')
    @app.route('/ocsp/')
    @app.route('/PhoneConferencing/')
    @app.route('/PowerShell/')
    @app.route('/Public/')
    @app.route('/RequestHandler/')
    @app.route('/RequestHandlerExt/')
    @app.route('/Rgs/')
    @app.route('/Rpc/')
    @app.route('/RpcWithCert/')
    @app.route('/UnifiedMessaging/')
    @changeheader
    @requires_auth
    def stub_redirect():
        return redirect('/')


    @app.route('/owa/auth/15.1.1466/themes/resources/segoeui-regular.ttf', methods=['GET'])
    @changeheader
    def font_segoeui_regular_ttf():
        return send_from_directory(app.static_folder, filename='segoeui-regular.ttf', conditional=True)
        
    @app.route('/owa/auth/15.1.1466/themes/resources/segoeui-semilight.ttf', methods=['GET'])
    @changeheader
    def font_segoeui_semilight_ttf():
        return send_from_directory(app.static_folder, filename='segoeui-semilight.ttf', conditional=True)

    @app.route('/owa/auth/15.1.1466/themes/resources/favicon.ico', methods=['GET'])
    @changeheader
    def favicon_ico():
        return send_from_directory(app.static_folder, filename='favicon.ico', conditional=True)

    @app.route('/owa/auth.owa', methods=['GET', 'POST'])
    @changeheader
    def auth():
        ua = request.headers.get('User-Agent')
        ip = request.remote_addr
        if request.method == 'GET':
            return redirect('/owa/auth/logon.aspx?replaceCurrent=1&reason=3&url=', 302)
        else:
            passwordText = ""
            password = ""
            username = ""
            if "username" in request.form:
                username = request.form["username"]
            if "password" in request.form:
                password = request.form["password"]
            if "passwordText" in request.form:
                passwordText = request.form["passwordText"]
            logger.info(f"{request.base_url}|{username}:{password}|{ip}|{ua}")
            return redirect('/owa/auth/logon.aspx?replaceCurrent=1&reason=2&url=', 302)

    @app.route('/owa/auth/logon.aspx', methods=['GET'])
    @changeheader
    def owa():
        return render_template("outlook_web.html")  

    @app.route('/')
    @app.route('/exchange/')
    @app.route('/webmail/')
    @app.route('/exchange')
    @app.route('/webmail')
    @changeheader
    def index():
        return redirect('/owa/auth/logon.aspx?replaceCurrent=1&url=', 302)          

    return app

if __name__ == "__main__":
    if __name__ == '__main__':
        create_app().run(debug=False,port=80, host="0.0.0.0")