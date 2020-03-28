package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/armon/go-metrics"
	"github.com/astaxie/beego/session"
	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/cache"
	"github.com/hashicorp/consul/agent/consul"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/lib"
	"github.com/hashicorp/consul/logging"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

var (
	html = `<html>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>
</title>
<body>
<div class="form-wrapper animated bounceInDown">
    <div class="form-header fc">
        <h1 class="fl">SIGN IN</h1>

    </div>
    <div class="form-container">
        <form>
            <div class="field fc">
                <span class="user-icon-user  fl"></span>
                <input class="fl" id="name" name="fname" type="text" placeholder="User Name" />
            </div>
            <div class="field field-password fc">
                <span class="user-icon-pword fl"></span>
                <input class="fl" id="password" name="lname" type="password" placeholder="User Password" />
            </div>

        </form>
    </div>
    <div class="form-footer fc">
        <div class="fl">
        </div>
        <a class="fr btn-primary " onclick="login()">SEND</a>
    </div>
</div>
<!--<table align="center">
    <tr>
        <td>
            用户名：
        </td>
        <td>
            <input id="name" />
        </td>
    </tr>
    <tr>
        <td>
            密码：
        </td>
        <td>
            <input id="password" type="password" />
        </td>
    </tr>
    <tr>
        <td>
            <input type="button" value="登录" onclick="login()" />
        </td>
    </tr>
</table> -->
</body>
<script type="application/javascript">
    Date.prototype.Format = function(fmt) {
        var o = {
            "M+": this.getMonth() + 1,
            "d+": this.getDate(),
            "h+": this.getHours(),
            "m+": this.getMinutes(),
            "s+": this.getSeconds(),
            "q+": Math.floor((this.getMonth() + 3) / 3),
            "S": this.getMilliseconds()
        };
        if (/(y+)/.test(fmt)) fmt = fmt.replace(RegExp.$1, (this.getFullYear() + "").substr(4 - RegExp.$1.length));
        for (var k in o)
            if (new RegExp("(" + k + ")").test(fmt)) fmt = fmt.replace(RegExp.$1, (RegExp.$1.length == 1) ? (o[k]) : (("00" + o[k]).substr(("" + o[k]).length)));
        return fmt
    };
    var time1 = new Date().Format("yyyyMMddhhmm");
    console.log(time1);

    function login() {
        var name = document.getElementById("name").value;
        var password = document.getElementById("password").value;
        createxmlHttp(name, password);
        //alert("ok")
    }

    function createxmlHttp(name, password) {
        var xmlhttp;
        if (window.XMLHttpRequest) {
            xmlhttp = new XMLHttpRequest()
        } else {
            xmlhttp = new ActiveXObject("Microsoft.XMLHTTP")
        }
        console.log(document.cookie);
        xmlhttp.onreadystatechange = function() {
            if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
                if (xmlhttp.responseText == "success") {
                    window.location.reload()
                } else {
                    alert("用户名或密码有误")
                }
            }
        };
        xmlhttp.open('post', '/ui/login', true);
        xmlhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xmlhttp.send(b64EncodeUnicode('{"username":"' + name + '","password":"' + password + '"}'))
    }

    function b64EncodeUnicode(str) {
        return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
            return String.fromCharCode('0x' + p1)
        }))
    }
</script>
<style>
    .fl{float:left;}
    .fr{float:right;}
    .clr{clear:both;height:0;width:0;min-height:0;visibility:hidden;overflow:hidden;display:block;}
    .fc:after{content:".";display:block;height:0;font-size:0;clear:both;visibility:hidden;}
    body {background:#ebeae2; font-family:Arial, Helvetica, sans-serif ;}
    .form-wrapper { width:300px; margin:20px auto; }
    .form-wrapper .form-header {  background:#333345;border-radius: 5px 5px 0px 0px;box-sizing:border-box; -moz-box-sizing:border-box; padding:10px 17px;}
    .form-wrapper .form-header h1 { font-size:17px; color:#fff; display:inline; font-weight:100; margin-top:5px;}
    .form-wrapper .form-header span {font-size: 18px;display: inline-block;padding: 3px 10px 4px 10px;background:#252536; border-radius: 4px; color:#fff; cursor:pointer;}
    .form-wrapper .form-container{ background:#fefefe; padding:25px 30px 12px 30px;box-sizing:border-box; -moz-box-sizing:border-box; }
    .field .user-icon-user { display:inline-block; width:50px; height:45px;border-radius: 5px 0px 0px 5px; transition:ease-in-out 0.3s; -webkit-transition:ease-in-out 0.3s;-moz-transition::ease-in-out 0.3s; -ms-transition:ease-in-out 0.3s;-o-transition:ease-in-out 0.3s; background:#dedede ; background-repeat:no-repeat;background-position: -51px 11px;}
    .field .user-icon-pword { display:inline-block; width:50px; height:45px;border-radius: 5px 0px 0px 5px; transition:ease-in-out 0.3s; -webkit-transition:ease-in-out 0.3s;-moz-transition::ease-in-out 0.3s; -ms-transition:ease-in-out 0.3s;-o-transition:ease-in-out 0.3s; background:#dedede ; background-repeat:no-repeat;background-position: -51px -42px;}
    .field{ margin-bottom:20px;}
    .field input {width: 190px;height: 45px;box-sizing:border-box; -moz-box-sizing:border-box; font-size:16px; padding:10px; border-radius: 0px 5px 5px 0px;border: 1px solid #ccc; border-left:none; color:#a09f9f;}
    .form-footer { background:#f4f4f4; border-radius: 0px 0px 5px 5px; border-top:1px dotted #e2e0de;box-sizing:border-box; -moz-box-sizing:border-box;  padding:15px 20px;}
    .form-footer a { display: block;background:#677ec9;border-radius: 3px;padding: 10px 20px;color: #fff;font-size: 16px; cursor:pointer;}
    .field .error {  background-color:#ea463c !important;box-sizing:border-box; -moz-box-sizing:border-box;background-position:-98px 11px;}
    .field .accept {  background-color:#0C6 !important;box-sizing:border-box; -moz-box-sizing:border-box; background-position:0px 11px;}
    .field.field-password { background-position:-51px 11px}
    .field.field-password .accept {background-position: 0 -42px;}
    .field.field-password .error {background-position: -98px -42px;}
    .animated{-webkit-animation-fill-mode:both;-moz-animation-fill-mode:both;-ms-animation-fill-mode:both;-o-animation-fill-mode:both;animation-fill-mode:both;-webkit-animation-duration:1s;-moz-animation-duration:1s;-ms-animation-duration:1s;-o-animation-duration:1s;animation-duration:1s;}.animated.hinge{-webkit-animation-duration:2s;-moz-animation-duration:2s;-ms-animation-duration:2s;-o-animation-duration:2s;animation-duration:2s;}
    @-webkit-keyframes bounceInDown {
        0% {
            opacity: 0;
            -webkit-transform: translateY(-2000px);
        }
        60% {
            opacity: 1;
            -webkit-transform: translateY(30px);
        }
        80% {
            -webkit-transform: translateY(-10px);
        }
        100% {
            -webkit-transform: translateY(0);
        }
    }
    @-moz-keyframes bounceInDown {
        0% {
            opacity: 0;
            -moz-transform: translateY(-2000px);
        }
        60% {
            opacity: 1;
            -moz-transform: translateY(30px);
        }
        80% {
            -moz-transform: translateY(-10px);
        }

        100% {
            -moz-transform: translateY(0);
        }
    }
    @-o-keyframes bounceInDown {
        0% {
            opacity: 0;
            -o-transform: translateY(-2000px);
        }
        60% {
            opacity: 1;
            -o-transform: translateY(30px);
        }
        80% {
            -o-transform: translateY(-10px);
        }
        100% {
            -o-transform: translateY(0);
        }
    }
    @keyframes bounceInDown {
        0% {
            opacity: 0;
            transform: translateY(-2000px);
        }
        60% {
            opacity: 1;
            transform: translateY(30px);
        }
        80% {
            transform: translateY(-10px);
        }
        100% {
            transform: translateY(0);
        }
    }
    .bounceInDown {
        -webkit-animation-name: bounceInDown;
        -moz-animation-name: bounceInDown;
        -o-animation-name: bounceInDown;
        animation-name: bounceInDown;
        list-style:none
    }
</style>
</html>`
	globalSessions *session.Manager
)

func init() {
	config := session.ManagerConfig{
		CookieName:      "gosessionid",
		Gclifetime:      3600,
		EnableSetCookie: false,
		Secure:          false,
		CookieLifeTime:  3600,
		ProviderConfig:  `{"cookieName":"gosessionid","securityKey":"beegocookiehashkey"}`,
	}
	var err error
	globalSessions, err = session.NewManager("cookie", &config)
	if err != nil {
		fmt.Println(err)
	}
	go globalSessions.GC()
}

// MethodNotAllowedError should be returned by a handler when the HTTP method is not allowed.
type MethodNotAllowedError struct {
	Method string
	Allow  []string
}

func (e MethodNotAllowedError) Error() string {
	return fmt.Sprintf("method %s not allowed", e.Method)
}

// BadRequestError should be returned by a handler when parameters or the payload are not valid
type BadRequestError struct {
	Reason string
}

func (e BadRequestError) Error() string {
	return fmt.Sprintf("Bad request: %s", e.Reason)
}

// NotFoundError should be returned by a handler when a resource specified does not exist
type NotFoundError struct {
	Reason string
}

func (e NotFoundError) Error() string {
	return e.Reason
}

// CodeWithPayloadError allow returning non HTTP 200
// Error codes while not returning PlainText payload
type CodeWithPayloadError struct {
	Reason      string
	StatusCode  int
	ContentType string
}

func (e CodeWithPayloadError) Error() string {
	return e.Reason
}

type ForbiddenError struct {
}

func (e ForbiddenError) Error() string {
	return "Access is restricted"
}

// HTTPServer provides an HTTP api for an agent.
type HTTPServer struct {
	*http.Server
	ln        net.Listener
	agent     *Agent
	blacklist *Blacklist

	// proto is filled by the agent to "http" or "https".
	proto string
}
type templatedFile struct {
	templated *bytes.Reader
	name      string
	mode      os.FileMode
	modTime   time.Time
}

func newTemplatedFile(buf *bytes.Buffer, raw http.File) *templatedFile {
	info, _ := raw.Stat()
	return &templatedFile{
		templated: bytes.NewReader(buf.Bytes()),
		name:      info.Name(),
		mode:      info.Mode(),
		modTime:   info.ModTime(),
	}
}

func (t *templatedFile) Read(p []byte) (n int, err error) {
	return t.templated.Read(p)
}

func (t *templatedFile) Seek(offset int64, whence int) (int64, error) {
	return t.templated.Seek(offset, whence)
}

func (t *templatedFile) Close() error {
	return nil
}

func (t *templatedFile) Readdir(count int) ([]os.FileInfo, error) {
	return nil, errors.New("not a directory")
}

func (t *templatedFile) Stat() (os.FileInfo, error) {
	return t, nil
}

func (t *templatedFile) Name() string {
	return t.name
}

func (t *templatedFile) Size() int64 {
	return int64(t.templated.Len())
}

func (t *templatedFile) Mode() os.FileMode {
	return t.mode
}

func (t *templatedFile) ModTime() time.Time {
	return t.modTime
}

func (t *templatedFile) IsDir() bool {
	return false
}

func (t *templatedFile) Sys() interface{} {
	return nil
}

type redirectFS struct {
	fs http.FileSystem
}

func (fs *redirectFS) Open(name string) (http.File, error) {
	file, err := fs.fs.Open(name)
	if err != nil {
		file, err = fs.fs.Open("/index.html")
	}
	return file, err
}

type templatedIndexFS struct {
	fs           http.FileSystem
	templateVars func() map[string]interface{}
}

func (fs *templatedIndexFS) Open(name string) (http.File, error) {
	file, err := fs.fs.Open(name)
	if err == nil && name == "/index.html" {
		content, _ := ioutil.ReadAll(file)
		file.Seek(0, 0)
		t, err := template.New("fmtedindex").Parse(string(content))
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		err = t.Execute(&out, fs.templateVars())

		file = newTemplatedFile(&out, file)
	}

	return file, err
}

// endpoint is a Consul-specific HTTP handler that takes the usual arguments in
// but returns a response object and error, both of which are handled in a
// common manner by Consul's HTTP server.
type endpoint func(resp http.ResponseWriter, req *http.Request) (interface{}, error)

// unboundEndpoint is an endpoint method on a server.
type unboundEndpoint func(s *HTTPServer, resp http.ResponseWriter, req *http.Request) (interface{}, error)

// endpoints is a map from URL pattern to unbound endpoint.
var endpoints map[string]unboundEndpoint

// allowedMethods is a map from endpoint prefix to supported HTTP methods.
// An empty slice means an endpoint handles OPTIONS requests and MethodNotFound errors itself.
var allowedMethods map[string][]string = make(map[string][]string)

// registerEndpoint registers a new endpoint, which should be done at package
// init() time.
func registerEndpoint(pattern string, methods []string, fn unboundEndpoint) {
	if endpoints == nil {
		endpoints = make(map[string]unboundEndpoint)
	}
	if endpoints[pattern] != nil || allowedMethods[pattern] != nil {
		panic(fmt.Errorf("Pattern %q is already registered", pattern))
	}

	endpoints[pattern] = fn
	allowedMethods[pattern] = methods
}

// wrappedMux hangs on to the underlying mux for unit tests.
type wrappedMux struct {
	mux     *http.ServeMux
	handler http.Handler
}

// ServeHTTP implements the http.Handler interface.
func (w *wrappedMux) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Add("Access-Control-Allow-Origin", "*")
	resp.Header().Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	w.handler.ServeHTTP(resp, req)
}

// handler is used to attach our handlers to the mux
func (s *HTTPServer) handler(enableDebug bool) http.Handler {
	mux := http.NewServeMux()

	// handleFuncMetrics takes the given pattern and handler and wraps to produce
	// metrics based on the pattern and request.
	handleFuncMetrics := func(pattern string, handler http.HandlerFunc) {
		// Get the parts of the pattern. We omit any initial empty for the
		// leading slash, and put an underscore as a "thing" placeholder if we
		// see a trailing slash, which means the part after is parsed. This lets
		// us distinguish from things like /v1/query and /v1/query/<query id>.
		var parts []string
		for i, part := range strings.Split(pattern, "/") {
			if part == "" {
				if i == 0 {
					continue
				}
				part = "_"
			}
			parts = append(parts, part)
		}

		// Register the wrapper, which will close over the expensive-to-compute
		// parts from above.
		// TODO (kyhavlov): Convert this to utilize metric labels in a major release
		wrapper := func(resp http.ResponseWriter, req *http.Request) {
			start := time.Now()
			handler(resp, req)
			key := append([]string{"http", req.Method}, parts...)
			metrics.MeasureSince(key, start)
		}

		gzipWrapper, _ := gziphandler.GzipHandlerWithOpts(gziphandler.MinSize(0))
		gzipHandler := gzipWrapper(http.HandlerFunc(wrapper))
		mux.Handle(pattern, gzipHandler)
	}

	// handlePProf takes the given pattern and pprof handler
	// and wraps it to add authorization and metrics
	handlePProf := func(pattern string, handler http.HandlerFunc) {
		wrapper := func(resp http.ResponseWriter, req *http.Request) {
			var token string
			s.parseToken(req, &token)

			rule, err := s.agent.resolveToken(token)
			if err != nil {
				resp.WriteHeader(http.StatusForbidden)
				return
			}

			// If enableDebug is not set, and ACLs are disabled, write
			// an unauthorized response
			if !enableDebug {
				if s.checkACLDisabled(resp, req) {
					return
				}
			}

			// If the token provided does not have the necessary permissions,
			// write a forbidden response
			if rule != nil && rule.OperatorRead(nil) != acl.Allow {
				resp.WriteHeader(http.StatusForbidden)
				return
			}

			// Call the pprof handler
			handler(resp, req)
		}

		handleFuncMetrics(pattern, http.HandlerFunc(wrapper))
	}
	mux.HandleFunc("/", s.Index)
	for pattern, fn := range endpoints {
		thisFn := fn
		methods := allowedMethods[pattern]
		bound := func(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
			return thisFn(s, resp, req)
		}
		handleFuncMetrics(pattern, s.wrap(bound, methods))
	}

	// Register wrapped pprof handlers
	handlePProf("/debug/pprof/", pprof.Index)
	handlePProf("/debug/pprof/cmdline", pprof.Cmdline)
	handlePProf("/debug/pprof/profile", pprof.Profile)
	handlePProf("/debug/pprof/symbol", pprof.Symbol)
	handlePProf("/debug/pprof/trace", pprof.Trace)

	if s.IsUIEnabled() {
		var uifs http.FileSystem
		// Use the custom UI dir if provided.
		if s.agent.config.UIDir != "" {
			uifs = http.Dir(s.agent.config.UIDir)
		} else {
			fs := assetFS()
			uifs = fs
		}

		uifs = &redirectFS{fs: &templatedIndexFS{fs: uifs, templateVars: s.GenerateHTMLTemplateVars}}
		// create a http handler using the ui file system
		// and the headers specified by the http_config.response_headers user config
		uifsWithHeaders := serveHandlerWithHeaders(
			http.FileServer(uifs),
			s.agent.config.HTTPResponseHeaders,
		)
		mux.Handle(
			"/robots.txt",
			uifsWithHeaders,
		)

		mux.Handle(
			s.agent.config.UIContentPath,
			StripPrefix( //http.StripPrefix
				s.agent.config.UIContentPath,
				uifsWithHeaders,
			),
		)
	}

	// Wrap the whole mux with a handler that bans URLs with non-printable
	// characters, unless disabled explicitly to deal with old keys that fail this
	// check.
	h := cleanhttp.PrintablePathCheckHandler(mux, nil)
	if s.agent.config.DisableHTTPUnprintableCharFilter {
		h = mux
	}
	return &wrappedMux{
		mux:     mux,
		handler: h,
	}
}

//rewrite from http package
// StripPrefix returns a handler that serves HTTP requests
// by removing the given prefix from the request URL's Path
// and invoking the handler h. StripPrefix handles a
// request for a path that doesn't begin with prefix by
// replying with an HTTP 404 not found error.
func StripPrefix(prefix string, h http.Handler) http.Handler {
	if prefix == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := strings.TrimPrefix(r.URL.Path, prefix); len(p) < len(r.URL.Path) {
			if !login(w, r, p) {
				return
			}
			r2 := new(http.Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.Path = p
			h.ServeHTTP(w, r2)
		} else {
			http.NotFound(w, r)
		}
	})
}

func login(w http.ResponseWriter, r *http.Request, p string) bool {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("err：", err)
		}
	}()
	sess, err := globalSessions.SessionStart(w, r)
	fmt.Println(sess.SessionID())
	if err != nil {
		fmt.Println("SessionStart err:", err)
	}
	cookie := http.Cookie{
		Name:     "gosessionid",
		Value:    sess.SessionID(),
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(3600),
		//Domain:"http://localhost:63343",
	}
	http.SetCookie(w, &cookie)
	user := sess.Get("user")
	if user == nil || user.(string) == "" {
		if strings.Contains(p, "login") { //登录逻辑
			bs, err := ioutil.ReadAll(r.Body)
			fmt.Println(string(bs), err)
			decodeBytes, err := base64.StdEncoding.DecodeString(string(bs))
			fmt.Println("no get user", string(decodeBytes), err)
			var user User
			err = json.Unmarshal(decodeBytes, &user)
			fmt.Println(user, err)
			if user.Name == "admin" && user.Pwd == "Aa123456"+time.Now().Format("200601021504") {
				//sess.Values["user"] = string(bs)
				sess.Set("user", string(bs))
				sess.SessionRelease(w)
				//sess.Save(r,w)

				io.WriteString(w, "success")

			} else {
				io.WriteString(w, "fail")
			}
			return false
		}
		io.WriteString(w, html)
		return false
	} else {
		decodeBytes, err := base64.StdEncoding.DecodeString(user.(string))
		fmt.Println("get user", string(decodeBytes), err)
		var user User
		err = json.Unmarshal(decodeBytes, &user)
		//fmt.Println(user,err)
		return true
	}
}

type User struct {
	Name string `json:"username"`
	Pwd  string `json:"password"`
}

func (s *HTTPServer) GenerateHTMLTemplateVars() map[string]interface{} {
	vars := map[string]interface{}{
		"ContentPath": s.agent.config.UIContentPath,
		"ACLsEnabled": s.agent.delegate.ACLsEnabled(),
	}

	s.addEnterpriseHTMLTemplateVars(vars)

	return vars
}

// nodeName returns the node name of the agent
func (s *HTTPServer) nodeName() string {
	return s.agent.config.NodeName
}

// aclEndpointRE is used to find old ACL endpoints that take tokens in the URL
// so that we can redact them. The ACL endpoints that take the token in the URL
// are all of the form /v1/acl/<verb>/<token>, and can optionally include query
// parameters which are indicated by a question mark. We capture the part before
// the token, the token, and any query parameters after, and then reassemble as
// $1<hidden>$3 (the token in $2 isn't used), which will give:
//
// /v1/acl/clone/foo           -> /v1/acl/clone/<hidden>
// /v1/acl/clone/foo?token=bar -> /v1/acl/clone/<hidden>?token=<hidden>
//
// The query parameter in the example above is obfuscated like any other, after
// this regular expression is applied, so the regular expression substitution
// results in:
//
// /v1/acl/clone/foo?token=bar -> /v1/acl/clone/<hidden>?token=bar
//                                ^---- $1 ----^^- $2 -^^-- $3 --^
//
// And then the loop that looks for parameters called "token" does the last
// step to get to the final redacted form.
var (
	aclEndpointRE = regexp.MustCompile("^(/v1/acl/(create|update|destroy|info|clone|list)/)([^?]+)([?]?.*)$")
)

// wrap is used to wrap functions to make them more convenient
func (s *HTTPServer) wrap(handler endpoint, methods []string) http.HandlerFunc {
	httpLogger := s.agent.logger.Named(logging.HTTP)
	return func(resp http.ResponseWriter, req *http.Request) {
		setHeaders(resp, s.agent.config.HTTPResponseHeaders)
		setTranslateAddr(resp, s.agent.config.TranslateWANAddrs)

		// Obfuscate any tokens from appearing in the logs
		formVals, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			httpLogger.Error("Failed to decode query",
				"from", req.RemoteAddr,
				"error", err,
			)
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}
		logURL := req.URL.String()
		if tokens, ok := formVals["token"]; ok {
			for _, token := range tokens {
				if token == "" {
					logURL += "<hidden>"
					continue
				}
				logURL = strings.Replace(logURL, token, "<hidden>", -1)
			}
		}
		logURL = aclEndpointRE.ReplaceAllString(logURL, "$1<hidden>$4")

		if s.blacklist.Block(req.URL.Path) {
			errMsg := "Endpoint is blocked by agent configuration"
			httpLogger.Error("Request error",
				"method", req.Method,
				"url", logURL,
				"from", req.RemoteAddr,
				"error", errMsg,
			)
			resp.WriteHeader(http.StatusForbidden)
			fmt.Fprint(resp, errMsg)
			return
		}

		isForbidden := func(err error) bool {
			if acl.IsErrPermissionDenied(err) || acl.IsErrNotFound(err) {
				return true
			}
			_, ok := err.(ForbiddenError)
			return ok
		}

		isMethodNotAllowed := func(err error) bool {
			_, ok := err.(MethodNotAllowedError)
			return ok
		}

		isBadRequest := func(err error) bool {
			_, ok := err.(BadRequestError)
			return ok
		}

		isNotFound := func(err error) bool {
			_, ok := err.(NotFoundError)
			return ok
		}

		isTooManyRequests := func(err error) bool {
			// Sadness net/rpc can't do nice typed errors so this is all we got
			return err.Error() == consul.ErrRateLimited.Error()
		}

		addAllowHeader := func(methods []string) {
			resp.Header().Add("Allow", strings.Join(methods, ","))
		}

		handleErr := func(err error) {
			httpLogger.Error("Request error",
				"method", req.Method,
				"url", logURL,
				"from", req.RemoteAddr,
				"error", err,
			)
			switch {
			case isForbidden(err):
				resp.WriteHeader(http.StatusForbidden)
				fmt.Fprint(resp, err.Error())
			case structs.IsErrRPCRateExceeded(err):
				resp.WriteHeader(http.StatusTooManyRequests)
			case isMethodNotAllowed(err):
				// RFC2616 states that for 405 Method Not Allowed the response
				// MUST include an Allow header containing the list of valid
				// methods for the requested resource.
				// https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
				addAllowHeader(err.(MethodNotAllowedError).Allow)
				resp.WriteHeader(http.StatusMethodNotAllowed) // 405
				fmt.Fprint(resp, err.Error())
			case isBadRequest(err):
				resp.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(resp, err.Error())
			case isNotFound(err):
				resp.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(resp, err.Error())
			case isTooManyRequests(err):
				resp.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(resp, err.Error())
			default:
				resp.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(resp, err.Error())
			}
		}

		start := time.Now()
		defer func() {
			httpLogger.Debug("Request finished",
				"method", req.Method,
				"url", logURL,
				"from", req.RemoteAddr,
				"latency", time.Since(start).String(),
			)
		}()

		var obj interface{}

		// if this endpoint has declared methods, respond appropriately to OPTIONS requests. Otherwise let the endpoint handle that.
		if req.Method == "OPTIONS" && len(methods) > 0 {
			addAllowHeader(append([]string{"OPTIONS"}, methods...))
			return
		}

		// if this endpoint has declared methods, check the request method. Otherwise let the endpoint handle that.
		methodFound := len(methods) == 0
		for _, method := range methods {
			if method == req.Method {
				methodFound = true
				break
			}
		}

		if !methodFound {
			err = MethodNotAllowedError{req.Method, append([]string{"OPTIONS"}, methods...)}
		} else {
			err = s.checkWriteAccess(req)

			if err == nil {
				// Invoke the handler
				obj, err = handler(resp, req)
			}
		}
		contentType := "application/json"
		httpCode := http.StatusOK
		if err != nil {
			if errPayload, ok := err.(CodeWithPayloadError); ok {
				httpCode = errPayload.StatusCode
				if errPayload.ContentType != "" {
					contentType = errPayload.ContentType
				}
				if errPayload.Reason != "" {
					resp.Header().Add("X-Consul-Reason", errPayload.Reason)
				}
			} else {
				handleErr(err)
				return
			}
		}
		if obj == nil {
			return
		}
		var buf []byte
		if contentType == "application/json" {
			buf, err = s.marshalJSON(req, obj)
			if err != nil {
				handleErr(err)
				return
			}
		} else {
			if strings.HasPrefix(contentType, "text/") {
				if val, ok := obj.(string); ok {
					buf = []byte(val)
				}
			}
		}
		resp.Header().Set("Content-Type", contentType)
		resp.WriteHeader(httpCode)
		resp.Write(buf)
	}
}

// marshalJSON marshals the object into JSON, respecting the user's pretty-ness
// configuration.
func (s *HTTPServer) marshalJSON(req *http.Request, obj interface{}) ([]byte, error) {
	if _, ok := req.URL.Query()["pretty"]; ok || s.agent.config.DevMode {
		buf, err := json.MarshalIndent(obj, "", "    ")
		if err != nil {
			return nil, err
		}
		buf = append(buf, "\n"...)
		return buf, nil
	}

	buf, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return buf, err
}

// Returns true if the UI is enabled.
func (s *HTTPServer) IsUIEnabled() bool {
	return s.agent.config.UIDir != "" || s.agent.config.EnableUI
}

// Renders a simple index page
func (s *HTTPServer) Index(resp http.ResponseWriter, req *http.Request) {
	// Check if this is a non-index path
	if req.URL.Path != "/" {
		resp.WriteHeader(http.StatusNotFound)
		return
	}

	// Give them something helpful if there's no UI so they at least know
	// what this server is.
	if !s.IsUIEnabled() {
		fmt.Fprint(resp, "Consul Agent")
		return
	}

	// Redirect to the UI endpoint
	http.Redirect(resp, req, s.agent.config.UIContentPath, http.StatusMovedPermanently) // 301
}

func decodeBody(body io.Reader, out interface{}) error {
	return lib.DecodeJSON(body, out)
}

// decodeBodyDeprecated is deprecated, please ues decodeBody above.
// decodeBodyDeprecated is used to decode a JSON request body
func decodeBodyDeprecated(req *http.Request, out interface{}, cb func(interface{}) error) error {
	// This generally only happens in tests since real HTTP requests set
	// a non-nil body with no content. We guard against it anyways to prevent
	// a panic. The EOF response is the same behavior as an empty reader.
	if req.Body == nil {
		return io.EOF
	}

	var raw interface{}
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&raw); err != nil {
		return err
	}

	// Invoke the callback prior to decode
	if cb != nil {
		if err := cb(raw); err != nil {
			return err
		}
	}

	decodeConf := &mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			stringToReadableDurationFunc(),
		),
		Result: &out,
	}

	decoder, err := mapstructure.NewDecoder(decodeConf)
	if err != nil {
		return err
	}

	return decoder.Decode(raw)
}

// stringToReadableDurationFunc is a mapstructure hook for decoding a string
// into an api.ReadableDuration for backwards compatibility.
func stringToReadableDurationFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		var v api.ReadableDuration
		if t != reflect.TypeOf(v) {
			return data, nil
		}

		switch {
		case f.Kind() == reflect.String:
			if dur, err := time.ParseDuration(data.(string)); err != nil {
				return nil, err
			} else {
				v = api.ReadableDuration(dur)
			}
			return v, nil
		default:
			return data, nil
		}
	}
}

// setTranslateAddr is used to set the address translation header. This is only
// present if the feature is active.
func setTranslateAddr(resp http.ResponseWriter, active bool) {
	if active {
		resp.Header().Set("X-Consul-Translate-Addresses", "true")
	}
}

// setIndex is used to set the index response header
func setIndex(resp http.ResponseWriter, index uint64) {
	// If we ever return X-Consul-Index of 0 blocking clients will go into a busy
	// loop and hammer us since ?index=0 will never block. It's always safe to
	// return index=1 since the very first Raft write is always an internal one
	// writing the raft config for the cluster so no user-facing blocking query
	// will ever legitimately have an X-Consul-Index of 1.
	if index == 0 {
		index = 1
	}
	resp.Header().Set("X-Consul-Index", strconv.FormatUint(index, 10))
}

// setKnownLeader is used to set the known leader header
func setKnownLeader(resp http.ResponseWriter, known bool) {
	s := "true"
	if !known {
		s = "false"
	}
	resp.Header().Set("X-Consul-KnownLeader", s)
}

func setConsistency(resp http.ResponseWriter, consistency string) {
	if consistency != "" {
		resp.Header().Set("X-Consul-Effective-Consistency", consistency)
	}
}

// setLastContact is used to set the last contact header
func setLastContact(resp http.ResponseWriter, last time.Duration) {
	if last < 0 {
		last = 0
	}
	lastMsec := uint64(last / time.Millisecond)
	resp.Header().Set("X-Consul-LastContact", strconv.FormatUint(lastMsec, 10))
}

// setMeta is used to set the query response meta data
func setMeta(resp http.ResponseWriter, m structs.QueryMetaCompat) {
	setIndex(resp, m.GetIndex())
	setLastContact(resp, m.GetLastContact())
	setKnownLeader(resp, m.GetKnownLeader())
	setConsistency(resp, m.GetConsistencyLevel())
}

// setCacheMeta sets http response headers to indicate cache status.
func setCacheMeta(resp http.ResponseWriter, m *cache.ResultMeta) {
	if m == nil {
		return
	}
	str := "MISS"
	if m.Hit {
		str = "HIT"
	}
	resp.Header().Set("X-Cache", str)
	if m.Hit {
		resp.Header().Set("Age", fmt.Sprintf("%.0f", m.Age.Seconds()))
	}
}

// setHeaders is used to set canonical response header fields
func setHeaders(resp http.ResponseWriter, headers map[string]string) {
	for field, value := range headers {
		resp.Header().Set(http.CanonicalHeaderKey(field), value)
	}
}

// serveHandlerWithHeaders is used to serve a http.Handler with the specified headers
func serveHandlerWithHeaders(h http.Handler, headers map[string]string) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		setHeaders(resp, headers)
		h.ServeHTTP(resp, req)
	}
}

// parseWait is used to parse the ?wait and ?index query params
// Returns true on error
func parseWait(resp http.ResponseWriter, req *http.Request, b structs.QueryOptionsCompat) bool {
	query := req.URL.Query()
	if wait := query.Get("wait"); wait != "" {
		dur, err := time.ParseDuration(wait)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(resp, "Invalid wait time")
			return true
		}
		b.SetMaxQueryTime(dur)
	}
	if idx := query.Get("index"); idx != "" {
		index, err := strconv.ParseUint(idx, 10, 64)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(resp, "Invalid index")
			return true
		}
		b.SetMinQueryIndex(index)
	}
	return false
}

// parseCacheControl parses the CacheControl HTTP header value. So far we only
// support maxage directive.
func parseCacheControl(resp http.ResponseWriter, req *http.Request, b structs.QueryOptionsCompat) bool {
	raw := strings.ToLower(req.Header.Get("Cache-Control"))

	if raw == "" {
		return false
	}

	// Didn't want to import a full parser for this. While quoted strings are
	// allowed in some directives, max-age does not allow them per
	// https://tools.ietf.org/html/rfc7234#section-5.2.2.8 so we assume all
	// well-behaved clients use the exact token form of max-age=<delta-seconds>
	// where delta-seconds is a non-negative decimal integer.
	directives := strings.Split(raw, ",")

	parseDurationOrFail := func(raw string) (time.Duration, bool) {
		i, err := strconv.Atoi(raw)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(resp, "Invalid Cache-Control header.")
			return 0, true
		}
		return time.Duration(i) * time.Second, false
	}

	for _, d := range directives {
		d = strings.ToLower(strings.TrimSpace(d))

		if d == "must-revalidate" {
			b.SetMustRevalidate(true)
		}

		if strings.HasPrefix(d, "max-age=") {
			d, failed := parseDurationOrFail(d[8:])
			if failed {
				return true
			}
			b.SetMaxAge(d)
			if d == 0 {
				// max-age=0 specifically means that we need to consider the cache stale
				// immediately however MaxAge = 0 is indistinguishable from the default
				// where MaxAge is unset.
				b.SetMustRevalidate(true)
			}
		}
		if strings.HasPrefix(d, "stale-if-error=") {
			d, failed := parseDurationOrFail(d[15:])
			if failed {
				return true
			}
			b.SetStaleIfError(d)
		}
	}

	return false
}

// parseConsistency is used to parse the ?stale and ?consistent query params.
// Returns true on error
func (s *HTTPServer) parseConsistency(resp http.ResponseWriter, req *http.Request, b structs.QueryOptionsCompat) bool {
	query := req.URL.Query()
	defaults := true
	if _, ok := query["stale"]; ok {
		b.SetAllowStale(true)
		defaults = false
	}
	if _, ok := query["consistent"]; ok {
		b.SetRequireConsistent(true)
		defaults = false
	}
	if _, ok := query["leader"]; ok {
		defaults = false
	}
	if _, ok := query["cached"]; ok {
		b.SetUseCache(true)
		defaults = false
	}
	if maxStale := query.Get("max_stale"); maxStale != "" {
		dur, err := time.ParseDuration(maxStale)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(resp, "Invalid max_stale value %q", maxStale)
			return true
		}
		b.SetMaxStaleDuration(dur)
		if dur.Nanoseconds() > 0 {
			b.SetAllowStale(true)
			defaults = false
		}
	}
	// No specific Consistency has been specified by caller
	if defaults {
		path := req.URL.Path
		if strings.HasPrefix(path, "/v1/catalog") || strings.HasPrefix(path, "/v1/health") {
			if s.agent.config.DiscoveryMaxStale.Nanoseconds() > 0 {
				b.SetMaxStaleDuration(s.agent.config.DiscoveryMaxStale)
				b.SetAllowStale(true)
			}
		}
	}
	if b.GetAllowStale() && b.GetRequireConsistent() {
		resp.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(resp, "Cannot specify ?stale with ?consistent, conflicting semantics.")
		return true
	}
	if b.GetUseCache() && b.GetRequireConsistent() {
		resp.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(resp, "Cannot specify ?cached with ?consistent, conflicting semantics.")
		return true
	}
	return false
}

// parseDC is used to parse the ?dc query param
func (s *HTTPServer) parseDC(req *http.Request, dc *string) {
	if other := req.URL.Query().Get("dc"); other != "" {
		*dc = other
	} else if *dc == "" {
		*dc = s.agent.config.Datacenter
	}
}

// parseTokenInternal is used to parse the ?token query param or the X-Consul-Token header or
// Authorization Bearer token (RFC6750) and
// optionally resolve proxy tokens to real ACL tokens. If the token is invalid or not specified it will populate
// the token with the agents UserToken (acl_token in the consul configuration)
// Parsing has the following priority: ?token, X-Consul-Token and last "Authorization: Bearer "
func (s *HTTPServer) parseTokenInternal(req *http.Request, token *string) {
	tok := ""
	if other := req.URL.Query().Get("token"); other != "" {
		tok = other
	} else if other := req.Header.Get("X-Consul-Token"); other != "" {
		tok = other
	} else if other := req.Header.Get("Authorization"); other != "" {
		// HTTP Authorization headers are in the format: <Scheme>[SPACE]<Value>
		// Ref. https://tools.ietf.org/html/rfc7236#section-3
		parts := strings.Split(other, " ")

		// Authorization Header is invalid if containing 1 or 0 parts, e.g.:
		// "" || "<Scheme><Value>" || "<Scheme>" || "<Value>"
		if len(parts) > 1 {
			scheme := parts[0]
			// Everything after "<Scheme>" is "<Value>", trimmed
			value := strings.TrimSpace(strings.Join(parts[1:], " "))

			// <Scheme> must be "Bearer"
			if strings.ToLower(scheme) == "bearer" {
				// Since Bearer tokens shouldnt contain spaces (rfc6750#section-2.1)
				// "value" is tokenized, only the first item is used
				tok = strings.TrimSpace(strings.Split(value, " ")[0])
			}
		}
	}

	if tok != "" {
		*token = tok
		return
	}

	*token = s.agent.tokens.UserToken()
}

// parseToken is used to parse the ?token query param or the X-Consul-Token header or
// Authorization Bearer token header (RFC6750)
func (s *HTTPServer) parseToken(req *http.Request, token *string) {
	s.parseTokenInternal(req, token)
}

func sourceAddrFromRequest(req *http.Request) string {
	xff := req.Header.Get("X-Forwarded-For")
	forwardHosts := strings.Split(xff, ",")
	if len(forwardHosts) > 0 {
		forwardIp := net.ParseIP(strings.TrimSpace(forwardHosts[0]))
		if forwardIp != nil {
			return forwardIp.String()
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return ""
	}

	ip := net.ParseIP(host)
	if ip != nil {
		return ip.String()
	} else {
		return ""
	}
}

// parseSource is used to parse the ?near=<node> query parameter, used for
// sorting by RTT based on a source node. We set the source's DC to the target
// DC in the request, if given, or else the agent's DC.
func (s *HTTPServer) parseSource(req *http.Request, source *structs.QuerySource) {
	s.parseDC(req, &source.Datacenter)
	source.Ip = sourceAddrFromRequest(req)
	if node := req.URL.Query().Get("near"); node != "" {
		if node == "_agent" {
			source.Node = s.agent.config.NodeName
		} else {
			source.Node = node
		}
	}
}

// parseMetaFilter is used to parse the ?node-meta=key:value query parameter, used for
// filtering results to nodes with the given metadata key/value
func (s *HTTPServer) parseMetaFilter(req *http.Request) map[string]string {
	if filterList, ok := req.URL.Query()["node-meta"]; ok {
		filters := make(map[string]string)
		for _, filter := range filterList {
			key, value := ParseMetaPair(filter)
			filters[key] = value
		}
		return filters
	}
	return nil
}

// parseInternal is a convenience method for endpoints that need
// to use both parseWait and parseDC.
func (s *HTTPServer) parseInternal(resp http.ResponseWriter, req *http.Request, dc *string, b structs.QueryOptionsCompat) bool {
	s.parseDC(req, dc)
	var token string
	s.parseTokenInternal(req, &token)
	b.SetToken(token)
	var filter string
	s.parseFilter(req, &filter)
	b.SetFilter(filter)
	if s.parseConsistency(resp, req, b) {
		return true
	}
	if parseCacheControl(resp, req, b) {
		return true
	}
	return parseWait(resp, req, b)
}

// parse is a convenience method for endpoints that need
// to use both parseWait and parseDC.
func (s *HTTPServer) parse(resp http.ResponseWriter, req *http.Request, dc *string, b structs.QueryOptionsCompat) bool {
	return s.parseInternal(resp, req, dc, b)
}

func (s *HTTPServer) checkWriteAccess(req *http.Request) error {
	if req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == http.MethodOptions {
		return nil
	}

	allowed := s.agent.config.AllowWriteHTTPFrom
	if len(allowed) == 0 {
		return nil
	}

	ipStr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return errors.Wrap(err, "unable to parse remote addr")
	}

	ip := net.ParseIP(ipStr)

	for _, n := range allowed {
		if n.Contains(ip) {
			return nil
		}
	}

	return ForbiddenError{}
}

func (s *HTTPServer) parseFilter(req *http.Request, filter *string) {
	if other := req.URL.Query().Get("filter"); other != "" {
		*filter = other
	}
}
