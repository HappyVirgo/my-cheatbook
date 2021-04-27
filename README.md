# my-cheatbook
this is book for my own tips

# laravel

1. Routing
use Illuminate/Support/Facades/Route;

Route::get("/greeting", function() {
	return "Hello world";
});

Route::get("user", [UserController::class, "index"]);

Route::match(['get', 'post'], '/', function() {
	return "Hello world";
}));

Route::any('/', function() {
	return "all";
});

Route::get('/', function() {
	return 'get';
});

Route::post('/', fucntion() {
	return 'post';
});

Route::put('/', function() {
	return "put";
});

Route::patch('/', function() {
	return "patch";
});

Route::delete('/', function() {
	return "delete";
});

Route::options('/', function() {
	return "options";
});

///////////////

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/users', functions(Request $req) {
	return req;
})

//////////////

//////Remember//////

Any HTML forms pointing to POST, PUT, PATCH or DELETE routes that are defined in the web routes file should include a CSRF token field. Otherwise, the reqeust will be rejected.

<form method="POST" action="/profile">
	@csrf
	<!-- Equivalent to... -->
	<input type="hidden" name="_token" value="{{ csrf_token() }}" />
</form>

/////CSRF/////

cross-site request forgery

//////////////

use Illuminate\Http\Request

Route::get('/token', function(Request $req) {
	$token = $req->session()->token();

	$toekn = csrf_token();
}))


////exclude csrf protection////

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
	protected $except = [
		'stripe/*',
		'http://example.com/foo/bar',
		'http://example.com/foo/*'
	];
}

///////X-CSRF-TOKEN///////
<meta name="csrf-token" content="{{ csrf_token() }}">

........

$.ajaxSetup({
	headers: {
		'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
	}
});
///////X-XSRF-TOKEN/////////


