# my-cheatbook
this is book for my own tips

# laravel

## Routing
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

/*Remember
Any HTML forms pointing to POST, PUT, PATCH or DELETE routes that are defined in the web routes file should include a CSRF token field. Otherwise, the reqeust will be rejected.*/

<form method="POST" action="/profile">
	@csrf
	<!-- Equivalent to... -->
	<input type="hidden" name="_token" value="{{ csrf_token() }}" />
</form>

###CSRF

/*cross-site request forgery*/

//////////////

use Illuminate\Http\Request

Route::get('/token', function(Request $req) {
	$token = $req->session()->token();

	$toekn = csrf_token();
}))


####exclude csrf protection

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

####X-CSRF-TOKEN
<meta name="csrf-token" content="{{ csrf_token() }}">

........

$.ajaxSetup({
	headers: {
		'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
	}
});
####X-XSRF-TOKEN/


###Redirect Routes

//By default, it returns 302 status code.
Route::redirect('/here', '/there');

//customize status code using the optional third parameter
Route::redirect('/here', '/there', 301);

//redirect with 301 status code
Route::permanentRedirect('/here', '/there');

/////////////////////////////////

####View Routes

Route::view('/welcome', 'welcome');

Route::view('/welcome', 'welcome', ['name' => 'Taylor']);

###Route Parameters

####Requried parameters

//to capture a user's id from url
Route::get('/users/{id}', function($id) {
	return 'User'.$id;
});

//define different parameters
Route::get('/posts/{post}/comment/{comment}', fucntion($postID, $commentID) {
	return $postID.' '.$commentID;
});

####Parameters & Dependency Injection

//parameters have to locate after dependency
use Illuminate\Http\Reqeust;

Route:get('/user/{id}', function(Request $request, $id) {
	return 'User'.$id;
});

####Optional Parameters
Route::get('/user/{id?}', function($id=null) {
	return $id; //return null
})

Route::get('/user/{name?}', function($name='John') {
	return $name; //return 'John'
});

####Regular Expression Constraints
//to constrain the format of your route parameters
Route::get('/user/{name}', function($name) {
	return 'User'.$name;
})->where('name', '[A-Za-z]+');

Route:get('/user/{id}/{name}', function($id, $name) {
	return 'User'.$id.$name;
})->where(['id' => '[0-9]+', 'name' => '[A-Za-z]+']);

//for convenience, helper methods for commonly used regular expression patterns

Route::get('/user/{id}/{name}', function($id, $name) {
	return 'User'.$id.$name;
})->whereNumber('id')->whereAlpha('name');

Route::get('/user/{id}', function($id) {
	return 'User'.$id;
})->whereUuid('id');

Route::get('/user/{name}', function($name) {
	return 'User'.$name;
})->whereAlphaNumeric('name');

*if the incoming request doesn't match the route pattern constraints, a 404 response will be returned.*

####Global Constraints

//App\Providers\RouteServiceProvider class

public function boot() {
	Route::pattern('id', '[0-9]+');
}

####Encoded forward slashes
Route::get('/search/{search}', function($search) {
	return $search;
})-where('search', '.*');

//Encoded forward slashes are only supported within the last route segment.

###Named Routes

//to specify a name for a route
Route::get('/user/profile', function() {
	return 'Profile';
})->name('profile');
//to specify route names for controller actions
Route::get('/user/profile', [UserProfileController::class, 'show'])->name('profile');

*Route names should always be unique*

####Generating URLs To Named Routes
$url = route('profile');
return redirect()->route('profile');

Route::get('/user/{id}/profile', function($id) {
	
})->name('profile');

$url = route('profile', ['id' => 1]);

$url = route('profile', ['id' => 1, photo => 'yes']); //return /user/1/profile?photo=yes

####Inspecting The Current Route

 /*Handle an incoming request*/
 /*@param \Illuminate\Http\Request $reqeust*/
 /*@param \Closure $next*/
 /*@return mixed*/

public function handle($request, Closure $next)
{
	if ($request->route()->named('profile')) {
		// ...
	}
	return $next($request);
}

###Route Groups

####Middleware
Route::middleware(['first', 'second'])->group(function() {
	Route::get('/', function() {
		//Uses first & second middleware...
	});

	Route::get('/users/profile', function() {
		//Uses first & second middleware...
	});
});

####Subdomain Routing
Route::domain('{account}.example.com')->group(function() {
	Route::get('user/{id}', function($account, $id) {
		//
	});
});

####Route Prefixes
Route::prefix('admin')->group(function() {
	Route::get('/users', function() {
		//Matches The "/admin/users" URL
	});
});

####Route Name Prefixes
Route::name('admin.')->group(function() {
	Route::get('/users', function() {
		//Route assigned name "admin.users"
	})->name('users');
});

###Route Model Binding

####Implicit Binding

*for route*
use App\Model\User;

Route::get('/users/{user}', function(User $user) {
	return $user->email;
});

*for controller actions*

use App\Http\Controllers\UserController;
use App\Models\User;

//Route definition...
Route::get('/users/{user}', [UserController::class, 'show']);

//Controller method definition...
public function show(User $user)
{
	return view('user.profile', ['user' => $user]);
}

####Customizing The Key
//example
use App\Models\Post;

Route::get('/posts/{post:slug}', function(Post $post) {
	return $post;
});

//to customize the key

/*Get the route key for the model. @return string*/
public function getRouteKeyName() {
	return 'slug';
}

####Custom Keys & Scoping
use App\Models\User;
use App\Models\Post;

Route::get('/users/{user}/posts/{post:slug}', function(User $user, Post $post) {
	return $user.$post;
})

####Customizing Missing Model Behavior
use App\Http\Controllers\LocationController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

Route::get('/locations/{location:slug}', [LocationController::class, 'show'])->name('location.view')->missing(function(Reqeust $request) {
	return Redirect::route('location.index');
});

####Explicit Binding
*in boot method of your RouteServiceProvider*
use App\Models\User;
use Illuminate\Support\Facades\Route;

*Define your route model bindings, pattern filters, etc. @return void*
public function boot()
{
	Route::model('user', User::class);
}


####Customizing The Resolution Logic
*in boot method of your RouteServiceProvider*
use App\Models\User;
use Illuminate\Support\Facades\Route;

*Define your route model bindings, pattern filters, etc. @return void*
public function boot()
{
	Route::bind('user', function($value) {
		return User::where('name', $value)->fisrtOrFail();
	});
}

###Fallback Routes
//for unhandled reqeust

Route::fallback(function() {
	
});

###Rate Limiting

####Defining Rate Limiters
//configureRateLimiting method of App\Providers\RouteServiceProvider class

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;

protected function configureRteLimiting()
{
	RateLimiter::for('global', function(Reqeust $request) {
		return Limit::perMinute(1000); //return 429 HTTP status code.
	});
}

//to customize response

RateLimiter::for('global', function(Request $request) {
	return Limit::perMinute(1000)->response(function() {
		return response('Custom response...', 429);
	});
});

####Segmenting Rate Limits
RateLimiter::for('uploads', function(Request $request) {
	return $request->user()->vipCustomer()?Limit::none():Limit::perMinute(100)->by(reqeust->ip());
});

####Multiple Rate Limits
RateLimiter::for('login', function(Request $request) {
	return [
		Limit::perMinute(500),
		Limit::perMinute(3)->by($request->input('email')),
	];
});

####Attaching Rate Limiters To Routes
Route::middleware(['throttle:uploads'])->group(function() {
	Route::post('/audio', function() {
		//
	});

	Route::post('/video', function() {
		//
	});
});

###Form Method Spoofing
<form action="/example" method="POST">
	<input type="hidden" name="_method" value="PUT">
	<input type="hidden" name="_token" value="{{ csrf_token() }}">
</form>

//using @method Blade directive

<form action="/example" method="POST">
	@method('PUT')
	@csrf
</form>

###Accessing The Current Route

use Illuminate\Support\Facades\Route;

$route = Route::current();
$name = Route::currentRouteName();
$action = ROute::currentRouteAction();

###Crosss-Origin Resoure Sharing(CORS)

*in config/cors.php*
*The Options requests are handled by the HandleCors middleware*

###Route Caching
php artisan route:cache

//clear cache
php artisan route:clear