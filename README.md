# my-cheatbook
this is book for my own tips

# laravel

## Routing
```php
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
```
///////////////

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/users', functions(Request $req) {
	return req;
})
```
//////////////

/*Remember
Any HTML forms pointing to POST, PUT, PATCH or DELETE routes that are defined in the web routes file should include a CSRF token field. Otherwise, the reqeust will be rejected.*/
```html
<form method="POST" action="/profile">
	@csrf
	<!-- Equivalent to... -->
	<input type="hidden" name="_token" value="{{ csrf_token() }}" />
</form>
```
###CSRF

/*cross-site request forgery*/

//////////////
```php
use Illuminate\Http\Request

Route::get('/token', function(Request $req) {
	$token = $req->session()->token();

	$toekn = csrf_token();
}))
```

####exclude csrf protection

```php
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
```

####X-CSRF-TOKEN
```html
<meta name="csrf-token" content="{{ csrf_token() }}">

........
```
```javascript
$.ajaxSetup({
	headers: {
		'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
	}
});
````
####X-XSRF-TOKEN/


###Redirect Routes
```php
//By default, it returns 302 status code.
Route::redirect('/here', '/there');

//customize status code using the optional third parameter
Route::redirect('/here', '/there', 301);

//redirect with 301 status code
Route::permanentRedirect('/here', '/there');
```

####View Routes

```php
Route::view('/welcome', 'welcome');

Route::view('/welcome', 'welcome', ['name' => 'Taylor']);
```
###Route Parameters

####Requried parameters

```php
//to capture a user's id from url
Route::get('/users/{id}', function($id) {
	return 'User'.$id;
});

//define different parameters
Route::get('/posts/{post}/comment/{comment}', fucntion($postID, $commentID) {
	return $postID.' '.$commentID;
});
```
####Parameters & Dependency Injection

```php
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
```
####Regular Expression Constraints
```php
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
```
*if the incoming request doesn't match the route pattern constraints, a 404 response will be returned.*

####Global Constraints
```php
//App\Providers\RouteServiceProvider class

public function boot() {
	Route::pattern('id', '[0-9]+');
}
```
####Encoded forward slashes
```php
Route::get('/search/{search}', function($search) {
	return $search;
})-where('search', '.*');

//Encoded forward slashes are only supported within the last route segment.
```
###Named Routes
```php
//to specify a name for a route
Route::get('/user/profile', function() {
	return 'Profile';
})->name('profile');
//to specify route names for controller actions
Route::get('/user/profile', [UserProfileController::class, 'show'])->name('profile');
```
*Route names should always be unique*

####Generating URLs To Named Routes

```php
$url = route('profile');
return redirect()->route('profile');

Route::get('/user/{id}/profile', function($id) {
	
})->name('profile');

$url = route('profile', ['id' => 1]);

$url = route('profile', ['id' => 1, photo => 'yes']); //return /user/1/profile?photo=yes
```
####Inspecting The Current Route
```php
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
```
###Route Groups

####Middleware
```php
Route::middleware(['first', 'second'])->group(function() {
	Route::get('/', function() {
		//Uses first & second middleware...
	});

	Route::get('/users/profile', function() {
		//Uses first & second middleware...
	});
});
```
####Subdomain Routing
```php
Route::domain('{account}.example.com')->group(function() {
	Route::get('user/{id}', function($account, $id) {
		//
	});
});
```
####Route Prefixes
```php
Route::prefix('admin')->group(function() {
	Route::get('/users', function() {
		//Matches The "/admin/users" URL
	});
});
```
####Route Name Prefixes
```php
Route::name('admin.')->group(function() {
	Route::get('/users', function() {
		//Route assigned name "admin.users"
	})->name('users');
});
```
###Route Model Binding

####Implicit Binding

*for route*
```php
use App\Model\User;

Route::get('/users/{user}', function(User $user) {
	return $user->email;
});
```
*for controller actions*
```php
use App\Http\Controllers\UserController;
use App\Models\User;

//Route definition...
Route::get('/users/{user}', [UserController::class, 'show']);

//Controller method definition...
public function show(User $user)
{
	return view('user.profile', ['user' => $user]);
}
```
####Customizing The Key
```php
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
```
####Custom Keys & Scoping
```php
use App\Models\User;
use App\Models\Post;

Route::get('/users/{user}/posts/{post:slug}', function(User $user, Post $post) {
	return $user.$post;
})
```
####Customizing Missing Model Behavior
```php
use App\Http\Controllers\LocationController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

Route::get('/locations/{location:slug}', [LocationController::class, 'show'])->name('location.view')->missing(function(Reqeust $request) {
	return Redirect::route('location.index');
});
```
####Explicit Binding
*in boot method of your RouteServiceProvider*
```php
use App\Models\User;
use Illuminate\Support\Facades\Route;

*Define your route model bindings, pattern filters, etc. @return void*
public function boot()
{
	Route::model('user', User::class);
}
```

####Customizing The Resolution Logic
*in boot method of your RouteServiceProvider*
```php
use App\Models\User;
use Illuminate\Support\Facades\Route;

*Define your route model bindings, pattern filters, etc. @return void*
public function boot()
{
	Route::bind('user', function($value) {
		return User::where('name', $value)->fisrtOrFail();
	});
}
```
###Fallback Routes
```php
//for unhandled reqeust

Route::fallback(function() {
	
});
```
###Rate Limiting

####Defining Rate Limiters
//configureRateLimiting method of App\Providers\RouteServiceProvider class
```php
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
```
####Segmenting Rate Limits
```php
RateLimiter::for('uploads', function(Request $request) {
	return $request->user()->vipCustomer()?Limit::none():Limit::perMinute(100)->by(reqeust->ip());
});
```
####Multiple Rate Limits
```php

RateLimiter::for('login', function(Request $request) {
	return [
		Limit::perMinute(500),
		Limit::perMinute(3)->by($request->input('email')),
	];
});
```
####Attaching Rate Limiters To Routes
```php
Route::middleware(['throttle:uploads'])->group(function() {
	Route::post('/audio', function() {
		//
	});

	Route::post('/video', function() {
		//
	});
});
```
###Form Method Spoofing
```html
<form action="/example" method="POST">
	<input type="hidden" name="_method" value="PUT">
	<input type="hidden" name="_token" value="{{ csrf_token() }}">
</form>
```
//using @method Blade directive
```html
<form action="/example" method="POST">
	@method('PUT')
	@csrf
</form>
```
###Accessing The Current Route
```php
use Illuminate\Support\Facades\Route;

$route = Route::current();
$name = Route::currentRouteName();
$action = ROute::currentRouteAction();
```
###Crosss-Origin Resoure Sharing(CORS)

*in config/cors.php*
*The Options requests are handled by the HandleCors middleware*

###Route Caching
```bash
php artisan route:cache
```
//clear cache
```bash
php artisan route:clear
```

##Eloquent
*to make enjoyable to interact with database*

###Generating Model Classes

```bash
php artisan make:model Flight
```
//to generate database migration
```bash
php artisan make:model Flight --migration
```
//to generate various other types of classes such as factories, seeders and controllers

```bash
php artisan make:model Flight -f
php artisan make:model Flight --factory

php artisan make:model Flight -s
php artisan make:model FLight --seeders

php artisan make:model Flight --controller
php artisan mkae:model Flight -c

php artisan make:model Flight -mfsc

php artisan make:model Member --pivot
```

###Eloquent Model Conventions

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Flight extends Model
{
	//
}
```

*"snake case": plural name of the class will be used as the table name*

```php
<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Flight extends Model
{
	protected $table = 'my_flights'; //to specify table name
	protected $primaryKey = 'flight_id'; //to specify primary key

	public $incrementing = false; //to use non-incrementing or non-numeric id
	protected $keyType = 'string'; //to set key type as string
}
```

###timestamps

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Flight extends Model
{
	public $timestamps = false; //not to use eloquent's timestamps function
	protected $dateFormat = 'U'; //set date format

	//to customize timestamps keys(created_at, updated_at) in database model
	const CREATED_AT = 'creation_date'; 
	const UPDATED_AT = 'updated_date'; 
}
```

###Database Connections

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Flight extends Model
{
	protected $connection = 'sqlite'; //to specify database type for this model
}
```

###Default Attribute Variables

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Models;

class Flight extends Models
{
	//to define default values for model's attribute
	protected $attributes = [
		'delayed' => false,
	];
}
```

###Retrieving Models

```php
<?php

use App\Models\Flight;

foreach(Flight:all() as $flight) {
	echo $flight->name;
}
```
####Building Queries

```php
$flights = Flight::where('active', 1)->orderBy('name')->take(10)->get();
```

####Refreshing Models

```php
$flight = Flight::where('number', 'FR 900')->first();

$freshFlight = $flight->fresh();
```

```php
$flight = Flight::where('number', 'FR 900')->first();
$flight->number = 'FR 456';
$flight->refresh();
$flight->number; //"FR 900"
```

###Collections

```php
$flights = Flight::where('destination', 'Paris')->get();

$flights = $flights->reject(fucntion($flight) {
	return $flight->cancelled;
})
```

###Chunking Results

```php
use App\Models\Flight;

Flight::chunk(200, function($flights) {
	foreach($flights as $flight) {

	}
});

Flight::where('departed', true)->chunkById(200, function($flights) {
	$flights->each->update(['departed' => false]);
}, $column = 'id');
```

###Streaming Results Lazily

```php

use App\Models\Flight;

foreach (Flight::lazy() as $flight) {

}

Flight::where('departed', true)->lazyById(200, $column = 'id')->each->update(['departed' => false]);
```

####Cursors

```php
use App\Models\Flight;
foreach(Flight::where('destination', 'Zurich')->cursor() as $flight) {

}
```

```php
use App\Models\User;

$users = User::cursor()->filter(function($user) {
	return $user->id > 500;
});

foreach($users as $user) {
	echo $user->id;
}
```

###Advanced Subqueries

####Subquery Selects

```php
use App\Models\Flight;
use App\Models\Destination;

return Destination::addSelect(['last_flight', Flight::select('name')->whereColumn('destination_id', 'destination_id')->orderByDesc('arrived_at')->limit(1)])->get();
```
####Subquery Ordering

```php
return Destination::orderByDes(Flight::select('arrived_at')->whereColumn('destination_id', 'destination_id')->orderByDesc('arrived_at')->limit(1))->get();
```

###Retrieving Single Models/Aggregates

```php
use App\Models\Flight;

$flight = Flight::find(1); //retrieve by primary key

$flight = Flight::where('active', 1)->first(); //retrieve the first model matching the query constraints

$flight = Flight::firstWhere('active', 1); //Alternative to retrieving the first model mathcing the query constraints
```

```php
$models = Flight::where('legs', '>', 3)->firstOr(function() {
	// ...
});
```

####Not Found Exceptions

```php
$flight = Flight::findOrFail(1);

$flight = Flight::where('legs', '<', 3)->firstOrFail();
```

####Retrieving Or Creating Models

```php
use App\Models\User;

//retrieve flight by name or create it if it doesn't exist...
$flight = Flight::firstOrCreate(['name' => 'London to Paris'], ['delayed' => 1, 'arrival_time' => '11.30']);

//retrieve flight by name or instantiate a new flight instance...
$flight = Flight::firstOrNew(['name' => 'Tokyo to Sydney'], ['delayed' => 1, 'arrival_time' => '11.30']);
```

####Retrieving Aggregates

```php
//return number of models matching the query constraints
$count = Flight::where('active', 1)->count();

//get a model which has max price among models matching the query constraints
$max = Flight:where('active', 1)->max('price')
```

###Inserting & Updating Models

####Inserts

```php
namespace App\Http\Controllers;

use App\Http\Controllers\Conroller;
use App\Models\Flight;
use Illuminate\Http\Request;

class FlightController extends Controller
{
	public function store(Request $request)
	{
		$flight = new Flight;
		$flight->name = $request->name;
		$flight->save();
	}
}
```

```php
use App\Models\Flight;

$flight = Flight::create(['name' => 'London to Paris']);
```

####Updates

```php
use App\Models\Flight;

$flight = Flight::find(1);
$flight = 'London to Paris';
$flight->save();
```
####Mass Updates

```php
Flight::where('active', 1)->where('destination', 'San Diego')->update(['delayed' => 1]);
```

####Examining Attribute Changes

```php
use App\Models\User;

$user = User::create(['firstName' => 'Kingsly', 'lastName' => 'Lee', 'title' => 'Developer', ]);
$user->title = 'designer';
$user->isDirty(); //true
$user->isDirty('title'); //true

$user->isClean(); //false
$user->isClean('firstName'); //true

$user->save();

$user->isDirty(); //false
$user->isClean(); //true
```

```php
$user = User::create(['name' => 'Kingsly Lee', 'title' => 'developer']);
$user->title = 'designer';

$user->save();

$user->wasChanged(); //true
```

```php
$user = User::find(1);
$user->name; //Kingsly Lee
$user->email; //happy0910virgo@outlook.com

$user->name = 'Jacky';

$user->getOriginal('name'); //Kingsly Lee
$user->getOriginal(); //Array of original attributes
```

###Mass Assignment

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class FlightModel extends Model
{
	protected $fillable = ['name'];
}



$flight->fill('name', 'Paris to London');
```

####Mass Assignment & JSON Columns

```php
protected $fillable = ['options->enabled'];
```

####Allowing Mass Assignment

```php
protected $guarded = [];
```

####Update and Insert(Upserts)

```php
$flight = Flight::updateOrCreate(['departure' => 'Oakland', 'destination' => 'San Diego'], ['price' => 99, 'active' => 1]);

Flight::upsert([['departure' => 'Oakland', 'destination' => 'San Diego', 'price' => 99], ['departure' => 'Chicago', 'destination' => 'New York', 'price' => 150]], ['departure', 'destination'], ['price']);
```

###Deleting Models

```php
use App\Models\User;

$user = User::find(1);
$user->delete();

//to delete all of the model's associated database records
User::truncate();
```

####Deleting An Existing Model By Its Primary Key

```php
Flight::Destroy(1);
Flight::Destroy(1,2,3);
Flight::Destroy([1,2,3]);
Flight::Destroy(collect([1,2,3]));
```

####Delecting Models Using Queries

```php
$deletedROws = Flight::where('active', 0)->delete();
```

####Soft Deleting
```php
<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Flight extends Model
{
	use SoftDeletes;
}

//to determine if a given model instance has been soft deleted
if ($flight->trashed()) {

}

//to restore a soft deleted model
$flight->restore();

//to restore multiple models
Flight::withTrashed()->where('airline_id', 1)->restore();

//build relationship queries
$flight->history()->restore();
```

####Permaneltyl Deleting Models

```php
//permanently delete a soft deleted model from the database table
$flight->forceDelete();
//build Eloquent relationship query
$flight->history()->forceDelete();
```

###Querying Soft Deleted Models

####Including Soft Deleted Models

```php
use App\Models\Flight;

$flight = FLight::withTrashed()->where('account_id', 1)->get();

//build Eloquent relationship queries
$flight->history()->withTrashed()->get();
```

####Retrieving only Soft Deleted Models

```php
$flight = Flight::onlyTrashed()->where('airline_id', 1)->get();
```

###Replacing Models

```php
use App\Models\Address;

$shipping = Address::create([
	'type': 'shipping',
	'line_1' => '123 Example Street',
	'city' => 'Victorville',
	'state' => 'CA',
	'postcode' => '90001'
]);

$billing = $shipping->replicate()->fill([
	'title' => 'billing'
]);

$billing->save();
```

###Query Scopes

####Global Scopes

#####Writing Global Scopes

```php
<?php

namespace App\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

class AncientScope implements Scope
{
	public function apply(Builder $builder, Model $modle)
	{
		$builder->where('created_at', '<', now()=>subYears(2000));
	}
}
```

#####Aplying Global Scopes

```php
<?php

namespace App\Models;

use App\Scopes\AncientScope;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{
	protected static function booted()
	{
		static::addGlobalScope(new AncientScope);
	}
}
```
```
User::all() = select * from `users` where `created_at`
 < 0021-02-18 00:00:00
 ```

#####Anonymous Global Scopes

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{
	protected static function booted()
	{
		static::addGlobalScope('ancient', function(Builder $builder) {
			$builder->where('created_at', '<', now()->subYears(2000));
		});
	}
}
```

#####Removing Global Scopes

```php
User::withoutGlobalScopes(AncientScope::class)->get();

User::withoutGlobalScopes('ancient')->get();

User::withoutGlobalScopes([
	FirstScope::class, SecondScope::class
])->get();
```

####Local Scopes

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{
	public function scopePopular($query)
	{
		return $query->where('votes', '>', 100);
	}

	public function scopeActive($query)
	{
		return $query->where('active', 1);
	}
}
```

####Utilizing A Local Scope

```php
use App\Models\User;

$users = User::popular()->active()->orderBy('craeted_at')->get();

$users = User::popular()->orWhere(function(Builder $query) {
	$query->active();
})->get();

$users = App\Models\User::popular()->orWhere->active()->get();
```

#####Dynamic Scopes

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
	public function scpeOfType($query, $type)
	{
		return $query->where('type', $type);
	}
}



$users = User::ofType('admin')->get();
```

###Comparing Models

```php
if ($post->is($anotherPost)) {
	//	
}

if ($post->isNot($anotherPost)) {
	//
}

if($post->author()->is($user)) {
	//
}
```

###Events

```php
namespace App\Models;

use App\Events\UserDeleted;
use App\Events\UserSaved;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
	use Notifiable;

	protected $dispatchesEvents = [
		'saved' => UserSaved::class,
		'deleted' => UserDeleted::class,
	];
}
```

###Using Closures

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
	protected static function booted()
	{
		static::created(function($user) {
			//
		})
	}
}


use function Illuminate\Events\queueable;

static::created(queueable(function ($user) {
	//
}));
```

###Observers

####Defining Observers

```bash
php artisan make:observer UserObserver --model=User
```

```php
namespace App\Observers;

use App\Models\User;

class UserObserver
{
	public function created(User $user)
	{
		//
	}

	public function deleted(User $user)
	{
		//
	}

	public function forceDeleted(User $user)
	{
		//
	}
}

//App\Providers\EventServiceProvider

use App\Models\User;
use App\Observers\UserObserver;

public function boot()
{
	User::observe(UserObserver::class);
}
```
####Observers &Database Transactions

```php
namespace App\Observers;

use App\Models\User;

class UserObserver
{
	public $afterCommit = true;

	public function created(User $user)
	{
		//
	}
}
```

####Muting Events

```php
use App\Models\User;

$user = User::withoutEvents(function() use() {
	User::findOrFail(1)->delete();

	return User::find(2);
})
```

####Saving A Single Model Without Events

```php
$user = User::findOrFail(1);

$user->name = 'Victoria Faith';

$user->saveQuielty();
```