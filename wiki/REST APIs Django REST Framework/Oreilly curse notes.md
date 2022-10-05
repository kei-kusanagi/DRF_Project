Ya tenia el proyecto creado pero la regué tratando de añadirle archivos estáticos y una pagina de login, entonces opte por crearlo nuevamente (sirve practico)

creamos nuestro proyecto de Django y de aquí es de donde saque la buena practica de ponerle ``_app`` para saber cuales son

hacemos nuestras migraciones

luego creamos un super usuario

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221003175917.png)


listo ya entramos al panel de administracion, ahora crearemos: 
- los modelos
- las vistas
- las urls


en models.py ponemos lo siguiente

```Python
from django.db import models

  

# Create your models here.

class Movie(models.Model):

    name = models.CharField(max_length=50)

    description = models.CharField(max_length=200)

    active= models.BooleanField(default=True)

  

    def __str__(self):

        return self.name
```

estos son los modelos de nuestro campo de películas que nos servirá para guardar en la base de datos, así que debemos hacer ``makemigrations`` si no marcara error

```
(env) PS C:\Users\admin\Desktop\Proyectos\Oreilly\DRF_Project> python manage.py makemigrations
Migrations for 'watchlist_app':
  watchlist_app\migrations\0001_initial.py
    - Create model Movie
```

esto nos regresara que a creado el ``MODELO`` movie (pareciera mentira pero hasta ahorita le voy entendiendo porque hizo esto... 😅)

luego hacemos un ``migrate``
```
(env) PS C:\Users\admin\Desktop\Proyectos\Oreilly\DRF_Project> python manage.py migrate       
Operations to perform:
  Apply all migrations: admin, auth, contenttypes, sessions, watchlist_app
Running migrations:
  Applying watchlist_app.0001_initial... OK
```

pa que aplique todas las migraciones y con esto tener completa nuestra estructura inicial de nuestra base de datos así que saltamos a nuestro archivo admin.py y registramos nuestro modelo allí _(esto es para que nos aparezca en el panel de administración)_

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221003183911.png)

vamos a llenar los campos para crear unas 3 películas solo para probar, ya que después lo haremos directamente con peticiones a la API

ahora si nos vamos a crear nuestras vistas, en views.py ponemos

```Python
from django.shortcuts import render

from watchlist_app.models import Movie

  

def movie_list(request):

    movies = Movie.objects.all()

    print(movies.values)
```

ojo el print es temporal ya que solo queremos ver que si me este regresando en forma Json las cosas, así que vamos a watchmate/urls.py para dar de alta ese path

```python
from django.contrib import admin

from django.urls import path, include

  

urlpatterns = [

    path('admin/', admin.site.urls),

    path('movie/', include('watchlist_app.urls')),

]
```

con esto estamos mandando a llamar la lista de paths de nuestra ``watchlist_app``, así que ahora vamos a su watchlist_app/urls.py

```Python
from django.urls import path, include

from watchlist_app.views import movie_list

  

urlpatterns = [

    path('list/', movie_list, name='movie-list'),

]
```


ya tenemos todo casi listo, ahora volvemos a views y lo modificamos para que la lista de películas se guarde en un Json, para esto importamos ``JsonResponse`` y ponemos lo siguiente

```Python
from django.shortcuts import render

from watchlist_app.models import Movie

from django.http import JsonResponse

  

def movie_list(request):

    movies = Movie.objects.all()

    data = {

        'movies': list(movies.values())

    }

  

    return JsonResponse(data)
```

en el navegador nos vamos a "http://127.0.0.1:8000/movie/list/" (path que declaramos en watchlist_app/urls.py) y veremos la respuesta del ``return JsonResponse(data)`` que en efecto es un Json, donde se ven las películas que metimos como prueba

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221003200113.png)
(como nota, en el Json los boléanos deberían aparecer como True no true pero luego arreglaremos eso)

ahora, esto nos da una lista de los objetos en la base de datos, pero que pasa si queremos solo el 1  el 2, pues tenemos que definir una nueva vista 

```Python
...
  

def movie_details(request, pk):

    movie = Movie.objects.get(pk=pk)

    print(movie)
```

Aquí le estamos diciendo que la pelicula que queremos es el numero que se pone en el pk (Primary Key) pero si tratamos de verlo con el path http://127.0.0.1:8000/movie/1/ nos regresara un error ya que no hemos declarado ese path

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221003201845.png)

Así que vamos a watchlist_app/urls.py (al otro ya no porque toma todos los pts de aquí y los pone en nuestro proyecto watchmate)

nos regresara un error en el navegador pero, le pusimos un print y en la terminal nos saldrá esto

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221003202401.png)

esto es porque solo le estamos regresando el nombre y no encuentra como representarlo como si no tuviera una forma, la ocasión pasada lo tuvimos que convertir en un Json para que pudiera interpretarlo así que hagámoslo creando otra ves un "data" que nos sirva de diccionario

```Python
...

def movie_details(request, pk):

    movie = Movie.objects.get(pk=pk)

    data = {

        'name': movie.name,

        'description': movie.description,

        'active': movie.active

    }

    
    return JsonResponse(data)
```

aquí asignamos a "movie" el objeto según el "pk" y este lo desglosamos en data y lo convertimos en un diccionario valido que se pueda mostrar como un JsonResponse, lo salvamos y ahora si ya tendrá forma de representarlo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221003203220.png)


todo esto lo estamos haciendo dato por dato y es algo engorroso con lo que según el video "Django REST Framework" nos podrá ayudar por medio de sus "serializares"  "funciones basadas en vistas" y mas funciones, así que en la próxima lección empezaremos con el proyecto de verdad jajaja (chale)

primero iniciamos instalándolo ``pip install djangorestframework`` y lo añadimos a las INSTALLED_APPS

Lo que estábamos haciendo actualmente era obtener datos complejos que son nuestro conjunto de consultas, estos los convertimos en un diccionario y lo mandamos como respuesta con un JSONResponse, esto lo hacemos dividiéndolo en 3 partes diferentes, cada que hacemos una entrada estamos creando nuevos objetos (actualmente solo son 3 name, description y active) entonces si quiero obtener algo, lo mandare a llama y me lo dará en forma de objeto de modelo actual y al convertirlo al diccionario de Python estamos haciendo una **serialización** y ya lo que queda es pasar (return) ese diccionario en forma de JSON, hasta ahorita hacemos todo esto manualmente, mapeando cada uno de los elementos individualmente, y ahorita solo son 3 pero pueden ser mas de 10 o 20 campos, por lo tanto si seguimos haciéndolo asi nos llevara mucho tiempo, aparte que ahorita solo estamos creando, nos falta poder consultar, actualizar y borrar **_(CRUD)_** todo esto lo podemos hacer mas fácil con la serialización y luego convertirlo en JSON (ta muy difícil de entender pero dice que se explicara cuando empecemos a trabajar en ello)

Ahora que es la **deserializacion** , si ahorita queremos entregar información a un usuario estamos serializando, pero si necesitamos _obtener_ información del usuario (GET) para almacenarla en la base de datos, para esto tenemos que deserializar los datos. Suponiendo que tenemos información en forma de JSON, luego necesitamos convertirla en un diccionario y luego desrealizarlo y almacenarlo en forma de objeto en nuestra DB eso seria la deserialización, comenta aquí que es donde todos cometemos errores pero que entre mas lo trabajemos mejor lo entenderemos

![[IMG/Pasted image 20221004101920.png]]


habla mucho sobre los tipos de serialización y que usaremos postman y que no nos preocupemos si ahorita no le entendemos, pero que casi todo mundo se pasa directo a serializar sin siquiera explicar que es, sin mencionar que no dicen que por ejemplo la "funciones basadas en vistas" es como "serializers.Serializer" y que las "clases basadas en vistas" es "serializers.ModelSerializer"

![[IMG/Pasted image 20221004152909.png]]

Entonces empecemos a codificar, vallamos a nuestra "watchlist_app" y creemos una nueva carpet llamada api, dentro de ella pongamos un archivo "urls.py" y otro llamado "views.py", en el "urls.py" utilizaremos casi lo mismo que teníamos en nuestro anterior archivo as que copy/paste
lo salvamos y vamos a nuestro "watchmate/urls.py" principal y ahora ponemos que use el que acabamos de crear

```Python
from django.contrib import admin

from django.urls import path, include

  

urlpatterns = [

    path('admin/', admin.site.urls),

    path('movie/', include('watchlist_app.api.urls')),

]
```

Y en nuestra nueva "urls.py" mandamos a llamar nuestro nuevo archivo de "views.py"

```Python
from django.urls import path, include

from watchlist_app.api.views import movie_list, movie_details

  

urlpatterns = [

    path('list/', movie_list, name='movie-list'),

    path('<int:pk>', movie_details, name='movie-detail'),

]
```

hecho esto podemos borrar nuestro anterior archivo de "urls.py" y comentar todo dentro del "views.py" anterior porque de ves en cuando regresaremos a verlo

ahora creamos un nuevo archivo dentro de la carpeta api llamado "serializers.py" este es importante porque hara el mapeo de todos los valores paso a paso (por eso comentamos lo de "views.py" porque ya no lo haremos allí si no aquí)

```Python
from rest_framework import serializers

  

class MovieSerializer(serializers.Serializer):

    id = serializers.IntegerField(read_only=True)

    name = serializers.CharField()

    description = serializers.CharField()

    active = serializers.BooleanField()
```

Creamos nuestros serializadores aquí, primero importamos ``serializers`` de ``rest_framework`` y declaramos nuestras formas por así decirlo, "id" como solo de lectura porque nos interesa nunca poderlo alterar y listo, ahora podremos hacer el mapeo aqui para poder hacer validaciones, crear borrar y actualizar.


Entonces vamos a nuestro archivo" api/views.py" y  creemos nuestro función que nos regresara el "movie_details" pero ahora usando nuestras serializaciones para que nos regrese un "JsonResponse"

```Python
from rest_framework.response import Response

from watchlist_app.models import Movie

from watchlist_app.api.serializers import MovieSerializer

  

def movie_list(request):

    movies = Movie.objects.all()

    serializer = MovieSerializer(movies)

    return Response(serializer.data)
```

Vamos a usar "movies" y le seleccionamos todo los "Movie.objecst.all()" (ojo, estamos usando el objeto "movie" creado precisamente en "watchlist_app/models.py" muchas veces me confundía de donde sacaba los objetos pero ahora lo entiendo, allí le estamos agregando todos los objetos que creamos allí como son "name", "description" y "active").

Lo siguiente es crear nuestro "serializer" entonces lo mandamos a llamar "serializer" jajaja, lo podemos llamar como queramos pero mejor llamarlo asi, ahora mandamos a llamar nuestro "movieSerializer()" que es precisamente nuestro serializador creado en "serializers.py" y le pasamos nuestro "complex data" que en este caso es movies (lo que creamos arriba 😉)

Ya esta todo preparado, ahora solo nos falta "retornar" este "Response", así que importamos eso del "rest_framework" y lo regresamos con el objeto "serializer.data" pa que nos mande los datos pues, para acceder a toda la información de ese objeto que estamos serializando (parece trabalenguas tanto serializador 😵)

nos falta agregar a ese response la función de "movie_details" porque si no, nos marcara error en "urls.py" así que lo creamos

```Python
def movie_details(request, pk):

    movie = Movie.objects.get(pk=pk)

    serializer = MovieSerializer(movie)

    return Response(serializer.data)
```

Desglosado esto, creamos nuestro objeto "movie" que sera igual a nuestro ya existente objeto "movies.objects" y le ponemos el ".get(pk=pk)" para que nos traiga SOLO el archivo cuyo "id"  #Duda sea igual al "pk" eso la neta no se como demonios lo hace si no le asigna en ningún momento el "pk" al "id" pero dice que luego lo veremos junto con los decoradores.

Ahora si corremos nuestro servidor y visitamos http://127.0.0.1:8000/movie/1
… 

😬 Que bonito error, ahora veremos como corregirlo
![[IMG/Pasted image 20221004163222.png]]

despues de un clavado que se avento en stack overflow y de revisar la documentacion, resulta que nos faltaba un decorador ``@api_view()``, estos nos permitirán decirle a Django REST framework si estamos haciendo Create, Read, Update o Delete  

```Python
from rest_framework.response import Response

from rest_framework.decorators import api_view

  

from watchlist_app.models import Movie

from watchlist_app.api.serializers import MovieSerializer

  

@api_view()

def movie_list(request):

    movies = Movie.objects.all()

    serializer = MovieSerializer(movies)

    return Response(serializer.data)

  

@api_view()

def movie_details(request, pk):

    movie = Movie.objects.get(pk=pk)

    serializer = MovieSerializer(movie)

    return Response(serializer.data)
```

y listo, con esto ya nos regresa el "Response" dependiendo de que "pk" le demos

![[IMG/Pasted image 20221004175951.png]]

pero si queremos entrar a http://127.0.0.1:8000/movie/list/ tenemos un error y de tarea tenemos que resolverlo  #Tarea

![[IMG/Pasted image 20221004184759.png]]


la solución es modificar "views.py" agregar ``many=True`` en el "serializer" ya que estamos mandando a llamar multiples instancias, en el de movie details no hay bronca porque solo estamos llamando una gracias al "pk" entonces con esto podemos visitar cada elemento de la lista y serializarlo tan sencillo como eso, con decirle que van a ser vario ``many=True``

```Python
serializer = MovieSerializer(movies, many=True)
```

![[IMG/Pasted image 20221004190517.png]]

y aquí aclara el porque aunque no le estamos poniendo ninguna clase de interfaz nos da esa vista tan bonita, todo es gracias a Django REST framework, si allí donde dice ``GET`` lo cambiamos a Json nos dará una respuesta como las que estábamos acostumbrados

![[IMG/Pasted image 20221004192237.png]]


y eso es todo por hoy, aprendimos el como usar los ``serializadores``, los decoradores ``@api_view`` y donde antes asábamos los views.py (que dejamos comentado todo) allí teníamos un un objeto que usaba un complex data, luego lo convertíamos y lo mandábamos como un Response, peor ahora que creamos un serializador que maneja todo con respecto a esta conversion y todo lo que tenemos que hacer es en "api/views.py seleccionar un complex data, pasar estos datos al serializador 
![[IMG/Pasted image 20221004193013.png]]
decirle que son multiples objetos ``many=True`` luego solo use serializador y ``.data`` y envíe una respuesta y listo, con eso mandamos la información que pedimos por un GET, en los próximos episodios veremos como mandar un POST, PUT o DELETE request y todo eso usando el decorador ``@api_view()``  y utilizando bien la guía https://www.django-rest-framework.org/api-guide/views/