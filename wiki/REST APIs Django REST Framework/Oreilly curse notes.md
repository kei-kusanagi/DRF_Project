
Ya tenia el proyecto creado pero la regué tratando de añadirle archivos estáticos y una pagina de login, entonces opte por crearlo nuevamente (sirve practico)

## Creating JSON Response - Individual Elements

creamos nuestro proyecto de Django y de aquí es de donde saque la buena practica de ponerle ``_app`` para saber cuales son

hacemos nuestras migraciones

luego creamos un super usuario

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221003175917.png)


listo ya entramos al panel de administración, ahora crearemos: 
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

## DRF Introduction

primero iniciamos instalándolo ``pip install djangorestframework`` y lo añadimos a las INSTALLED_APPS

Lo que estábamos haciendo actualmente era obtener datos complejos que son nuestro conjunto de consultas, estos los convertimos en un diccionario y lo mandamos como respuesta con un JSONResponse, esto lo hacemos dividiéndolo en 3 partes diferentes, cada que hacemos una entrada estamos creando nuevos objetos (actualmente solo son 3 name, description y active) entonces si quiero obtener algo, lo mandare a llama y me lo dará en forma de objeto de modelo actual y al convertirlo al diccionario de Python estamos haciendo una **serialización** y ya lo que queda es pasar (return) ese diccionario en forma de JSON, hasta ahorita hacemos todo esto manualmente, mapeando cada uno de los elementos individualmente, y ahorita solo son 3 pero pueden ser mas de 10 o 20 campos, por lo tanto si seguimos haciéndolo asi nos llevara mucho tiempo, aparte que ahorita solo estamos creando, nos falta poder consultar, actualizar y borrar **_(CRUD)_** todo esto lo podemos hacer mas fácil con la serialización y luego convertirlo en JSON (ta muy difícil de entender pero dice que se explicara cuando empecemos a trabajar en ello)

Ahora que es la **deserializacion** , si ahorita queremos entregar información a un usuario estamos serializando, pero si necesitamos _obtener_ información del usuario (GET) para almacenarla en la base de datos, para esto tenemos que deserializar los datos. Suponiendo que tenemos información en forma de JSON, luego necesitamos convertirla en un diccionario y luego desrealizarlo y almacenarlo en forma de objeto en nuestra DB eso seria la deserialización, comenta aquí que es donde todos cometemos errores pero que entre mas lo trabajemos mejor lo entenderemos

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221004101920.png)


habla mucho sobre los tipos de serialización y que usaremos postman y que no nos preocupemos si ahorita no le entendemos, pero que casi todo mundo se pasa directo a serializar sin siquiera explicar que es, sin mencionar que no dicen que por ejemplo la "funciones basadas en vistas" es como "serializers.Serializer" y que las "clases basadas en vistas" es "serializers.ModelSerializer"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221004152909.png)

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

## Serializers - GET Request

Ahora creamos un nuevo archivo dentro de la carpeta api llamado "serializers.py" este es importante porque hara el mapeo de todos los valores paso a paso (por eso comentamos lo de "views.py" porque ya no lo haremos allí si no aquí)

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
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221004163222.png)

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

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221004175951.png)

pero si queremos entrar a http://127.0.0.1:8000/movie/list/ tenemos un error y de tarea tenemos que resolverlo  #Tarea

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221004184759.png)


la solución es modificar "views.py" agregar ``many=True`` en el "serializer" ya que estamos mandando a llamar multiples instancias, en el de movie details no hay bronca porque solo estamos llamando una gracias al "pk" entonces con esto podemos visitar cada elemento de la lista y serializarlo tan sencillo como eso, con decirle que van a ser vario ``many=True``

```Python
serializer = MovieSerializer(movies, many=True)
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221004190517.png)

y aquí aclara el porque aunque no le estamos poniendo ninguna clase de interfaz nos da esa vista tan bonita, todo es gracias a Django REST framework, si allí donde dice ``GET`` lo cambiamos a Json nos dará una respuesta como las que estábamos acostumbrados

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221004192237.png)


y eso es todo por hoy, aprendimos el como usar los ``serializadores``, los decoradores ``@api_view`` y donde antes asábamos los views.py (que dejamos comentado todo) allí teníamos un un objeto que usaba un complex data, luego lo convertíamos y lo mandábamos como un Response, peor ahora que creamos un serializador que maneja todo con respecto a esta conversion y todo lo que tenemos que hacer es en "api/views.py seleccionar un complex data, pasar estos datos al serializador 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221004193013.png)
decirle que son multiples objetos ``many=True`` luego solo use serializador y ``.data`` y envíe una respuesta y listo, con eso mandamos la información que pedimos por un GET, en los próximos episodios veremos como mandar un POST, PUT o DELETE request y todo eso usando el decorador ``@api_view()``  y utilizando bien la guía https://www.django-rest-framework.org/api-guide/views/

## Serializers - POST, PUT, DELETE Request

Bien, ya tenemos hasta ahora nuestra forma de obtener ['GET'] nuestras películas por id y por lista, todo gracias a nuestros serializadores, ahora aparte de obtener hagamos uno para crear, para esto vamos a https://www.django-rest-framework.org/api-guide/views/#api_view 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005112714.png)

Segun la documentación tenemos que agregar ``['GET', 'POST']`` a nuestro decorador en "api/views.py"

```Python
...

@api_view(['GET', 'POST'])

def movie_list(request):

    movies = Movie.objects.all()

    serializer = MovieSerializer(movies, many=True)

    return Response(serializer.data)
...
```

ahora vamos a nuestro "serializers.py" y creamos el método de crear

esto va dentro de la clase "MovieSerializer" que es algo que se me complica aun #Duda le pasamos como parámetro a el mismo y luego un _"validatred_data"_  (según esto ya nos explicara cada uno y el porque)

luego creamos un objeto con "Movie.objects.create" y le pasamos el mentado "validated_data" que contiene nuestro nombre, descripción y si esta activa (aun no se como obtiene eso) y lo regresamos con un "return"

```Python
...
    def create(self, validated_data):

        return Movie.objects.create(**validated_data)
...
```

ahora vamos a "api/views.py" y dividiremos nuestro "movie_list" en dos partes, poniéndole un if para que cheque si nuestro "REQUEST" es 'GET' o 'POST'


si el "request" trae 'POST' entonces creamos un serializador nuevo con "MovieSerializer" y le pasamos "data" y según esto viene dentro del "request.data" #Duda porque según esto al mandarle el request con 'POST' el usuario mandara aparte la otra información (seguro ahorita veremos como), ahora le ponemos otro if para ver si el objeto él cual creamos con "MovieSerializer" es valido y si lo es le damos un "serializer.save()" y listo retornamos como "Response(serializer.data)"

por ultimo tenemos que pasarle un "else" por si el serializador no es valido (ósea que pasen mal los datos dentro del "reques.data")

```Python
...

@api_view(['GET', 'POST'])

def movie_list(request):

  

    if request.method == 'GET':

        movies = Movie.objects.all()

        serializer = MovieSerializer(movies, many=True)

        return Response(serializer.data)

    if request.method == 'POST':

        serializer = MovieSerializer(data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data)

        else:

            return Response(serializer.errors)
...
```

corremos nuestro servidor y vamos a http://127.0.0.1:8000/movie/list/

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005115859.png)

nos sale esa caja de texto, que viene precisamente del decorador
```Python
@api_view(['GET', 'POST'])
```
(si le quitamos ['POST'] se quitara) recordemos que esto es gracias al Django REST framework que nos da esa pequeña interfaz, ahora provisos mandarle un 'POST', este tiene que ser en forma de Json asi que copiemos el ultimo y cambiémosle los datos (ojo quitamos el "id" porque ese se lo pondrá automático y no nos dejara cambiarlo)
```Json
    {
        "name": "Programmer X",
        "description": "Description 3",
        "active": true
    }
```

Y obtenemos este bonito error, que según esto falto algo en nuestro "serializers.py"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005120326.png)

asi que revisando falto importar

```Python
from watchlist_app.models import Movie
```

lo importamos y lo volvemos a pasar

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005120813.png)

listo allí esta, por fin nuestro método ['POST'] sirve, recordemos que nos esta mostrando la información porque le pusimos en el "If" de ['POST']
```Python
...
return Response(serializer.data)
...
```

si volvemos a visitar http://127.0.0.1:8000/movie/list/ nos regresara ahora ls 3 películas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005121047.png)

Perfecto, ahora iremos con el método ['UPDATE'] y ['DELETE']

vamos a "api/views.py" y agregamos a nuestro decorador de "movie_details" )este porque este nos permite ver 1 sola película y no una lista. Primero pondremos un "if" para cada caso, para que dependiendo del REQUEST que nos manden sea el Response que le mandemos, 

si nos manda ['UPDATE'] tendremos que actualizar todos los datos (name, description y active) si nos manda ['PUT'] solo actualizaremos uno de los datos, así que en el "if" lo primero que le mandamos son los datos (data=request.data) serializados, luego checamos si son datos validos con otro "if", si es valido le damos "serializer.save()" pa que lo salve y un return Response y si no, le mandamos un else con el error, quedando mas o menos asi

```Python
...

@api_view(['GET', 'PUT', 'DELETE'])

def movie_details(request, pk):

    if request.method == 'GET':

        movie = Movie.objects.get(pk=pk)

        serializer = MovieSerializer(movie)

        return Response(serializer.data)

    if request.method == 'PUT':

        serializer = MovieSerializer(data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data)

        else:

            return Response(serializer.errors)
...
```

ahora antes de pasar a 'DELETE' tenemos que actualizar una condición en "serializers.py" aquí crearemos las instrucciones de como "actualizar" cada "instancia", lo pongo entre comillas porque es importante ya que tenemos que separar con ese "instance.name" para solo actualizar el nombre y así con los demás campos, al final solo salvamos con "instance.save()" y eso nos guardara solo esa instancia y las demás no las tocara

```Python
...

    def update(self, instance, validated_data):

        instance.name = validated_data.get('name', instance.name)

        instance.description = validated_data.get('description', instance.description)

        instance.active = validated_data.get('active', instance.active)

        instance.save()

        return instance
...
```

Ahora si, volvemos a correr el servidor y el buen REST framework nos regala la opción ya de DELETE(arriba a la derecha) y de PUT (abajo a la derecha) intentemos mandarle un PUT para actualizar la primera película

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005161306.png)

Pareciera que si lo hizo pero en realidad nos creo un nuevo objeto (vean el "id": 4) esto paso porque no le dijimos con el "pk" que objeto es el que queremos actualizar y por eso creo un nuevo ( #Duda sigo sin saver como demonios le dices eso con el "pk")
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005161823.png)

entonces le agregamos el objeto movie y en el serializador se lo indicamos

```Python
...

if request.method == 'PUT':

        movie = Movie.objects.get(pk=pk)

        serializer = MovieSerializer(movie, data=request.data)

        if serializer.is_valid():
...
```

vamos nuevamente al "/movie/1" y actualizamos los datos
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005162251.png)

 Y ahora si, solo nos actualizo el campo de descripción sin que nos creara una nueva película
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005162352.png)


Bien ahora el método que nos falta ['DELETE']
igual que en el caso de actualizar debemos seleccionar que película es la que queremos borrar... sip, nuevamente con el "pk=pk" ya que la tengo seleccionada (asignándosele el objeto a la variable "movie") le damos movie.delete()

```Python
...

if request.method == 'DELETE':

        movie = Movie.objects.get(pk=pk)

        movie.delete()
```

tratemos de borrar el que creamos de mas "id":4 en http://127.0.0.1:8000/movie/4 dandole en el boton grandote que dice DELETE

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005163058.png)

nos sale una bonita advertencia gracias al REST framework y …

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221005163124.png)

nos da este error porque claro, no estamos regresando ningún "Response" al momento de borrar, así que le agregamos ese ``return Response()`` que por el momento dejaremos así en blanco, pero podríamos ponerle algún buen mensaje, pero eso lo veremos hasta el siguiente capitulo ya que tenemos que hablar sobre "status code"

## Status Codes

Bien, que es un status code, simple es el "ERROR 404" que nos da cada que no encontramos algo, eso es un "status code" y ahora se lo podemos configurar cada que mandemos una petición, podemos ir a https://www.django-rest-framework.org/api-guide/status-codes/ y revisar bien cada uno, y lo primero que sale es ``from rest_framework import status`` y después de importar esto checando al documentación, al momento de borrar pues ya no tendremos el contenido que estábamos viendo así que le diremos que nos regrese un "HTTP_204_NO_CONTENT"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006134532.png)

Así que pasémoslo al código
```Python
...

from rest_framework import status

...

    if request.method == 'DELETE':

        movie = Movie.objects.get(pk=pk)

        movie.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)

```

vamos a testearlo, intentemos borrar el "id" 6

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006135124.png)

le damos en "DELETE" y 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006135337.png)

Pareciera que nada cambio pero podemos ver esto, que en efecto es el "status code" que le dijimos nos diera
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006135312.png)

ahora pondremos un "status code" a cada request, empecemos por el de error que nos podia dar en ep 'POST' y en el 'PUT' si nuestra petición estaba mal, vamos a la documentación y checamos los diferentes errores

```Python
else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
```

si checamos el de 'GET' este ya tiene definido un  "HTTP_200_OK"
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006141029.png)

Nada mas por curiosidad lo voy a cambiar yo (esto no vienen en el curso) pa ver si esto depende de realmente lo que se esta haciendo (en este caso 'GET' o si puedo personalizarlo)
```Python
...
if request.method == 'GET':

	movie = Movie.objects.get(pk=pk)

	serializer = MovieSerializer(movie)

	return Response(serializer.data, status=status.HTTP_208_ALREADY_REPORTED)
...
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006141159.png)

ok, al parecer en efecto pueden ser los status code exactamente lo que yo quiera, incluso si no es solo 2XX si no cualquiera 4XX por ejemplo
```Python
...
if request.method == 'GET':

	movie = Movie.objects.get(pk=pk)

	serializer = MovieSerializer(movie)

	return Response(serializer.data, status=status.HTTP_428_PRECONDITION_REQUIRED)
        
...
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006141359.png)

Ok lo regresamos a como estaba y que pasa si le ponemos que nos busque la película "id"=15, esta no existe y si lo buscamos nos sacara un error pero un un "Response" con un "status code" así que vamos a ponerle una condición con un ``try`` (hace mucho no usaba uno de esos) diciéndole que intente try: si con el GET hay una película collo id sea = al "pk" except: la película no existe entonces te mando este mensaje de error y también añadimos que el status sea un HTTP_404

```Python
...

@api_view(['GET', 'PUT', 'DELETE'])

def movie_details(request, pk):

  

    if request.method == 'GET':

        try:

            movie = Movie.objects.get(pk=pk)

        except Movie.DoesNotExist:

            return Response({'error': 'Movie not found'}, status=status.HTTP_404_NOT_FOUND)

  

        serializer = MovieSerializer(movie)

        return Response(serializer.data)

...
```

Perfecto, chequen como el mensaje dentro del Json es 
```Json
{
    "Error": "Movie not found"
}
```

y el mensaje en status si es igual al que le pusimos ``HTTP_404_NOT_FOUND`` 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006142317.png)

Y es todo pro ese capitulo de "status code" estuvo interesante me abrió un poco mas los ojos a los códigos ya que yo pensaba que no podia customisarlos, que al momento de borrar algo me debería dar algo como 4xx pero no, yo puedo definir que ponerle y no necesariamente 4xx si no un 204 de no hay contenido, al final le puse nuevos "status code" y termino quedando así:

```Python
from rest_framework.response import Response

from rest_framework.decorators import api_view

  

from watchlist_app.models import Movie

from watchlist_app.api.serializers import MovieSerializer

  

from rest_framework import status

  
  

@api_view(['GET', 'POST'])

def movie_list(request):

  

    if request.method == 'GET':

        movies = Movie.objects.all()

        serializer = MovieSerializer(movies, many=True)

        return Response(serializer.data)

    if request.method == 'POST':

        serializer = MovieSerializer(data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

  

@api_view(['GET', 'PUT', 'DELETE'])

def movie_details(request, pk):

  

    if request.method == 'GET':

        try:

            movie = Movie.objects.get(pk=pk)

        except Movie.DoesNotExist:

            return Response({'error': 'Movie not found'}, status=status.HTTP_404_NOT_FOUND)

  

        serializer = MovieSerializer(movie)

        return Response(serializer.data)

    if request.method == 'PUT':

        movie = Movie.objects.get(pk=pk)

        serializer = MovieSerializer(movie, data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data)

        else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'DELETE':

        movie = Movie.objects.get(pk=pk)

        movie.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)
```
## APIView Class

Moy bien, ahora vamos a la documentation y buscamos "Class-based Views" https://www.django-rest-framework.org/api-guide/views/ lo que aprenderemos a usar ahora son las ``APIView`` podemos allí mismo en la documentación ver el repositorio de GitHub donde esta detallada toda esta clase, pero por ahora solo necesitamos entender como utilizar esta "APIView class" y pos bueno, aunque sonara feo ya no usaremos la "api/views.py" que hemos estado creando hasta ahora, bueno el archivo si pero las funciones no así que la la comentaremos para no darle borrar así nomas 😢...

Lo primero sera importar esta clase ``from rest_framework.views import APIView`` y comentamos el "api_view" que estábamos usando

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006165221.png)

luego lo primero que haremos sera crear una "Clase" llamada "movie_list" (le agregamos "AV" al final para distinguir que es una APIView y asi no mezclarla) ahora si queremos usar las condicionales que ya teníamos, ahora tendremos que usar definir ese método, con este definiremos todo lo que era hacer un 'GET' para hacer todas estas tareas en esta función. Vamos a la documentación y buscamos este método.

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006170506.png)

lo ponemos en nuestra nueva clase y alli declaramos todo lo que necesitara, le ponemos 
```Python
movies = Movie.objects.all()
```
quedaria mas o menos asi:

```Python
...

class MovieListAV(APIView):

    def get(self, request):

        movies = Movie.objects.all()

        serializer = MovieSerializer(movies, many=True)

        return Response(serializer.data)

...
```

Para asignarle la lista completa de películas a esta variable por eso la s al final de movie"s" jajajaja, ahora todo lo que necesitamos para acceder a esto seria utilizar mi "serializador" y regresar nuestro "Response" y listo, esta definido mi metodo 'GET',ahora solo falta ponerle el condicional "if" (osea antes era con el fi preguntar si era un 'GET' o un 'POST' pero ahora estamos definiendolo por separado)

Entonces tenemos que recolectar todos los datos  usar este serializador 

```Python
...

class MovieListAV(APIView):
...

	def post(self, request):
	
	        serializer = MovieSerializer(data=request.data)
	
	        if serializer.is_valid():
	
	            serializer.save()
	
	            return Response(serializer.data, status=status.HTTP_201_CREATED)
	
	        else:
	
	            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

```

Aqui estamos llemando mi serializador y pasando el ``data=request.data`` (que es el Json que estamos pasando)
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006171928.png)

Cuando tenemos todo esto checamos si esta bien con el "if serializer.is_valid():" y si es valido usamos el método salver "serializer.save()" si todo esta bien regresamos el "Response(serializer.data)"

Y listo, algo que tenemos que tener en cuenta es que no vamos a usar ningun timpo de decorador en neustras classes basadas en vistas, además, no necesitamos definir este tipo de condiciones (el ``(['GET', 'POST'])``).

En este momento no tenemos nada como eliminar o colocar, por lo que debemos crear otra clase para nuestro elemento específico.

Y mas en especifico ya que tenemos que seleccionar un "id" en especifico (ya dije muchas veces especifico jajaja) y volverá a nosotros el famoso "pk" así que crearemos una nueva "clase"
```Python
class MovieDetailAV(APIView):
```
ahora dentro de esta tenemos que definir nuevamente un método tipo 'GET', 'PUT' y 'DELETE' porque aquí podremos seleccionar un elemento especifico tanto para obtener su información, ponerle o borrarla, así que creemos una función para primero obtener ('GET')

```Python
...

def get(self, request, pk):

	try:

		movie = Movie.objects.get(pk=pk)

	except Movie.DoesNotExist:

		return Response({'error': 'Movie not found'}, status=status.HTTP_404_NOT_FOUND)
...
```

luego nuestro método ('PUT')

```Python
def put(self, request, pk):

	movie = Movie.objects.get(pk=pk)

	serializer = MovieSerializer(movie, data=request.data)

	if serializer.is_valid():

		serializer.save()

		return Response(serializer.data)

	else:

		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
```

y por ultimo nuestro ('DELETE')

```Python
def delete(self, request, pk):

	movie = Movie.objects.get(pk=pk)

	movie.delete()

	return Response(status=status.HTTP_204_NO_CONTENT)
```

Con todo esto ya solo nos falta actualizar nuestras "URLs" porque alli estamos usando la anterior "movie_list" que esta apuntando a la anterior función en views

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006180022.png)

lo cambiaremos por  y en el path ponerle ".as_view" para indicarle que es una vista
```Python
from django.urls import path, include

#from watchlist_app.api.views import movie_list, movie_details

from watchlist_app.api.views import MovieListAV, MovieDetailAV

  

urlpatterns = [

    path('list/', MovieListAV.as_view(), name='movie-list'),

    path('<int:pk>', MovieDetailAV.as_view(), name='movie-detail'),

]
```

corremos el servidor y agreguemos un elemento mas para poder hacer pruebas

El 'POST' trabaja bien

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006180858.png)


Ahora si intentamos obtener una pelicula en particular por el "pk" 'GET'

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006181239.png)

Probemos el 'PUT'
```Json
{
    "name": "Java vs Python",
    "description": "Description 3 - update",
    "active": false
}
```
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006181536.png)

Perfecto, ahora borremos uno con 'DELETE'

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221006181720.png)


Y eso es todo con respecto con la introducción las "Class-based Views" ya que hay muchas mas que veremos, más adelante, vamos a utilizar esta clase genérica y vamos a tener este "ListCreateAPIView". Luego hay varias otras vistas de API tenemos "RetrieveAPIView", "DestroyAPIView", "CreateAPIView".pero hablaremos de ellas en los siguientes capítulos junto con expandir nuestra base de datos y usar un "Foreign Key".

## Validation

Ok hoy toca Validaciones (después de un repaso rápido de todo lo que había echo hasta ahora), así que vamos a la documentación y veamos que nos dice https://www.django-rest-framework.org/api-guide/serializers/#validation lo primero que nos salta son 3 tipos de validaciones "Fiel-level", "Object.level" y por ultimo "Validators" estas validaciones las utilizaremos en nuestro archivo "serializers.py" y en nuestro archivo "views.py" las mandaremos llamar donde pusimos el ``if serializer.is_valid():``

"Fiel-level"

La primera de la que hablaremos sera "Field.level", se refiere a que solo estaremos revisando un campo en particular en busca de alguna palabra duplicada, entonces si por ejemplo nos vamos al campo de "name" en 

```Python
...
name = serializers.CharField()
...
```

si agrego una validación "Field.level", eso significa que estoy verificando su longitud o tal vez cualquier otra condición según yo elija. Pero eso significa que solo estoy revisando este único campo que no se repita por ejemplo el nombre con la descripción de la película y así, ta medio confuso pero lo veremos paso a paso.

Así que vamos a nuestro "serializers.py" y definamos nuestra validación para un campo en especifico, tomemos ahorita el campo de "name", lo que haremos sera checar el valor actual de su longitud del nombre, para esto creemos un método (función nueva) y la llamaremos "validate_name" y tomara ds entradas, una sera "self" osea ella misma y la segunda sera "value" que sera el valor de nombre, empezamos con una condicional if y le decimos que si la longitud del nombre es menor a 2 (ósea dos caracteres) le regresaremos un error de validación y le diremos que el nombre es muy corto

```Python
...
	# Field level validation
    def validate_name(self, value):

        if len(value):

            raise serializers.ValidationError('Name is too short')

        else:

            return value
            
...
```

provemoslo, vallamos a crear un nuevo item pasándole un nombre de película normal y luego con uno muy shiquito jejejeje

Provemos con 

```Json
    {
        "name": "PHP - The Old King",
        "description": "Description 3",
        "active": true
    }
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221007154357.png)

ahora con
```Json
    {
        "name": "J",
        "description": "Description 4",
        "active": true
    }
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221007154448.png)


"Object.level"

Perfecto, ahora sigamos con el "Object.level" comparando si el nombre de la película no es exactamente igual que la descripción, igual haremos una comparación pasándole el "data['title']" comparándolo si es idéntico al "data['description']:" si no es el caso entonces con un "else:" le regresamos el "data"

```Python
...
# Object level Validation

def validate(self, data):

	if data['name'] == data['description']:
	
		raise serializers.ValidationError('Description cannot be the same as the title')
	
	else:
	
		return data
...
```

Probémoslo haciendo un nuevo elemento poniéndole como nombre y descripción lo mismo

```Json
    {
        "name": "Description ",
        "description": "Description",
        "active": true
    }
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221007182522.png)


"Validators"

Ahora, el validador es en realidad un argumento central que debemos pasar a nuestros campos actuales. entonces si vamos a la documentación vemos que estamos pasando este validador como valor dentro de nuestro serializador, necesitamos agregar una validación de nivel de campo a nuestro nombre, puedo hacerlo con la ayuda de validadores, vamos a nuestro archivo "serializers.py" y comentemos por el momento el "Field level validation" y entonces dentro de donde convertimos el nombre con el serializador le pasamos la validación

```Python
name = serializers.CharField(validators=[ ])
```

y aquí le debemos pasar una función (que aun no definimos), la llamaremos "name_length" y en ella haremos la magia

```Python
name = serializers.CharField(validators=[name_length])
```

creamos nuestra función

```Python
def name_length(value):

    if len(value) < 2:

        raise serializers.ValidationError('Name is too short')
```

y al final el código queda así:

```Python
...

from rest_framework import serializers

from watchlist_app.models import Movie

  

def name_length(value):

    if len(value) < 2:

        raise serializers.ValidationError('Name is too short')

class MovieSerializer(serializers.Serializer):

    id = serializers.IntegerField(read_only=True)

    name = serializers.CharField(validators=[name_length])

    description = serializers.CharField()

    active = serializers.BooleanField()
...
```

Vamos a probarlo, metamos a http://127.0.0.1:8000/movie/list/ el siguiente Json

```Json
    {
        "name": "J",
        "description": "Description 3",
        "active": true
    }
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221007185206.png)

Y listo, eso es todo con estos tres tipos de validaciones, para mi me gusto mas la de "Object Level" aunque esta ultima suena mas complicada pero creo es la mas sencilla.

## Serializer Fields and Core Arguments

Hoy analizaremos el campo del serializador en "serializers.py"

```Python
class MovieSerializer(serializers.Serializer):

    id = serializers.IntegerField(read_only=True)

    name = serializers.CharField(validators=[name_length])

    description = serializers.CharField()

    active = serializers.BooleanField()
```

estos, donde podemos indicar si es un "IntegerField" y por ejemplo ese del "id" que es "read_only" eso quiere decir que quien nos mande peticiones puede verlo, pero no puede modificarlo, en pocas palabras hay posibilidades de que necesitemos agregar una cualidad o una instrucción específica, entonces con este "Core Argument" o "argumento central" podemos pasar ese valor.

No se porque s eme complico tanto esto, ya lo vi varias veces y pues lo que entendí que habla sobre el como podemos especificar el como se comportaran estos campos, como de solo lectura, o que sea un campo necesario y así, la única #Duda que me surgió es cuando habla que tenemos estos campos aquí en "seializers.py" y también en "models.py"


## Model Serializer

Lo primero que haremos sera comentar todo lo que hicimos hasta ahora de serializadores en "serializers.py" ya que crearemos un nuevo modelo de serializador

Para crear un nuevo "Model Serializer" tenemos que crear una nueva "class" 

```Python
class MovieSerializer(serializers.ModelSerializer)
```

Lo importante aquí es que ese ``ModelSerializer`` contiene todo lo relacionado con el CRUD de estos campos (los creados en "models.py" o eso es lo que entendí #Duda ) lo único que necesito es mencionar que "modelo" voy a usar, y en que "field" o campo voy a trabajar, si mencionamos "__all__" significa que usaremos todos

Si vamos a https://github.com/encode/django-rest-framework/blob/master/rest_framework/serializers.py y hacemos scroll mas abajo podemos encontrar las diferentes funciones que podemos usar para hacer el CRUD así como la información de como usarla

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221010140426.png)


![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221010140543.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221010140609.png)

Ya viendo todo esto ahora si vamos a codificar, camos a nuestro "serializers.py"

dentro de mi "class Meta" necesitamos definir nuestro modelos ( #Duda ven es a lo que me refería, pos no que tomaba todos de models.py) podemos definir cada uno individualmente o podemos definir todos

```Python
...

class MovieSerializer(serializers.ModelSerializer):

    class Meta:

        model = Movie

        fields = "__all__"
```

Y con eso es todo para definir el modelo del serializador, si necesitamos definir validaciones la podemos definir como lo hicimos anterior mente y las definimos separadamente como cuando definimos "Object level Validation" y "Field level validation"

```Python
...

class MovieSerializer(serializers.ModelSerializer):

    class Meta:

        model = Movie

        fields = "__all__"

# Object level Validation
     def validate(self, data):

        if data['name'] == data['description']:

            raise serializers.ValidationError('Description cannot be the same as the title')

        else:

            return data

# Field level validation

    def validate_name(self, value):

        if len(value) < 2:

            raise serializers.ValidationError('Name is too short')

        else:

            return value
```

Repasando, definimos nuestro ``class Meta:`` enseguida definimos nuestros modelos indicándole que usara todos los campos con`` fields = "__all__"`` y luego le pasamos las validaciones que ya habíamos creado, ahora que pasa detrás de cámaras es que como ya tenemos este modelo en "models.py" ( #Duda aaaaaaa ven ven si era lo que yo decía) el serializador los mapea respectivamente , al decirle que ocupamos todos los campos ``fields = "__all__"``le estamos diciendo que agarre todos los de allí, se pueden excluir o usar solo algunos pero para este ejemplo lo seguiremos usando así

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221010150008.png)

Probemos agregar un nuevo item con este método "Model Serializer"

```Json
    {
        "name": "DRF",
        "description": "Description",
        "active": true
    }
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221010150723.png)

Perfecto, si lo creo con todos los campos, ahora intentemos crear uno pero sin que salga el campo "active", para esto vamos a "serializers.py" y cambiemos el campo ``fields = "__all__"`` y definimos cada campo individualmente pasándole una lista tupla sin poner el campo "active"

```Python
...

fields = ['id', 'name', 'description']

...
```

Salvamos y vamos a http://127.0.0.1:8000/movie/list/ y veos que nuestro campo "active" se fue

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221010152424.png)


podemos llegar al mismo resultado si le damos ``exclude = ['active']`` y eso le dirá que tome todos menos ese 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221010173030.png)

a ver intentemos quitar `['name']`

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221010173126.png)


Y bueno des comentemos estoy y lo dejaremos solo para recordarlo

```Python
...

class MovieSerializer(serializers.ModelSerializer):

    class Meta:

        model = Movie

        fields = "__all__"

        # fields = ['id', 'name', 'description']

        # exclude = ['name']
...
```


## Custom Serializer Fields

Bueno ahora hablemos sobre los "Custom Serializer Fields", anteriormente tenemos estos campos mencionados en nuestro "models.py" pero que pasa si queremos calcular algo con estos, por ejemplo con ratings o cosas así, y que debamos desplegar un nuevo campo que tenga una longitud u otro nombre, esto lo haremos especificando otro método, vallamos entonces a nuestro "serializers.py" y justo enzima de nuestro "class Meta:" pongamos nuestro nuevo serializador al cual llamaremos "len_name" y le asignamos un "SerializerMethodField" cn esto estamos definiendo un método que calculara la longitud de los nombres y esto nos los regresara en el "Response"

```Python
len_name = serializers.SerializerMethodField()
```

ahora solo tenemos que definir un método (una función pues) abajo de "class Meta:" y lo llamaremos "get_len_name"

```Python
...

    def get_len_name(self, object):

        return len(object.name)
...
```

Y alli esta nuestra longitud del nombre
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011124700.png)

#Duda no vi como es que hace que esto salga dentro del Json final, como lo encadena con el len_name si solo puso en la funcion get_len_name y nunca lo llama 

## Updating Models

Ahora nos tocara nuevamente hablar sobre modelos, actualmente contamos con 3

```Python
...
class Movie(models.Model):

    name = models.CharField(max_length=50)

    description = models.CharField(max_length=200)

    active= models.BooleanField(default=True)
...
```

Y si queremos crear un con de IMDb, vamos a necesitar mas campos, asi que vamos a borrar completamente nuestra base de datos y crear nuevos modelos y actualizar mis vistas y serializers

Así que vamos a "serializers.py" y ya no necesitaremos las validaciones así que borrémoslas (o mejor las comentamos no valla a ser) y cambiemos el nombre de nuestro modelo de Movie a algo mas genérico por si son podcast, o series, algo como "Watchlist" pero primero localicemos nuestro archivo db.squlite3 y borremosla

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011143305.png)

Ahora si pongámosle bien el nombre, cambiemos el nombre de "name" a "title" y pongamos uno nuevo llamado "created" que usara el "DateTimeField" y le pondremos "auto_now_add=True" para que quede como una estampa de tiempo indicándonos cuando fue creado, al final lucira asi

```Python
...
class Watchlist(models.Model):

    title = models.CharField(max_length=50)

    storyline = models.CharField(max_length=200)

    active= models.BooleanField(default=True)

    created = models.DateTimeField(auto_now_add=True)

  

    def __str__(self):

        return self.title
...
```

Ahora creemos un nuevo modelo llamado "streamingPlataform" pa saver en donde verlo y poner directamente el link, agréguenosle un campo de "name" con un "mx_length" de 30, un campo llamado "about" com 150 caracteres y el "website" este sera un "URLField" y este le pondremos 100 caracteres y al final definimos una función, le pasamos a el mismo (self) y regresamos como ``return self.name``

```Python
...
class StreamPlataform(models.Model):

    name = models.CharField(max_length=30)

    about = models.CharField(max_length=150)

    website = models.URLField(max_length=100)

    def __str__(self):

        return self.name
...
```

#Duda porque solo regresamos el nombre si vamos a usar todos los demás campos????

Ahora debemos remplazar todo esto en nuestras "views.py", "serializers.py" y "models.py" quedando asi

```Python 
## views.py
from rest_framework.response import Response
# from rest_framework.decorators import api_view
from rest_framework.views import APIView

from watchlist_app.models import WatchList
from watchlist_app.api.serializers import WatchListSerializer

from rest_framework import status
  

class WatchListAV(APIView):


    def get(self, request):

        movies = WatchList.objects.all()

        serializer = WatchListSerializer(movies, many=True)

        return Response(serializer.data)

  

    def post(self, request):

        serializer = WatchListSerializer(data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

  

class WatchDetailAV(APIView):

    def get(self, request, pk):

        try:

            movie = WatchList.objects.get(pk=pk)

        except WatchList.DoesNotExist:

            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

  

        serializer = WatchListSerializer(movie)

        return Response(serializer.data)

    def put(self, request, pk):

        movie = WatchList.objects.get(pk=pk)

        serializer = WatchListSerializer(movie, data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data)

        else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):

        movie = WatchList.objects.get(pk=pk)

        movie.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)
```

```Python 
## serializers.py
from rest_framework import serializers

from watchlist_app.models import WatchList

  
class WatchListSerializer(serializers.ModelSerializer):

  

    class Meta:

        model = WatchList

        fields = "__all__"
```

```Python
## models.py
from django.db import models

  

class StreamPlataform(models.Model):

    name = models.CharField(max_length=30)

    about = models.CharField(max_length=150)

    website = models.URLField(max_length=100)

    def __str__(self):

        return self.name

  

class WatchList(models.Model):

    title = models.CharField(max_length=50)

    storyline = models.CharField(max_length=200)

    active= models.BooleanField(default=True)

    created = models.DateTimeField(auto_now_add=True)

  

    def __str__(self):

        return self.title
```

Hecha toda la refactorización debemos hablar de la class "StreamPlataform" donde necesitamos escribir un serializer basado en vistas como lo vimos anteriormente, para esto en "serializers.py" importamos nuestro modelo

```Python
from watchlist_app.models import WatchList, StreamPlataform
...
```

y creamos nuestra clase para el

```Python
...
class StreamPlataformSerializer(serializers.ModelSerializer):

  

    class Meta:

        model = StreamPlataform

        fields = "__all__"
...
```

Y ahora como la ves anterior vamos a "views.py" a crear nuestra clase

```Python
class StreamPlataformAV(APIView):
```

(recuerden le ponemos el AV al final porque es una Api View)

ahora necesitamos un método 'GET' y otro de 'POST', asi que importamos el modelo (como pa decirle que alli van a dar los datos a la base de datos) y tambien nuestro serializador "StreamPlataformSerializer"

```Python
from watchlist_app.models import WatchList, StreamPlataform
...
from watchlist_app.api.serializers import WatchListSerializer, StreamPlataformSerializer
...
```

Creamos nuestro metodo 'GET' le pasamos el mentado self y el request, ahora llamaremos a la variable "plataform" y le pasaremos todos los objetos, ya que tenemos acceso a ellos ahora usaremos el serializador "StreamPlataSerializer" le pasamos "plataform" y le decimos que pueden ser muchos objetos pa que no nos de el error de la otra vez "many=True", una ves hecho esto le regresamos un "Response" con los datos serializados ``return Response(serializer.data)`` 

```Python
...
class StreamPlataformAV(APIView):

    def get(self, request):

        plataform = StreamPlataform.objects.all()

        serializer = StreamPlataSerializer(plataform, many=True)

        return Response(serializer.data)
```

Listo eso es todo sobre mi 'GET' ahora vamos con el 'POST', vamos a hacer algo similar, necesitamos el acceso a mi self y al request, usaremos nuestro serializador otra ves pero ahora tendremos acceso al contenido pero no necesitaremos el "many=True" porque solo necesitaremos el accesos al data ``serializer = StreamPlataformSerializer(data=request.data)`` y ahora le pondremos una condición de que si es valido lo salve si no que de un "HTTP_400_BAD_REQUEST"

```Python
...

    def post(self, request):

        serializer = StreamPlataformSerializer(data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data)

        else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
...
```

ahora vamos a "api/urls.py" e importamos esto y añadimos su path (vengo del futuro, aquí también había un error con el import ya que importamos MovieLisAV y era ya WatchListAV y asi las otras)

```Python
from django.urls import path, include
from watchlist_app.api.views import WatchListAV, WatchDetailAV, StreamPlataformAV


urlpatterns = [

    path('list/', WatchListAV.as_view(), name='movie-list'),

    path('<int:pk>', WatchDetailAV.as_view(), name='movie-detail'),

    path('stream/', StreamPlataformAV.as_view(), name='stream'),

]
```

Bueno vamos a salvar y hacer las migraciones porque borramos la base de datos, pero nos salta un error

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011162415.png)

esto no lo había visto antes pero hay que ir al archivo "watchlist_app/admin.py" y modificar lo siguiente

```Python
from django.contrib import admin

from watchlist_app.models import WatchList, StreamPlataform
  

# Register your models here.

admin.site.register(WatchList)

admin.site.register(StreamPlataform)
```

ahora si le damos ``python manage.py makemigrations``

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011162929.png)

ahora si le damos ``python manage.py migrate``

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011163031.png)


Recordemos crear un super usuario porque borramos todo lo anterior
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011163429.png)
Corremos el servidor y nos logeamos en http://127.0.0.1:8000/admin/
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011163539.png)

Bien ya tenemos nuestro Stream plataforms, vamos a añadir una pelicula en Watch list

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011163625.png)

ahora vamos a http://127.0.0.1:8000/movie/list/ y ya podemos ver hasta cuando fue creado

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011163722.png)

ahora vamos a http://127.0.0.1:8000/movie/stream/ (aqui el tenia un error porque no lo había importado pero a mi me salto y lo corregí desde antes)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011163910.png)

añadamos un elemento desde el panel de administración

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011170040.png)

Ahora agreguemos uno por una petición por medio de un Json

```Json
    {
        "name": "Prime Video",
        "about": "Streaming Service",
        "website": "https://www.primevideo.com"
    }
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221011170253.png)

Como lo creamos solo podemos acceder a todos los elementos y si queremos actualizar un elemento por separado tenemos que entrar al panel de administración
## Django Relationships

A como me costo trabajo la tarea pero ya quedo, se trataba de poner el "StreamPlataformDetailAV" para poder hacer un get, put y delete especifico pero de las plataformas, entonces vamos a "views.py" y creamos nuestra clase ``class StreamPlataformDetailAV(APIView):`` y le definimos la opcion de ger, put y delete

```Python
  
...
    def get(self, request, pk):

        return Response(serializer.data)

    def put(self, request, pk):

         return Response(serializer.data)


    def delete(self, request, pk):

        return Response(status=status.HTTP_204_NO_CONTENT)
...
```

le pasamos su serializador pero tambien el mentado y famosisimo "pk", en el get bastara con eso y ponerle una excepcion por si no existe y su mensaje de error

```Python
...

    def get(self, request, pk):

        try:

            plataform = StreamPlataform.objects.get(pk=pk)

        except StreamPlataform.DoesNotExist:

            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
...
```

para el put le agregamos al serializer los datos que nos estan pasando y un if por si es valido lo salvamos si no va pa atras

```Python
...

    def put(self, request, pk):

        plataform = StreamPlataform.objects.get(pk=pk)

        serializer = StreamPlataformSerializer(plataform, data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data)

        else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

...
```

Y en el delete con el poderosísimo "ok" le indicamos cual es y le damos ".delete()" y le pasamos un Response de no hay contenido

```Python
  
...
    def delete(self, request, pk):

        plataform = StreamPlataform.objects.get(pk=pk)

        plataform.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)
...
```

Y por ultimo y por lo que estaba trabado porque no sabia que faltaba, pos vamos a "urls.py" y le pasamos el path

```Python
...
path('stream/<int:pk>', StreamPlataformDetailAV.as_view(), name='stream-detail'),
...
```

Dejando de lado la tarea ahora si veamos las "Django Relationships" o relaciones, lo primero que haremos es actualizar nuestro URL para que no se siga llamando /movies/ lo cambiaremos a /watch/ esto lo hacemos en "/watchmate/urls.py" pa que valla coherente con lo que estamos haciendo

```Python
from django.contrib import admin

from django.urls import path, include

  

urlpatterns = [

    path('admin/', admin.site.urls),

    path('watch/', include('watchlist_app.api.urls')),

]
```
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221012142538.png)

Ahora, necesitamos agregar algo para que al momento de agregar una película podamos añadir en que plataforma podemos verla, esto lo haremos con el "relationship method in Django" y existen 3, el "one-to-one", "one-to-many" y "many-to-many" y aquí nos envió a google a buscar mas sobre eso

Relación uno a uno
https://youtu.be/fEf1LWYfb9A

Relación uno a muchos 
https://youtu.be/VxrHagfpr2k

Relaciones muchos a muchos 
https://youtu.be/oDeHM_SQNnM

Ok ya aclarado el tema ahora vamos a nuestro panel de administracion a borrar nuevamente todo pero sin borrar nuestra base de datos, ahora vamos a "models.py" y creamos nuestra nueva "relationship" alli:

Crearemos una variable con nombre "plataform" y de modelo usaremos el "ForeignKey" y le pasaremos "StreamingPlataform" (lo que dijimos, una película o una serie o un show solo podrá tener una plataforma, pero una plataforma si podrá tener varias películas, series o shows, ósea, este video solo podrá ser visto en Netflix por ejemplo), le pasamos el "on_delete=models.CASCADE" por si se borra la plataforma borrar todos los que tengan relación con ella y así no dejar películas sin plataforma

```Python
...

class WatchList(models.Model):
    title = models.CharField(max_length=50)
    storyline = models.CharField(max_length=200)
	#Relathiuonship "one-to-many"
    plataform = models.ForeignKey(StreamPlataform, on_delete=models.CASCADE, related_name="watchlist
	#####
    active= models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)
 

    def __str__(self):
        return self.title
```

Hecha nuestra relación nos queda hacer las migraciones otra ves, nos pedirá elijamos una opción, le pondremos "1" y luego "None" (esto lo hace porque a los datos que ya hay les faltara ese campo, entonces le decimos que si lo agregue y que a todos los que ya esten les ponga None como valor y listo)
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221012152447.png)
Vallamos nuevamente a http://127.0.0.1:8000/admin/watchlist_app/watchlist/ y ya nos da la opción de relacionar con que plataforma es

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221012174352.png)

pongamos algunos ejemplos, llenando primero las plataformas, haciendo una con "None" , "netflix" y otra con "Prime Video" y luego creemos "watch list"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221012181215.png)

Si vamos a http://127.0.0.1:8000/watch/stream/ veremos que si nos aparecen normalmente 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221012181926.png)

pero si vamos a http://127.0.0.1:8000/watch/list/ nos aparecen como ``"plataform": 4`` 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221012181917.png)

tambien i vamos a los detalles de una plataforma http://127.0.0.1:8000/watch/stream/5 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221012182127.png)

Nos aparecen sus datos pero no que películas están relacionadas con el, pero todo eso lo veremos el siguiente capitulo.
## Nested Serializers

En este capitulo veremos sobre la relación anidada o "Nested Relationship" o como la manejaremos aquí "Nested Serializer", entonces lo que queremos hacer es si vamos a http://127.0.0.1:8000/watch/stream/ veremos que tenemos nuestros 3 servicios de stream (bueno 2 namas y el none) y lo que queremos lograr es "relacionar" que peliculas tiene cada una, y para hacer eso debemos crear una Relación en el Serializador (aaaah lo dijo lo dijo)

Para ayudarnos iremos a la documentación a https://www.django-rest-framework.org/api-guide/relations/#nested-relationships entonces después de una breve introducción vamos a "serializers.py" y tomemos nuestra class "StreamPlataformSerializer" y pongámosla después de nuestra WatchListSerializer (porque? pues no se!) y alli8 mismo antes de nuestra clase Meta creamos una variable llamada "watchlist" o un nuevo item y un nuevo campo, que va a tener todos los elementos con respecto a esta "watchlist" en traducción, si seleccionamos Netflix se le asignara a este item todas las películas o watchlist (recuerden que cambiamos el nombre por si eran series o podcast) que contenga Netflix

```Python
...

class StreamPlataformSerializer(serializers.ModelSerializer):

    watchlist = WatchListSerializer(many=True, read_only=True)

    class Meta:

        model = StreamPlataform

        fields = "__all__"
...
```

si vamos nuevamente a http://127.0.0.1:8000/watch/stream/ vemos como ya nos aprese en forma de lista las "watchlist" que tenemos asignadas a Netflix y PrimeVideo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013135246.png)

Recordemos que este watchlist:
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013135442.png)
es mui importante, porque lo definimos aquí en "models.py" en "related_name"
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013135552.png)

Si le cambiamos ese nombre en nuestro "Nested Serializer" no funcionara
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013135933.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013135945.png)

En resumen o lo que entendí es que con esa simple instrucción 
```Python
...
watchlist = WatchListSerializer(many=True, read_only=True)
...
```
Estamos guardando en ese item llamado "watchlist" que lo pasamos dentro de models con el mismo nombre como 

```Python
...
plataform = models.ForeignKey(StreamPlataform, on_delete=models.CASCADE, related_name="watchlist")
...
```
y a el le asignamos todas las watchlist que posea el serializador

Bueno intentemos añadir una nueva plataforma pero desde las peticiones

```Json
    {
        "name": "Disney +",
        "about": "D+",
        "website": "https://www.disneyplus.com"
    }
```
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013141232.png)

Ahora agreguemos algunas Watchlist a nuestra nueva plataforma, vamos a http://127.0.0.1:8000/watch/list/  y pasémosle una petición 

```Json
    {
        "title": "C++",
        "storyline": "Description",
        "active": false,
        "plataform": 6
    }
```
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013142645.png)

y si vamos a checar el detalle de nuestra nueva plataforma nos aparecerá esta relación anidada jejeje

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013142745.png)


## Serializer Relations

En el capitulo anterior vimos como usar el serializador anidado pero que pasa, que nos muestra todo el contenido relacionado, que pasa si solo queremos cierta parte del contenido como el nombre o la descripción solamente, para esto podemos usar los "serializer relations", si vamos a la documentacion podemos usar el "StringRelatedField" https://www.django-rest-framework.org/api-guide/relations/#stringrelatedfield

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013173548.png)

Nos viene hasta con un ejemplo, el cual usaremos (igualito que el anidado)

```Python
serializers.StringRelatedField(many=True)
```

en este retornaremos todo lo que tiene el "modelo" como un string (una cadena pues o el famoso ``__str__`` ), asi que igual vamos a nuestro archivo "serializers.py" y comentemos el anterior y pongamos este mas especifico:

```Python
...
class StreamPlataformSerializer(serializers.ModelSerializer):

    # watchlist = WatchListSerializer(many=True, read_only=True)

    watchlist = serializers.StringRelatedField(many=True)

    class Meta:

        model = StreamPlataform

        fields = "__all__"
...
```

Lo que hara esto es utilizar nuestro modelo  y lo regresara como esto "title"

Imagen de "models.py"
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013175016.png)

Si vamos nuevamente a http://127.0.0.1:8000/watch/stream/ veremos que ya solo nos muestra los titulos de las peliculas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013175142.png)

#Duda hasta dónde entendí esto pasa porque en el model, le dijimos cuando lo creamos que regresara el titulo pero que hubiera pasado si le ponemos otro campo, a ver movámoslo a ver si no la riego, vamos a "models.py"
y sip, le puse el "storyline" y me regresa eso, que raro porque en la instrucción solo le estoy diciendo "StringRelatedField" apoco ese save que me estoy refiriendo a lo que estoy retornando en el modelo..
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013175411.png)

En fin sigamos a ver si después puedo resolver la duda


Ahora según el curso, que pasa si en ves de querer regresar el nombre queremos regresar el PrimaryKey o el famoso "pk", pues hay una instrucción que nos ayuda
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013175817.png)

vamos a copiarla y usarla como la anterior, asignándole eso a nuestra variable watchlist

```Python
...
class StreamPlataformSerializer(serializers.ModelSerializer):

    # watchlist = WatchListSerializer(many=True, read_only=True)

    # watchlist = serializers.StringRelatedField(many=True)

    watchlist = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:

        model = StreamPlataform

        fields = "__all__"
...
```
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013180009.png)

Y sip, nos muestra nuestro "pk" pero pues no nos sirve de mucho, seria mejor que nos mostrara el link directo para poder ver las peliculas y adivinen que, si hay un Serializador para esto llamad o "HyperlinkRelatedField"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013180131.png)

Pero este no solo es cortar y pegar como en los anteriores, aquí debemos cuidar nuestro nombre de nuestra vista, entonces necesitamos crear nuestros links de películas (los que habíamos creado eran para plataformas) así que le pasamos ``view_name='movie-detail'`` 

```Python
    watchlist = serializers.HyperlinkedRelatedField(

        many=True,

        read_only=True,

        view_name='movie-detail'

    )
```

Esto nos generara un error
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013180922.png)

pero alli mismo nos da la respuesta, tenemos que pasar el contexto como parte del request en el serializador, entonces vamos anuestra vista en "views.py" y en nuestra clase "StreamPlataformAV" en el request (del serializador) le agregamos el contexto

```Python
...
class StreamPlataformAV(APIView):

    def get(self, request):

        plataform = StreamPlataform.objects.all()

        serializer = StreamPlataformSerializer(plataform, many=True, context={'request': request})

        return Response(serializer.data)
...
```

Wow neta pareció magia que nomas no capisque como lo hizo bien, pero ahora cada que le damos click a uno nos lleva al "movie detail"... aaaaaaaaaaaaaah por eso usa el pk, ósea lo que hizo fue darnos el link de la petición del movie detail y namas le pasa el pk de cada uno

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221013181332.png)

Y bueno quitemos todo eso porque le gusta mas como esta XD

## HyperLinked Model Serializer

hoy toca hablar del "HyperLinked Model Serializer" esto al igual que el anterior "HyperlinkedRelatedField" que vimos, nos ayudara a acceder pro medio de un URL a algún elemento en particular, por ejemplo en este momento, hemos estado usando el "id" para relacionar todos los elementos, pero con este "HyperLinked Model Serializer" podremos tener el link para entrar al detail de este elemento en ves de ese feo "id"
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221014113920.png)

Si nos vamos a la documentación https://www.django-rest-framework.org/api-guide/serializers/#hyperlinkedmodelserializer el HLMS es igual que el modern serializer, con excepción que representa la relacion como una "pk" (esa es la única diferencia #Duda no entendí 😅), para usarlo tenemos que pasárselo en la clase 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221014121403.png)

Vamos a "serializers.py" y experimentemos, en la class ``class StreamPlataformSerializer(serializers.ModelSerializer):`` cambiemos el ModelSerializer por el HLMS
```Python
...
class StreamPlataformSerializer(serializers.HyperlinkedModelSerializer):

    watchlist = WatchListSerializer(many=True, read_only=True)
...
```


ahora cada que mandemos llamar ese serializador debemos mandar un contexto
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221014121750.png)

así que vamos a "views.py" y le pasamos el contexto en donde inicializamos nuestro serializador "StreamPlataformSerializer"

```Python
...
class StreamPlataformAV(APIView):

    def get(self, request):

        plataform = StreamPlataform.objects.all()

        serializer = StreamPlataformSerializer(plataform, many=True, context={'request': request})
        return Response(serializer.data)
...
```

Y se supone que deveria darnos esto

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221014135300.png)
pero a mi por mas que lo intente no me salió #Duda regresar después a ver que paso aqui que ya gaste mucho tiempo tratando de ver porque me salia esto
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221014135435.png)


Y eso es todo por este capitulo, recomienda dar un repaso de todo porque se vienen cosas mas difíciles 
## Serializer Relations Continued

Ahora en esta y las siguientes lecciones, nos estaremos enfocando en las "Generic views", pero no iniciaremos esto directamente, empezáremos a expandir el proyecto empezando con los "models" otra vez.

Ahorita tenemos información respecto a las películas o series, como en que plataforma están pero queremos agregar un nuevo "feature", que sera los "Ratings"  entonces en ves de reescribir todas las vistas y tareas mejor agregaremos esto creando una nueva "class", asi que vamos a nuestro archivo "models.py" y creamos esta nueva "class" y la llamaremos "Review" esto igual tomara nuestro "models.Model".

Ahora, recuerde, el motivo principal es crear una clase de revisión adecuada y luego conectarla a través de una clave externa o "foreign key".

Entonces, si abro cualquier película o watchlist podremos tener opciones para ver su reseña, y recordemos que la "relationship" que usaremos es que cada "review" solo podrá calificar una película pero una "watchlist" podrá tener muchas "reviews"

Pues bien vamos a "models.py" y escribamos nuestra clase, donde definitivamente necesitamos la variable "rating" la cual variara entre el 1 y el 5, necesitamos un sistema de reseñas usando valores positivos así que de models usaremos "PositiveIntegerField" y ahora podemos añadirle validadores aqui y los validadores nos ayudan a definir una brecha específica o definir un rango específico para números y aqui usaremos lo que es el "MinValueValidator" y "MaxValueValidator" (y necesitamos importarlos primero)

```Python
...
from django.core.validators import MinValueValidator, MaxValueValidator
...

class Review(models.Model):

    rating = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
```

Lo siguiente que necesitamos es que este es una reseña, pero necesitamos una descripción de la reseña así que se la agregamos como "model.CharField", también necesitaremos dos "DateTimeField" unos para cuando fue creado y otro cuando se actualiza

Ahora, sabemos que debemos conectarlo con un active por si son "reviews" falsas poderlo poner como desactivado y listo


```Python
...
class Review(models.Model):

    rating = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])

    description = models.CharField(max_length=200, null=True)

    active = models.BooleanField(default=True)

    created = models.DateTimeField(auto_now_add=True)

    update = models.DateTimeField(auto_now=True)
```

Listo ya tenemos todo para los "reviews" ahora solo necesitamos conectarlo con las multiples películas, entonces lo añadimos abajo de la descripción, lo vamos a conectar a nuestra watchlist (por eso le ponemos el nombre de la variable asi), esto va a ser una relacion "models.ForeignKey" y supongamos que si alguien eliminó esta película, eso significa que todas las reseñas deberían eliminarse. Así que esto debería ser models.CASCADE. Esto se ve bien y luego necesito proporcionar "related_name" si alguien abre una película aquí, ¿cuál debería ser el término que debería estar visible aquí? Llamémoslo solo como "reviews". ya solo nos falta pasar el rating ( #Duda aun no me queda claro como despues de uan class por medio de una funcion regresamos algo de ella)

```Python
...
class Review(models.Model):

    rating = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])

    description = models.CharField(max_length=200, null=True)

    #Relationship
    watchList = models.ForeignKey(WatchList, on_delete=models.CASCADE, related_name="reviews")

    active = models.BooleanField(default=True)

    created = models.DateTimeField(auto_now_add=True)

    update = models.DateTimeField(auto_now=True)

  

    def __str__(self):

        return str(self.rating)
```

Paramos el servidor y le damos "makemigrations" y "migrate"
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017141515.png)

una cosa mas que debemos hacer es registrarlo para que nos salga en el sitio de administración de Django, así que vamos a "admin.py" y registramos nuestro modelo.

```Python
from django.contrib import admin

from watchlist_app.models import WatchList, StreamPlataform, Review


# Register your models here.

admin.site.register(WatchList)

admin.site.register(StreamPlataform)

admin.site.register(Review)
```

Listo, ahora creemos un "review"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017142327.png)

Ahora en ves de que solo se vea el 5 hagamos que se vea el nombre de la pelicula o wactchlist a la que se refiere, vamos  a "models.py" en la funcion que nos regresa el rating le pondremos esto

```Python
...
    def __str__(self):

        return str(self.rating) + " | " + self.watchList.title
```
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017142545.png)

Ahora eso se hace en nuestra sección de administración y esto solo verifica que hayamos escrito el modelo correcto. Ahora lo que tenemos que hacer es acceder a esta información. Así que tenemos que escribir puntos de vista. Y necesitamos escribir un serializador, lo importante es que necesitamos hacer una relación. Entonces, aquí en nuestra "StreamPlataform" podemos tener muchas películas. Del mismo modo, ahora con nuestras películas, podemos tener muchas críticas y debemos seguir algo similar en nuestro archivo "serializers.py" escribimos una nueva clase "ReviewSerializer" y usaremos nuestro "ModelSerializer" lo importamos arriba, añadimos nuestro "class MEta:" y dentro necesitamos tomar todo de mi model y nuestros campos, yle pasaremos todos

```Python
...
from watchlist_app.models import Review, WatchList, StreamPlataform, Review
...
class ReviewSerializer(serializers.ModelSerializer):

    class Meta:

        model = Review

        fields = "__all__"
...
```

Ya que tenemos eso creemos nuestra "relationship" necesitamos definir "reviews" le pasamos su serializador "ReviewSerializer" y le decimos que "many=True" y lo ponemos como solo de lectura, esto significa que cuando envío una solicitud de publicación mientras agrego una película, un podcast o cualquier tipo de programa, no voy a agregar una reseña. Luego voy a agregar todos estos campos. Pero cuando voy a enviar una solicitud de obtención, también voy a recibir este campo de solo lectura. Entonces podemos agregar una revisión a través de este campo solo este serializador, no podemos agregar una revisión desde el serializador.

```Python
...
class WatchListSerializer(serializers.ModelSerializer):

    reviews = ReviewSerializer(many=True, read_only=True)
...
```

y listo ahora si accedemos a cada watchlist nos aparecerá sus reviews

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017144749.png)
## GenericAPIView and Mixins

En el capitulo anterior nos quedamos en que ya podemos hacer los ratings, y los vamos a mostrar pero no vamos a utilizar esta clase APIView (por ejemplo en  ``class StreamPlataformAV(APIView):`` ), usaremos la vista genérica junto con los mixins osease "GenericAPIView" y "Mixins". Asi que brinquemos a la documentación y vamos donde dice "Tutorial" y luego donde dice "class based views" https://www.django-rest-framework.org/tutorial/3-class-based-views/
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017193210.png)

Estando alli veremos que tenemos 3 Vistas basadas en clases la "using APIView class", la segunda parte que debemos discutir será usar "mixins" esta esla que nos interesa.

Entonces, ¿cómo vamos a usar estos mixins? Básicamente, vamos a importar GenericAPIView. Ahora, junto con este GenericAPIView, podemos importar mixins y ¿por qué los vamos a usar? Tenemos esta clase APIView, ¿por qué necesitamos otro tipo de vista API? Entonces, la cuestión es que estos mixins son muy populares para realizar tareas comunes.
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017194221.png)
Todo lo que tenemos que hacer es proveerle settings básicos y podremos realizar estos métodos comunes como enumerar, crear, recuperar, actualizar y podemos realizar todas estas tareas comunes muy rápidamente. No tenemos que definir todo así con estos detalles (como en nuestras funciones en "views.py". Así que no tenemos que escribir todo, todo lo que vamos a hacer es definir nuestro conjunto de consultas "query set" y luego definir qué tipo de método necesitamos.
Todo lo que vamos a hacer es definir nuestro conjunto de consultas y luego definir qué tipo de método necesitamos. Recordemos que con estos mixins, tenemos el método ".list", ".create", ".retrieve", ".update" y ".destroy". Estos son los métodos comunes que necesitamos, cuando queremos extraer todos los elementos(osea los "reviews") vamos a usar "ListModel", cuando necesitamos realizar una solicitud "post request" (ósea crear una "review"), vamos a usar "create" cuando necesitemos recuperar un elemento individual (como cuando queremos el detail de solo uno), usaremos "retrieve", luego tenemos "update" y "destroy".

Bueno ahora si vamos a codificar, vamos a copiar el ejemplo que nos aparece y lo ponemos en "views.py"
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017195704.png)

Así que por ahora voy a recuperar todas las "reviews" y voy a crear una "post request" en una sola página, osea poner todas las reviews en una lista simple, y recordar que lo que queremos hacer es crear una dirección tipo "stream/1/review" y que esto me de TODOS los reviews que tenga la película o watchlist "1", que no se mezclen los reviews pues que solo nos de los de la pelicula 1 y muestre todos pero de esa misma, si le ponemos la 2 que no nos muestre los reviews mezclados de la 1 y la 2, que solo sean los reviews de la 2 pero que sean todos y asi.

Entonces, lo que vamos a hacer es por ahora con fines de prueba, voy a crear una lista de revisión "ReviewList" y aquí también necesito importar mi "generic class" ``from rest_framework import status, mixins, generics``
Entonces, lo que estamos haciendo aquí es pasar directamente nuestro "queryset". No tenemos que hacer todo línea por línea, solo necesito compartir mi "queryset" importamos esta clase (de "watchlist_app.models") y ahora mi "queryset" está listo, solo necesito usar mi serializador (lo importamos)

```Python
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from rest_framework import generics
from rest_framework import mixins


from watchlist_app.models import WatchList, StreamPlataform, Review
from watchlist_app.api.serializers import WatchListSerializer, StreamPlataformSerializer, ReviewSerializer


class ReviewList(mixins.ListModelMixin, mixins.CreateModelMixin, generics.GenericAPIView):

    queryset = Review.objects.all()
    serializer_class = ReviewSerializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
...
```
En "resumen" hemos creado nuestra clase "ReviewList", ahora vamos a utilizar esta importación de vista genérica "GenericAPIView". Entonces importartamos todas las mezclas de métodos que necesitamos realizar. Si vemos, hemos importado "ListModelMixin", eso significa que necesito realizar una solicitud de "request for list". Y aquí también hemos realizado "CreateModelMixins", eso significa que necesito realizar una "post request" que se creará.  Luego, necesitamos definir mi "queryset" en el que voy a recopilar todos los objetos. Luego necesito definir mi "serializer_class", recuerde, este es un nombre de atributo y no podemos cambiarlos.
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017211353.png)

Ahora lo que tenemos que hacer es dentro de nuestra solicitud de obtención, solo necesito devolver mi lista y dentro de mi solicitud de publicación, solo necesito crearla.

Ahora debemos ir a "urls.py" y crear sus paths, estamos tratando de obtener todas las reseñas que están disponibles en nuestra base de datos así que vamos a usar la "review" como mi enlace y luego voy a importar mi "revisión.as_views"
```Python
from django.urls import path, include

from watchlist_app.api.views import ReviewList, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV


urlpatterns = [

    path('list/', WatchListAV.as_view(), name='movie-list'),
    path('<int:pk>', WatchDetailAV.as_view(), name='movie-detail'),
    path('stream/', StreamPlataformAV.as_view(), name='stream'),
    path('stream/<int:pk>', StreamPlataformDetailAV.as_view(), name='stream-detail'),
	#GenericAPIView and Mixins
    path('review', ReviewList.as_view(), name='review-list'),

]
```

Listo, vamos a http://127.0.0.1:8000/watch/review y 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017212423.png)

Actualmente solo tenemos un elemento dentro de nuestra sección de "review", eso significa que solo tenemos un objeto dentro de nuestra tabla de "review". Y nos recomienda no usar la opción de HTML form, que mejor sigamos usando el Json con Raw data, porque despues usaremos PostMan y pues alli es a puro Json también

Y bueno, recordemos que con esta vista podemos hacer "post request" tambien, asi que hagamos una para darle un "review" a otra peliclua

```Json
    {
        "rating": 5,
        "description": "Good Movie - second review",
        "active": true,
        "watchList": 4
    }
```

Recordemos que le tenemos que pasar nuestro famoso "pk" que seria en este caso que watchlist nos referimos (osea que pelicula), en este caso la ``"watchList": 4`` 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017213118.png)

y si regresamos a http://127.0.0.1:8000/watch/review nos mostrara una lista con todas las reviews
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221017213159.png)

Muy bien, como mencionamos tenemos múltiples clases, pero tal vez si queremos recuperar un solo un elemento(como cuando mandabamos a llamar un "watchlist" por detalle), lo que voy a hacer es utilizar este "RetrieveModelMixin" en neustro "views.py". 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018115228.png)
Así que lo que vamos a hacer crear una nueva clase y la llamaremos "ReviewDetail", voy a importar "mixins" y el "RetrieveModelMixin" y al final también importamos el "GenericAPIView". Ya hecho esto definimos nuestro "queryset" y solo necesitamos pasarle nuestro objeto "review"  y nuestro "serializer_class" que es "ReviewSerializer" y dentro de mi "gest request" solo necesitamos regresar una opcion de recuperacion o "retrive option (que seria la función que les digo que tengo #Duda de porque se usa eso pa regresar datos)" 

```Python
...
class ReviewDetai1(mixins.RetrieveModelMixin, generics.GenericAPIView) :

    queryset = Review.objects.all()

    serializer_class = ReviewSerializer

    def get(self, request, *args, **kwargs):

        return self.retrieve(request, *args, **kwargs)
...
```

Ahora solo tenemos que crear una url en nuestro "urls.py" primero usaré esta clave principal ("pk") y luego, en lugar de "list", usaré "detail" aparte necesitamos agregarlo en las importaciones como "ReviewDetail" Y en lugar de "review-list", lo llamaré "review-detail"

```Python
from django.urls import path, include
from watchlist_app.api.views import ReviewList, ReviewDetail, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV

urlpatterns = [
    path('list/', WatchListAV.as_view(), name='movie-list'),
    path('<int:pk>', WatchDetailAV.as_view(), name='movie-detail'),
    path('stream/', StreamPlataformAV.as_view(), name='stream'),
    path('stream/<int:pk>', StreamPlataformDetailAV.as_view(), name='stream-detail'),

    path('review', ReviewList.as_view(), name='review-list'),
    # GenericAPIView and Mixins
    path('review/<int:pk>', ReviewDetail.as_view(), name='review-detail'),
]
```

Listo ahora vamos a nuestro servidor e intentemos acceder a un review, mediante la url http://127.0.0.1:8000/watch/review/1

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018121551.png)

Y recordemos que hemos agregado solo obtener "request". Eso significa que básicamente no podemos realizar la solicitud de creación o "post". Estos son bastante importantes cuando tenemos que realizar tareas sencillas como acceder, crear, eliminar o actualizar y eso veremos en la siguiente lección donde aprenderemos a como eliminarlos con este método basado en clases que usara una "generic view" basada en clases, y en la próxima lección reduciremos aun mas esto para que quede mas como en el ejemplo de la documentación.

## URL Structure

Muy bien, en los capítulos anteriores habíamos creado estas dos clases
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018161507.png)

estas vistas estan bien asi pero, al momento de darle en http://127.0.0.1:8000/watch/review me muestra TODAS las reviews, entonces vamos a crear una URL para revisar individualmente por peliculas o watchlist (porque pueden ser podcast o series) tipo ponerle esta ruta http://127.0.0.1:8000/stream/1/review y nos de todos los reviews de esa pelicula y por otra parte si queremos revisar una sola review poderle poner una ruta tipo http://127.0.0.1:8000/watch/review/1 y que nos salga solo esa review

ahorita de echo podemos ingresar a ese enlace y nos saldra el detalle del review como queremos
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018162515.png)

Pero no podemos modificarlo ni destruirlo, así que en las siguientes lecciones veremos como y ahorita esta solo fue para enseñarnos la estructura de como quedara.

## Concrete View Classes

En esta lección comenzaremos un nuevo viaje 🚞 que serán las "Concrete View Clases" oxea las clases de vista concretas, asi que si vamos a la documentación podemos dar click aquí donde dice ``generics.py`` 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018163951.png)
que nos llevara aqui https://github.com/encode/django-rest-framework/blob/master/rest_framework/generics.py

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018164050.png)

y si hacemos scroll para abajo podremos ver las diferentes clases que usaremos como la "CreateAPIView", "ListAPIView", "RetriveAPIView" aqui ya viene toda la información, por ejemplo en "ListAPIView" ya viene con la función de lista , en la de  "RetriveAPIView" igual ya tiene la función de obtención y así.

Entonces, cuando vamos a utilizar estas "clases de vista concreta", no necesitamos escribir estas listas ni nada más, aunque ahorita estubimos usando "mixins", necesitamos escribir las funciones. Pero cuando vamos a usar estas "Clases de Vista Concreta", no necesitamos importarlas porque ya las tienen.

Lo primero que haremos sera comentarlos en nuestro archivo "views.py" y comentamos nuestras dos clases anteriormente creadas, la "ReviewDetail" y la "ReviewList" y luego los modificaremos de acuerdo con nuestras nuevas URL.

Asi que vamos a la documentacion y buscamos "ListCreateAPIView" que es lo que queremos "crear una lista de nuestros ratings" https://www.django-rest-framework.org/api-guide/generic-views/#listcreateapiview
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018190851.png)
Alli nos menciona que nos dara tanto un "get" como un "post"

Entonces vamos a "views.py" y creemos una clase, a eso si, tambien teniamos que importar "generics" (como lo dice el ejemplo) pero ya lo habiamos importado antes junto con "mixins" entonces namas comentamos el "mixins"

Creamos la class y llamamos a "ReviewList" primero y haremos todo igualito a como creamos las clases anteriores con los "mixins" pero en ves de usar esos "mixins" usaremos la clase generica "ListCreateAPIView" y asi, esto me dara el poder de mandar un "get" y de "post", luego dre crear mi casa devemos definir dentro mi "query set" y mi "serializer class", entronces nuestro "queryset" igual que la ves anterior sera "Review.objects.all()" y nuestro serializador de clase sera "ReviewSerializer"

```Python
...
from rest_framework import generics
...
class ReviewList(generics.ListCreateAPIView):

    queryset = Review.objects.all()

    serializer_class = ReviewSerializer
...
```

Y listo, con esto no tendremos que escribir NADA MAS 😲, ahora tenemos que ir a nuestro "urls.py" y alli deveriamos escribir su URL pero ya la escribimos anteriormente
```Python
...
path('review/', ReviewList.as_view(), name='review-list'),
...
```

Ahora necesitamos otra pero para los detalles, regresamos a "views.py", creamos nuestra clase y la llamamos "ReviewDetail" igual le pasamos la clase genérica "generics.RetriveUpdateDestroyAPIView" esto me dará opciones para hacer "get", "put" y "delete", después definimos nuestro "queryset" y nuestro "serializer_calss" (igualito que con los mixins, peor a diferencia que esto es todo)

```Python
...
class ReviewDetail(generics.RetrieveUpdateDestroyAPIView):

    queryset = Review.objects.all()

    serializer_class = ReviewSerializer
...
```

Después deberíamos ir a "urls.py" y definir su path pero ya lo habíamos echo anteriormente

```Python
...
path('review/<int:pk>', ReviewDetail.as_view(), name='review-detail'),
...
```

vamos a nuestro servidor a ver como se ve http://127.0.0.1:8000/watch/review/1
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018194130.png)

Oh que diferencia, ahora si nos da la opción de borrar y solo con dos líneas. Anteriormente, tenemos que definir todo en forma de get, put y delete. Luego tratamos de reducirlos en forma de estos mixins. Ahora los hemos eliminado por completo.
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018195728.png)

antes de terminar intentemos mandar otro review, metemos este json en http://127.0.0.1:8000/watch/review/ 

```Json
    {
        "rating": 5,
        "description": "Great Movie",
        "active": true,
        "watchList": 4
    }
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018200040.png)

perfecto, ya tenemos nuestra tercera review, intentemos hacerle un update entrando al detalle de ese review http://127.0.0.1:8000/watch/review/3


```Json
    {
        "rating": 5,
        "description": "Great Movie - update",
        "active": true,
        "watchList": 4
    }
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018200221.png)

Perfecto, ahora intentemos borrarlo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018200301.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221018200313.png)

Perfecto, todo lo que habíamos configurado antes cosa pro cosa lo hace con las 2 líneas que escribimos, genial 😲
## Overwrite Queryset

Ahora cambiaremos los paths para que al momento de ver la lista de "reviews" por ejemplo de la pelicula "4" no nos salgan todos los reviews existentes, si no solo los que sean de esa pelicula o "watchlist".

Para esto primero vamos a "urls.py" y cambiamos nuestros paths de la siguiente forma, para tener una estructura mas apegada a lo que queremos

```Python
...
    # path('review/', ReviewList.as_view(), name='review-list'),
    # path('review/<int:pk>', ReviewDetail.as_view(), name='review-detail'),
  

    path('stream/<int:pk>/review', ReviewList.as_view(), name='review-list'),
    path('stream/review/<int:pk>', ReviewDetail.as_view(), name='review-detail'),
...
```
si vamos a http://127.0.0.1:8000/watch/stream/4/review nos muestra la lista completa de reviuews, incluso si ponemos uno nuevo a otra pelicula sale alli
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019114444.png)
Aunque por el path estamos dándole el "pk" 4 ósea la película "C++", nos debería mostrar solo el review que tiene esta no los de las otras películas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019114601.png)

la razón viene de este querryset en nuestro "views.py"
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019120841.png)
por default accede a todas las reseñas ``objects.all()`` y no solo a la de la pelicula que queremos, entonces, lo que tenemos que hacer es eliminar este conjunto de consultas y sobrescribirlo, para esto creamos una funcion definiendo nuestro queryset method, esto se tomara a si mismo "self" y le añadimos una declaracion de devolucion "return" accediendo primeramente a nuestra "pk" voy a usar self y luego necesito usar mi ``kargs['pk']``  porque todo va a estar aquí dentro, luego le doy un return al "Review" y vamos a filtrar todas las watchlist y solo regresar la que concuerde con mi "PK"

```Python
...
class ReviewList(generics.ListCreateAPIView):

    # queryset = Review.objects.all()

    serializer_class = ReviewSerializer

  
    def get_queryset(self):

        pk = self.kwargs['pk']

        return Review.objects.filter(watchList=pk)
...
```

Guardamos y si vamos nuevamente a http://127.0.0.1:8000/watch/stream/4/review
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019122937.png)

Perfecto, ya solo nos sale la "review" que se le dio a ese "watchlist" en particular, ya por ultimo cambiaremos nuestra clase "ReviewList" para que solo podamos "ver" , cambiando el "ListCreateAPIView" por un "ListAPIView" (jejeje namas le quitamos la opcion Create)

```Python
...
class ReviewList(generics.ListAPIView):
...
```

Listo desapareció el cuadro de dialogo donde podíamos crear reviews.
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019140920.png)

Pero ahora, como podremos crear los reviews si no es para no solo usar el método de entrar a la sección de administración, entonces vamos a nuestro archivo "urls.py" y agregamos este path y añadimos "ReviewCreate" en nuestro "form" aun que aun no creamos esa "class"

```Python
...
from watchlist_app.api.views import ReviewList, ReviewDetail, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV, ReviewCreate
...
    path('stream/<int:pk>/review-create', ReviewCreate.as_view(), name='review-create'),
...
```

Ahora si vamos a "views.py" a crear nuestra "class" y la llamaremos "ReviewCreate" le pasaremos generics.CreateAPIView" (osease pa crear que es lo que estamos viendo con las clases concretas de vistas co "concrete view class"), ahora dentro de esta clase iniciamos el serializador de las "reviews el "ReviewSerializer" y ya con eso creamos nuestra función y la llamaremos "perform_create" para hacerle "override" al método crear (por cierto sacamos ese método de la documentación)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019142608.png)

Entonces dentro de nuestro "perform_create" le pasamos el self y luego nuestro seryalizador, luego dentro de esto seleccionamos nuestra "pk", utilizamos nuestro self el tendrá toda la información dentro de nuestros "kwargs" (argumentos) y nuestro "pk" (que estamos obteniendo del link).

Luego iniciamos nuestro "movie" (pa no confundirlos porque le habia puesto igual watchlist) pasándole que obtenga la watchlist que corresponda a nuestro "pk" (cuando obtenga la película que le pasamos por el pk la guardara en movie), lo único que queda es salvar nuestro serializador indicándole que nuestra watchlist (ósea lo que regresaremos en el serializador) sera igual a el "movie" que acabamos de definir

```Python
...
class ReviewCreate(generics.CreateAPIView):

    serializer_class = ReviewSerializer

  

    def perform_create(self, serializer):

        pk = self.kwargs.get('pk')

        movie = WatchList.objects.get(pk=pk)

  

        serializer.save(watchList=movie)
...
```
Guardamos y ahora mandamos a llamar este metodo (por medio del link que definimos) 
http://127.0.0.1:8000/watch/stream/1/review-create
desglosandolo pa entender
``http://127.0.0.1:8000/ `` el servidor
``watch/stream/`` nuestra lista de plataformas
``1/`` la película dentro de esa plataforma al cual estamos apuntando con nuestro metodo
``review-create`` el método que acabamos de crear
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019145156.png)

ojo, nos aparece 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019145448.png)
porque solo esta permitido hacer post (Allow: POST, ), ahora vamos a mandarle un Json para comprobar que funciona 
```Json
{
    "rating": 5,
    "description": "Again a great movie",
    "active": true
}
```

Ojo quitamos el watchilist porque no lo necesitamos, ya que por el link al que mandaremos el request ya seleccionamos a cual seria la request
Nos da este error, y menciona que es porque en el serializador (ya ven queni lo tocamos) estamos mandando llamar todo, por copnsecuencia nos pide en el json que mandamos el watchlist, pero no lo necesitamos ya que apuntamos a el con el link
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019145827.png)

Como solución debemos ir a "serializers.py" y en nuestro "ReviewSerializer" quitarle el ``fields = "__all__"`` y excluir precisamente el watchlist

```Python
...
    class Meta:

        model = Review

        exclude = ('watchList',)

        # fields = "__all__"
...
```

Listo, ahora si ya incluso en el cuadro de dialogo no nos lo pide
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019150744.png)

Asi que mandemos nuevamente nuestro Json como review

```Json
{
    "rating": 5,
    "description": "Great movie - New!",
    "active": true
}
```
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019151216.png)

Y eso es todo por este episodio, la idea es que aunque lo simplificamos con dos líneas con el "concrete View Classes" podemos especificar los métodos por ejemplo este de "POST" para hacerlo mucho mas especifico (ósea primero lo simplificamos y luego lo complicamos jajaja bueno no es cierto)
## Viewsets and Routers


Bueno, este metodo no es algo importante, porque es preferible usar los diferentes tipos de vistas de clase genérica para cualquier tipo de API (de echó yo si vi que usaban mucho esto de los routers en los ejemplos que hacia antes y se me hacia arto complicado) asi que hablaremos de los "ViewSet" y los mendigos "Routers".

Lo primero es que nuestro objetivo es disminuir el tamaño del código de las últimas lecciones, ahora lo que vamos a hacer con "ViewSet" es combinar la logica para las listas "list" y los detalles "detail" entonces vallamos a "views.py" y creemos una clase simple, primero importamos 
``from rest_framework import viewsets``
y ensima de nuestra "StreamPlataformAV" crearemos nuestra clase, la llamaremos "StreamPlataform" e importaremos nuestro ViewSet
``class StreamPlataform(viewsets.ViewSet)``
este viewset sporta varios metodos como los que queremos usar como lo que es list, create, retrive, update, partial update y destroy 💣, ais que vamos a la documentacion y de alli sacamos este ejemplo y copiamos y pegamos las funciones de list y retrive
https://www.django-rest-framework.org/api-guide/viewsets/
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019203158.png)

pero obvio no podemos namas copiar y pegar, tenemos que definir nuestro queryset, que en nuestro caso ya habiamos usado StreamPlataform y como serializador igual el que ya habiamos usado StreamPlataformSerializer

```Python
...
class StreamPlataform(viewsets.ViewSet):


    def list(self, request):

        queryset = StreamPlataform.objects.all()

        serializer = StreamPlataformSerializer(queryset, many=True)

        return Response(serializer.data)

  
    def retrieve(self, request, pk=None):

        queryset = StreamPlataform.objects.all()

        watchlist = get_object_or_404(queryset, pk=pk)

        serializer = StreamPlataformSerializer(StreamPlataform)

        return Response(serializer.data)
...
```

Así que ahora hemos creado una nueva clase en la que estamos importando este ViewSet y actualmente tenemos estos dos métodos, que son la lista "list" y la recuperación "retrieve".

Lo que voy a hacer es crear enrutadores ¿qué es este enrutador? un enrutador nos ayuda a combinar todo tipo de enlace. Entonces, cada vez que usamos un enrutador, no necesitamos crear un enlace separado como lo habíamos hecho ante (como estos de stream y stream-detail)
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019204100.png)
si bajamos un poco en la documentación https://www.django-rest-framework.org/api-guide/viewsets/ podemos ver que podemos crear routers con diferentes requerimientos
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019204000.png)

entonces vamos a "urls.py" y definimos nuestro router allí acordándonos de importarlo de "rest_framework.routers"
entonces usaremos router como nombre de la variable, luego usaremos "register" para el link y le pasaremos solo 'str' y le pasaremos nuestras "views" StreamPlataform (la clase que acabamos de crear) y lo incluimos en el import de las vistas, hecho esto solo tenemos que pasarle también un "basename" que sera 'streamplataform'.

Lo unico que nos falta es incluir este "router" en nuestro "urlpattern" asi que comentemos los dos que ya hacían lo de stream-list y stream-detail

```Python
...
from watchlist_app.api.views import ReviewList, ReviewDetail, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV, ReviewCreate, StreamPlataform
  
from rest_framework.routers import DefaultRouter
 

router = DefaultRouter()
router.register('stream', StreamPlataform, basename='streamplataform')


urlpatterns = [

    path('list/', WatchListAV.as_view(), name='movie-list'),
    path('<int:pk>', WatchDetailAV.as_view(), name='movie-detail'),
   
	path('', include(router.urls)),
...
```

Entonces, lo que voy a hacer es, una vez que alguien visite el enlace vacío. Se va a conectar con nuestros enrutadores para url. Aquí, vamos a llamar a este "stream" para acceder a esto. Si vamos a llamar a stream/1, que es un elemento individual, seguirá funcionando. Intentemos acceder a esta "stream" y obtenemos un error intencional, solo debemos cambiar nuestra clase porque se llama igual a otra que usamos de "StreamPlataform" a "StreamPlataformVS"  tanto en nuestras views como en nuestras urls

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019210712.png)

Ahora tenemos TODA la informacion de nuestras plataformas de stream, tooooda, y si queremos solo de una por ejemplo netflix que es la 4 http://127.0.0.1:8000/watch/stream/4/
nos da un error, per es porque nos falta importar en "views.py"
```Python
from django.shortcuts import get_object_or_404
...
```

ahora si vamos al enlace y... otro fregado error...

poner watchlist en el serializador

```Python
...
  def retrieve(self, request, pk=None):

        queryset = StreamPlataform.objects.all()

        watchlist = get_object_or_404(queryset, pk=pk)

        serializer = StreamPlataformSerializer(watchlist)
...
```

porfin, nos da TODOS los datos de esa plataforma
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221019212116.png)


## ModelViewSets

En el capitulo pasado hablamos de como con la clase "StreamPlataformVS" y la función de lista que creamos nos regresa la lista de todo lo que tiene la plataforma que elegimos gracias al potente router, que este método lo recomienda para proyectos grandes, cuando son pequeños prefiere que usemos el APIView

Entonces si ahorita solo nos da la opción de GET 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020140452.png])
de la misma forma en la parte de lista de streams también solo nos da el GET 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020140557.png)

Entonces si queremos añadirle la opción de crear, añadimos en nuestro archivo "views.py" otra función (de crear jajajaa) entonces si recordamos, necesitamos serializar todo y una validación y luego mandar un response, recordar, todo esto va en nuestra clase "StreamPlataformVS"

```Python
...
    def create(self, request):

        serializer = StreamPlataformSerializer(data=request.data)

        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data)

        else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
...
```

lo salvamos y 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020150529.png)

ya nos da la opcion de post, vamos a intentar mandarle un Json

```Json
    {
        "name": "HBO",
        "about": "SV",
        "website": "http://www.hbo.com"
    }
```

perfecto, si sirve.
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020150716.png)

Si queremos añadir el borrar podemos hacer algo similar y agregar algo similar solo que en ves de Delete se llama Destroy dentro de la documentación

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020150928.png)

Pero esto no lo pondremos pa borrar todas nuestras plataformas, eso lo tenemos que hacer de manera individual, como entrar al http://127.0.0.1:8000/watch/stream/3/ y que nos de aqui la opción de borrar 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020151332.png)

entonces esto lo podriamos hacer manualmente, pero lo bonito de lo que estamos viendo "ModelViewSet" tiene modelos para todo eso (usando mixins)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020151518.png)

entonces usaremos este nuevo método y por lo tanto comentaremos toda la clase "StreamPlataformVS" y creemos la nueva clase arriba y la llamaremos igual, dentro usaremos nuestro "viewset.ModelViewSet" con esto hecho ahora debemos definir nuestro "queryset" y nuestro serializador

```Python
...
class StreamPlataformVS(viewsets.ModelViewSet):

    queryset = StreamPlataform.objects.all()
    serializer_class = StreamPlataformSerializer
...
```
Y listo, ya con eso creamos un modelo completo que tiene todas las opciones, sera cierto? "pongámoslo a prueba"

Vamos a http://127.0.0.1:8000/watch/stream/3/

Perfecto si nos sale la opción de borrar y las demás opciones
``**Allow:** GET, PUT, PATCH, DELETE, HEAD, OPTIONS`` 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020174920.png)

Tenemos un sistema completo con solo 3 lineas

```Python
class StreamPlataformVS(viewsets.ModelViewSet):

    queryset = StreamPlataform.objects.all()
    serializer_class = StreamPlataformSerializer
```

Ahora, tenemos que discutir el "ReadOnlyModelViewSet"  si cambiamos lo que acabamos de hacer por este modelo

```Python
class StreamPlataformVS(viewsets.ReadOnlyModelViewSet):

    queryset = StreamPlataform.objects.all()
    serializer_class = StreamPlataformSerializer
```

y vamos a http://127.0.0.1:8000/watch/stream/3/, vemos que el botón de Delete o algo que pudiera dejarnos modificarlo desapareció (incluso el cuadro de texto de la parte de abajo)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221020175938.png)

Y bueno en resumen con estos "modelViewSet" y con la ayuda de los Routers podemos con poquitas líneas tener todas las herramientas de un CRUD e incluso cambiando solamente el modelo hacer que todo sea de lectura y se configure automáticamente si mostrando cosas que no modifiquen nada (como el get)

## Postman

Hoy hablaremos de "Postman" la app que ya había usado antes para poder mandar las peticiones, ya que ahorita todo lo hemos estado haciendo tanto desde la pagina de administración como desde los mismos links gracias al poder de Django Rest Framework, lo descargamos (por si aun no lo tienen) https://www.postman.com creamos una cuenta y listo, todo free

Desde este programa podemos acceder a nuestra API de la misma forma que en el navegador, solo copiamos nuestro link http://127.0.0.1:8000/watch/stream/ y nos da varias opciones sobre los diferentes request que podemos hacer
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021115935.png)
le damos en GET y luego en Send
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021115951.png)

Los puse asi uno alado del otro para que vean que es lo mismito, algo que no savia es que si le das donde dice Preview, te aparece la respuesta que se manda por ejemplo al Back End u otros usuarios que usen el API desde dispositivos moviles o alomejor algun equipo de escritorio.
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021120111.png)

Mas en el futuro usaremos esto de la autenticación 😨°°°(**war noises**) 

Ok vamos a nuestro archivo "serielizers.py" y quitemos el ReadOnly que habíamos puesto en nuestro capitulo anterior, para poder acceder a las demás opciones del CRUD en nuestro PostMan

```Python
...
class StreamPlataformVS(viewsets.ModelViewSet):

    queryset = StreamPlataform.objects.all()
    serializer_class = StreamPlataformSerialize
...
```

Hecho esto ahora haremos pruebas para CRUD pero ahora desde PostMan, tratemos de acceder a nuestra plataforma de streaming numero 3 de neustra appi http://127.0.0.1:8000/watch/stream/3 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021120934.png)

Bien, si nos vamos a Headers, nos muestra efectivamente que tenemos las siguientes opciones

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021121148.png)

si le quitamos el 3 y dejamos todas las plataformas alli no nos sale el delete

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021121424.png)

Ahora otra cosa que nos aparece alli es el status
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021121442.png)

intentemos acceder a otro id que sepamos que no exista 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021121522.png)

Nos marca 404 Not Found, ahora intentemos un put request con el siguiente Json al http://127.0.0.1:8000/watch/stream/3/

```Json
{

    "name": "None",

    "about": "None - updated!",

    "website": "http://www.none.com"

}
```

le cambiamos la opcion de GET a PUT, luego en donde dice Body, seleccionamos ray y por ultimo cambiamos esto a JSON

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021132529.png)

Le damos en Send y nos lo actualiza, incluso si vamos a nuestra base de datos (nuestro html pues) vemos que si lo actualizo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021132741.png)

Bien ahora intentemos hacer un POST request, ponemos http://127.0.0.1:8000/watch/stream/ y le ponemos este Json
```Json
{

    "name": "None 2",

    "about": "None - updated!",

    "website": "http://www.none.com"

}
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021134310.png)

Le damos en send y ya nos creo otra plataforma, que nos servirá para probar delete también

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021134755.png)

Entonces pongamos la direccion http://127.0.0.1:8000/watch/stream/8/ (importante, poner el ultimo / porque es la direccion correcta para elementos individuales,) y borramos el contenido del raw, de echo para asegurarnos primero le damos un GET, ya que vemos que si es el elemento que queremos borrar le damos en DELETE

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021135201.png)

