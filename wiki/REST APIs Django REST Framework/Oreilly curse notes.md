
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


## User Model

Ya va siendo tiempo que empecemos a enfocarnos hacia nuestro proyecto final, y por mientras lo que haremos sera añadir la funcionalidad de que las reviews sean por usuario, esto se lograra añadiendo nuevos models pero por lo mientras, borraremos todos los reviews dentro del sitio de administración para no tener complicaciones a la hora de crear nuestras migraciones, entonces vamos a "models.py" y creemos en nuestra clase Review el campo "user" ( #Duda mas bien aclaración para mi, se pone en la class Review porque sera un campo que se llenara junto con las reviews, a la hora de crear una, obtendremos el nombre de usuario y se lo asignaremos a la review, no es como si a cada usuario le asignaremos las reviews que hace si no al contrario, a cada reviews le pondremos una marquita pa saber que usuario fue)

entonces creamos nuestro campo al cual llamaremos "review_user" luego le asignamos un modelo el cual sera un "ForeignKey( )" este tomara el usuario como forma de entrada, importemos el usuario , entonces eso se lo pasamos al ForeignKey y le pasamos que si se borra sea en cascada (ya hablamos de esto)

```Python
...
from django.contrib.auth.models import User
...
class Review(models.Model):

    review_user = models.ForeignKey(User, on_delete=models.CASCADE)
...
```

y antes de hacer las migraciones e incluso de guardar los cambios vamos a nuestra sección de administración y borramos todas las entradas respecto a reviews
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021181015.png)

Y antes de hacer las migraciones, vamos a nuestro "serializer.py" e incluyamos este campo respecto a nuestras "review_user" 

```Python
...
class ReviewSerializer(serializers.ModelSerializer):

	review_user = serializers.StringRelatedField(read_only=True)
...
```

Ahora vamos a hacer las migraciones

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021182134.png)

Listo, corremos el servidor y revisamos que ta nos deja seleccionar el usuario, asi que creemos una nueva review
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021182541.png)

Ahora si accedemos a http://127.0.0.1:8000/watch/stream/ veermos que ya nos aparece nuestro review y el usuario que lo creo 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021182719.png)

Pero, si intentamos hacer otro a el mismo watchlist, me va a dejar, ya que no hay nad que nos impida hacer mas que un review

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021182822.png)

Incluso tambien podemos entrar y editar cualquier review, incluso si no fuera nuestra, solo entrando al path http://127.0.0.1:8000/watch/stream/review/1

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021183008.png)


Entonces para parar esto vamos a "views.py" en nuestra class "ReviewCreate" y dentro de nuestra función "perform_create" crearemos nuestra verificación, iniciamos una variable llamada "review_user y la usaremos para añadirle la información del usuario actual, ahora solo queda checar su el usuario actual es quien hiso el review a editar, así qu7e creamos la variable "review_queryset" y le asignamos los objetos de "Review" estos los vamos a filtrar por watchlist y por review_user.

Luego checaremos si tenemos un resultado (osease si ya tenemos que el usuario hizo una review) entonces le mandaremos una validation error

Y por ultimo a la hora de salvarlo, salvaremos también el "review_user"

```Python
...
class ReviewCreate(generics.CreateAPIView):
    serializer_class = ReviewSerializer

    def perform_create(self, serializer):

        pk = self.kwargs.get('pk')
        watchlist = WatchList.objects.get(pk=pk)
  

        review_user = self.request.user
        review_queryset = Review.objects.filter(watchlist=watchlist, review_user=review_user)

        if review_queryset.exists():
            raise ValidationError("You have already reviewed this movie!")

        serializer.save(watchList=watchlist, review_user=review_user)
...
```

Antes de salvarlo hay que borrar las anteriores "reviews" pa no generar conflictos, vamos y seleccionamos una película http://127.0.0.1:8000/watch/stream/1/review-create y le pasamos este Json de Review 

```Json
{
    "rating": 5,
    "description": "Description 1",
    "active": false
}
```

Perfecto, nos dejo crearlo sin problemas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021190856.png)

Ahora intentemos páraselo otra ves.. nos da un error, eso porque nos falta pasar el querry set donde creamos nuestra clase ( #Duda la verdad no entendí el porque faltaba esto) 

```Python
...
class ReviewCreate(generics.CreateAPIView):

    serializer_class = ReviewSerializer

    def get_queryset(self):
        return Review.objects.all()

    def perform_create(self, serializer):
        pk = self.kwargs.get('pk')
        watchlist = WatchList.objects.get(pk=pk)

        review_user = self.request.user
        review_queryset = Review.objects.filter(watchList=watchlist, review_user=review_user)


        if review_queryset.exists():
            raise ValidationError("You have already reviewed this movie!")

        serializer.save(watchList=watchlist, review_user=review_user)
...
```

y ahora si
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221021191318.png)

## Temporary Login and Logout

Gracias al poder de DjangoREST framework podemos obtener una solución temporal respecto a los usuarios, si vamos a nuestra sección de administración podemos ver esta sección de usuarios, donde ahorita nuestro super usuario "keikusanagi" tiene todos los permisos

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024113953.png)

El mas importante es el "Superuser status" que nos permite modificar y ver TODO de la pagina, después esta el de "Staff status" que ese nos permite entrar al sitio de administración pero no podremos cambiar nada y por ultimo tenemos "Active" que pues bueno no hay mucha ciencia, esta activa la cuenta o no, como cuando uno desactiva temporalmente su face pero no lo elimina, así que para propósitos de practica creemos otro usuario el cual sera normal

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024114257.png)

Listo, de echo si hacemos LOG OUT e intentamos entrar al sitio de administración con este nuevo usuario vean lo que pasa

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024114402.png)

ya que no tenemos los permisos, regresemos a nuestro super usuario para ver que permisos tiene

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024114459.png)

en efecto, solo tiene lo que es "Active" seleccionado, pero ahora como podremos usarlo para usar nuestra api, pues entonces vamos a nuestro código y en nuestro archivo "watchmate/urls.py" (ojo no es de la app si no de nuestro programa principal) y agregamos este path

```Python
from django.contrib import admin
from django.urls import path, include

urlpatterns = [

    path('admin/', admin.site.urls),
    path('watch/', include('watchlist_app.api.urls')),
	#Temporary Login
    path('api-auth', include('rest_framework.urls')),
]
```

Y listo, ahora si vamos a cualquier parte de nuestra api veremos a la derecha que ya aparece nuestro nombre de usuario y un cuadro de dialogo para hacer Log out y Login, intentemos nuevamente entrar pero con nuestro usuario de pruebas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024115018.png)

Y listo, ya nos deja entrar a nuestra api desde nuestro usuario de pruebas, esto lo hacemos con la finalidad de poder hacer reviews de diferentes usuarios y como dijimos hace como 2 capitulos que solo el autor de la reseña pueda modificar la suya pero no la de los demás

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024115140.png)


## Introduction to Permissions

en esta lección, desglosaremos un poco mas los permisos que vimos en la anterior capitulo, donde ya pudimos crear un usuario de pruebas y ahora podemos hacer de todo lo permitido en la api con el, pero no en el area de administración, pero, queremos lograr que solo si este usuario creo el review, solo el 
modificarlo o eliminarlo, de igual forma que solo usuarios registrados no importando su nivel puedan ver los reviews sin importar su nivel de SATFF (llamémoslo asi aunque ya no veremos mucho en este capitulo), en este capitulo hablaremos mas sobre Permissions (permisos pues).

Podemos ir a la documentacion para obtener informacion mas detallada https://www.django-rest-framework.org/api-guide/permissions/
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024144757.png)

Tenemos dos formas de agregar permisos, unos son poniendo directamente en los settings, y estos aplican en todas y cada una de las class que tengamos y por otro lado tenemos los "[Object level permissions](https://www.django-rest-framework.org/api-guide/permissions/#object-level-permissions)"  estos nos permiten poner una restriccion a una class en particular (esto es lo que se adecua mas a nostoros)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024150414.png)

Intentaremos primero poner un "global permission class" 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024150537.png)

Tan fácil como irnos a nuestro archivo de "settings.py" y pegarlo hasta abajo

```Python
...
REST_FRAMEWORK = {

    'DEFAULT_PERMISSION_CLASSES': [

        'rest_framework.permissions.IsAuthenticated',

    ]

}
...
```

Ahora si recargamos nuestra pagina sin estar identificados

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024150810.png)


Si nos logeamos nos dará acceso ahora si a todo, esto se acerca medianamente a lo que queremos, pero nos serviría mas el poder custamizarlo un poco mas, para poderle poner que solo un admin o quien lo creo pueda modificarlo, eso lo podremos lograr solo con el "Object level permissions", ais que comentemos el permiso que le acabamos de dar.

Todo lo que tenemos que hacer es definir en la class que queremos una variable llamada "permission_classes" y pasarle el tipo de permiso que queremos (a e importarlo arriba)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024151413.png)

ojo, si usamos permisos basados en funciones, se hace casi lo mismo pero con decoradores

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024151533.png)

Entonces vamos a "views.py" y en nuestra class ReviewList, la añadiremos

```Python
...
# Permissions
from rest_framework.permissions import IsAuthenticated
...
class ReviewList(generics.ListAPIView):
    # queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    
    # Permissions
    permission_classes = [IsAuthenticated]
...
```

Esto nos dará lo mismo que la ves anterior, solo un usuario identificado (no importando su nivel de staff), vamos a http://127.0.0.1:8000/watch/stream/1/review (ojo vamos aquí porque estamos modificando esa class de ese path, si nos vamos a cualquier otra al solo estar afectando esta clase nos mostrara todas las demás con normalidad y con todas las opciones que le hemos puesto) aquí estamos accediendo a la lista completa de reviews del item 1

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024152513.png)

Si hacemos Logout no tendremos permiso para verlo 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024172419.png)

Ok pero que pasa si queremos acceder a un review en especifico, poniendo el review 3 http://127.0.0.1:8000/watch/stream/review/3

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024172614.png)

Nos da completo acceso ya que en nuestra class, solo le dimos la restriccion a la "ReviewList" y no a la "ReviewDetail"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024172727.png)

Entonces, pongámosle lo mismo, solo le ponemos el 
```Python
permission_classes = [IsAuthenticated]
```

Perfecto ya no nos da acceso a menos que hagamos Login
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024172829.png)

Y asi podemos ponerle varios permisos que ya nos provee DjangoREST Framework, por ejemplo cambiemos este por `IsAuthenticatedOrReadOnly` acuerdense de importarle en la parte de arriba

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024173143.png)

Lo pondremos en la class ReviewDetail, para que solo el usuario autenticado pueda editarlo, pero si no lo esta solo pueda leerlo
```Python
...
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
...
class ReviewDetail(generics.RetrieveUpdateDestroyAPIView):

    queryset = Review.objects.all()
    serializer_class = ReviewSerializer

    permission_classes = [IsAuthenticatedOrReadOnly]
...
```

Vean, podemos verlo sin estar autenticados pero no podemos mas que verlo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024173452.png)

Ahora si hacemos Login con nuestra cuenta de prueba

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024173605.png)

nos da total acceso, pero... si vemos, este review esta hecho por mi super user "keikusanagi" y aun así nos deja modificarlo o incluso borrarlo, aun así estamos mas cerca de lo que queremos, para esto tenemos que usar "Custom permissions" pero eso lo veremos en la siguiente lección

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221024173825.png)




## Custom Permissions

Bueno después de una breve agonía volvemos, nos quedamos con que queríamos ponerle permisos personalizados, y asi como lo hicimos en el anterior capitulo, en este tenemos que importarlos, pero de donde, pues crearemos nuestro propio archivo de permisos, en la carpeta /api/permissions y allí importamos nuestros permisos de "rest_frameework"
``from rest_framework import permission`` y aqui nos ayudaremos del ejemplo en la documentación, nuestro objetivo es si es "admin" podrá editar lo que sea, de modo contrario solo sera de lectura, Para esto creemos una ``class=AdminOrReadOnly(permissions.IsAdminUser)`` dentro importamos nuestros permisos y usaremos el que viene en la documentacion que es "IsAdminUser", ahora para implementarlo nos vienen estas dos bases
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221031165422.png)

El que usaremos sera este  ``.has_object_permission(self, request, view, obj)`` ya que es el que nos permite interactuar con un objeto en especifico, este se lo daremos al propietario del review, mientras que el otro de ``.has_permission(self, request, view)`` no tiene el permiso para modificar este objeto, ahora, cualquiera de esatas dos bases nos regresara un boleano, tanto True como False, como quien dice "tiene permiso? cierto/falso" si lo traducimos seria

```Python
from rest_framework import permissions

  
class AdminOrReadOnly(permissions.IsAdminUser):

    def has_permission(self, request, view):

        admin_permission = bool(request.user and request.user.is_staff)
        
        return request.method == "GET" or admin_permission
```

Esto nos dará como resultado un doble condicional, en primera si esta logeado y luego checa si ese usuario es Admin, eso asigna a "admin_permission" el valor True y ya lo que queda es retornarlo y ahora si usarlo en nuestro archivo "views.py" no sin antes importarlo y le añadimos este permiso personalizado a nuestra ReviewDetail class

```Python
...
# Permissions
from watchlist_app.api.permissions import AdminOrReadOnly
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
...

class ReviewDetail(generics.RetrieveUpdateDestroyAPIView):

    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [AdminOrReadOnly]
...
```

Vamos a http://127.0.0.1:8000/watch/stream/review/3 y si no estamos identificados nos saldra esto solamente
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221031172453.png)

si iniciamos sesión como test (que no es admin)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221031172909.png)

y si nos metemos como admin

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221031174627.png)

Perfecto, ya se parece mas a lo que queremos, ahora solo nos falta que lo pueda modificar solo si es el autor del review, asi que creemos una nueva class en nuestros permisos personalizados, asi que creemos nuestra nueva clase, se llamara "ReviewUserOrReadOnly", le pasaremos el BasePermission, leugo creamos nuestra funcion y le damos su if, pa que cheque que si el object.user es igual a la persona que hizo el review

```Python
...
  

class ReviewUserOrReadOnly(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):

        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            return obj.review_user == request.user
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221031180850.png)

Ok, si iniciamos sesión con otro usuario no nos dejara modificarlo, solo nos dará el GET, si no iniciamos sesión igual

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221031180934.png)

pero si iniciamos sesión con el usuario que hicimos el Review, nos dará las opciones completas pa modificarlo y hasta borrarlo
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221031181042.png)

Podemos hacer algo similar en la parte superior. Entonces,podemos agregar lo mismo agregar directamente este tipo de permiso en AdminOrReadOnly. Entonces, si la request tiene permiso, es SAFE_METHOD. Ahora request.method es GET, si este es el caso, SAFE_METHODS significa GET. Entonces, si el método de solicitud es GET, entonces podemos devolver directamente verdadero, eso es todo. Y de lo contrario, vamos a probar todo lo demás, para que podamos agregar nuestra propia condición. Así que aquí lo que voy a hacer es hacer un return, lo cual es cierto porque si estamos accediendo a la solicitud de request pueden enviar esta solicitud (osea si estan mandando un request y aparte no tienen permisos de administrador pos namas le damos los SAFE_METHODS osea, puro get y nada que peuda modificar la base de datos). Pero si están tratando de acceder a la solicitud POST o cualquier otro tipo de solicitudes,  voy a verificar esta condición else ``bool(request.user and request.user.is_staff)`` , si esto es administrador o no, y listo eso es todo.

En resumen si la solicitud es GET, entonces aceptaremos su solicitud. Si la solicitud no es GET, estamos probando si el usuario es administrador o no.


Al final nuestras dos clases de permisos personalizadas "Custom Permissions" quedaría así

```Python
from rest_framework import permissions


class AdminOrReadOnly(permissions.IsAdminUser):

    def has_permission(self, request, view):


        if request.method in permissions.SAFE_METHODS:
            return True

        else:
            return bool(request.user and request.user.is_staff)


class ReviewUserOrReadOnly(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):

        if request.method in permissions.SAFE_METHODS:
            return True

        else:
            return obj.review_user == request.user
``` 


## Custom Calculation

Hola, en este capitulo veremos el como hacer calculos con los datos que tenemos de la API, mas especificamente con los "reviews", osease el "rating" de la pelicula, algo asi como lo que hacen en IMDb

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101130144.png)

donde a base de los reviews de los usuarios se va haciendo el rating de la serie, pelicula o podcast en cuestion, es mas si damos click en el se despligan los porcentajes y vemos algo interesante en la barra de titulo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101130402.png)

esta esta compuesta como el api que estamos creando, https://www.imdb.com/title/tt5923962/ratings/?ref_=tt_ov_rt primero va pues la pagina imbd, luego /title/ y luego viene el Id, este id se refiere a esta pelicula que en nuestro casos eria una watchlist y luego ratings, asi que para que se parezca mas, removeremos del path el "stream"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101130608.png])
quedándonos asi

```Python
from django.db import router
from django.urls import path, include
from watchlist_app.api.views import ReviewList, ReviewDetail, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV, ReviewCreate, StreamPlataformVS

from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register('stream', StreamPlataformVS, basename='streamplataform')

urlpatterns = [

    path('list/', WatchListAV.as_view(), name='movie-list'),

    path('<int:pk>', WatchDetailAV.as_view(), name='movie-detail'),

    path('', include(router.urls)),

    path('<int:pk>/review-create', ReviewCreate.as_view(), name='review-create'),
    path('<int:pk>/reviews', ReviewList.as_view(), name='review-list'),
    path('review/<int:pk>', ReviewDetail.as_view(), name='review-detail'),
]
```

Listo ya tenemos nuestros path pero aun no tenemos nada que nos de el calculo respecto a los ratings, asi que tendremos que crear nuevos campos en nuestros modelos , asi que vamos a "models.py" y en nuestra class WatchList, agreguemos el numero total de reviews (esto seria para cada película) y el otro sera el "avg_rating" entonces cada que escribanos una review nueva para cada película o watchlist estos dos números se modificaran, antes que todo esto, tenemos que ir a nuestro panel de administración y borrar todas las reviews que tengamos (esto nada mas pa no tener mayor complicaciones)

Entonces agregamos nuestro campo ``avg_rating = models.FloatField(default=0)`` al cual lo ponemos como un campo con punto flotante ya que puede ser 4.5 o asi y le ponemos que el valor por default sea cero(ojo esto se lo estamos agregando a cada watchlist, por ejemplo al que ya tenemos de python, aparte de los campos de titulo, storyline, plataform, le estamos agregando este campo a el, por ejemplo lo que hicimos con review que es otra clase es que relacionamos estos con los watchlist ok)

Ahora agregaremos nuesto ``number_ratging = models.IntegerField(default=0)`` este sera IntegerField ya que se contara de uno en uno dependiendo cuantas veces le de review a nuestra watchlist y el valor de deafault sera cero y listo, no tenemos que hacer nada con el serializador ya que al llamar watchlist estamos mandando a llamar todos los campos
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101132004.png)

entonces, nuestra class WatchList quedaría asi
```Python
...
class WatchList(models.Model):

    title = models.CharField(max_length=50)
    storyline = models.CharField(max_length=200)
    
    plataform = models.ForeignKey(StreamPlataform, on_delete=models.CASCADE, related_name="watchlist")
    active= models.BooleanField(default=True)

    # Custom Calculation
    avg_rating = models.FloatField(default=0)
    number_ratging = models.IntegerField(default=0)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):

        return self.title
...
```

Muy bien, ahora hagamos las migraciones

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101132345.png)
Listo, ahora vamos a "views.py" que es donde tenemos nuestros cálculos funciones y demás y justo donde hacemos la validación de si ya tenemos un review o no allí es donde pondremos después el calculo, para estar seguros que no estamos haciendo este calculo de mas, entonces lo primero es hacer una comprobación para ver si el numero de reviews es 0, eso significa que podemos poner directamente el rating, de otro modo tenemos que promediarlo, entonces ponemos el if y seleccionamos este queryset que en este caso seria watchlist y su numero de ratings si esto es exactamente igual a 0 entonces directamente le asignamos el percentage del rating

```Python
...
class ReviewCreate(generics.CreateAPIView):

    serializer_class = ReviewSerializer

    def get_queryset(self):
        return Review.objects.all()

    def perform_create(self, serializer):
        pk = self.kwargs.get('pk')
        watchlist = WatchList.objects.get(pk=pk)

        review_user = self.request.user
        review_queryset = Review.objects.filter(watchList=watchlist, review_user=review_user)

        if review_queryset.exists():
            raise ValidationError("You have already reviewed this movie!")

        # Custom Calculation
        if watchlist.number_ratging == 0:

            watchlist.avg_rating = serializer.validated_data['rating']
        else:
...
```

Ahora si pasamos de esto (ósea que ya tengamos un rating mas) ahora si haremos el calculo, entonces lo que haremos después del else sera recalcular este campo ``watchlist.avg_rating`` y lo combinamos poniendo el viejo rating y luego el nuevo todo entre 2, suponiendo que nuestro viejo rating era 4.5 y el nuevo es de 5 seria 

```Python

# watchlist.avg_rating = ( 4.5 + 5 ) / 2
# watchlist.avg_rating = 4.75
	else:
		watchlist.avg_rating = (watchlist.avg_rating + serializer.validated_data['rating'])/2
```

Ya lo unico que faltaria seria incrementar el numero de ratings en 1 y luego salvar nuestra watchlist

```Python
...
	watchlist.number_ratging = watchlist.number_ratging + 1
	watchlist.save()
...
```

Listo luce bien, ahora si vamos a nuestro panel de administración veremos que ya tenemos nuestro campo de AVG rating

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101134740.png)

Entonces creemos un review, vallamos a abrir nuestra api http://127.0.0.1:8000/watch/2/review-create (recuerden que le cambiamos el path) y agreguemos una 
```Json
{
    "rating": 5,
    "description": "Good Movie!",
    "active": true
}
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101140154.png)

perfecto, vemos que el rating es 5, si vamos a  http://127.0.0.1:8000/watch/2 vemos que el numero de ratings es 1 y el avg_rating es 5.0

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101140243.png)

Ahora, si queremos crear otro review, no nos va a dejar por la funcionalidad que pusimos, de dejar solo hacer un review por usuario, entonces nos logeamos con el de test 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101140737.png)


Ahora si vemos que el avg_rating cambio ahora a 4.5, ya namas por ultimo añadimos una / final a los paths para que no nos de el error si nos falta, al final de ``'<int:pk>``
```Python
path('<int:pk>/', WatchDetailAV.as_view(), name='movie-detail'),
```


## Introduction to Authentications

Bueno, empezamos con lo chido, las autenticaciones, pero antes de pasar a verlas debemos entender la diferencia entre permiso y autenticación, podemos ir a la documentacion https://www.django-rest-framework.org/api-guide/authentication/ y hay una nota muy importante

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101151159.png)

que traduciendo nos dice que tengamos en cuenta que una autenticación por si sola, no permitirá ni rechazara una solicitud entrante, simplemente identifica quien realizo la solicitud... Es como cuando le dijimos a nuestra api que checara si quien hace la solicitud es administrador o no y luego le otorgamos permisos o no para modificar o borrar su review, cada que manejemos una restricción esto sera a través de una "permission class"

Ahora hablemos sobre autenticación, esta nos ayuda a checar cada petición entrante "incoming request" y checa que cada request provenga de una credencial identificada (ya se apersona usuario etc que sea valido pues) como quien dice es cuando uno quiere hacer log in, esto checa si la request (que es el inicio de sesión) es valido, si lo es entonces es un usuario valido y esta autenticado, si no pues no.

hay muchas maneras de usar autenticaciones (ni me lo recuerden) y ahorita usaremos lo que es la "BasicAuthentication" que en la misma documentación hablan que sea solo para hacer pruebas y la famosa JWT "JSON Web Token"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101152536.png)


## Basic Authentication

Bueno ahora solo para propósitos de test haremos lo que es la autenticación básica, para empezar debemos importar los settings que vienen en la documentación https://www.django-rest-framework.org/api-guide/authentication/#setting-the-authentication-scheme ya que recordemos que estamos usando Django rest framework y asi funciona este, luego vamos y las pegamos en nuestro archivo "settings.py"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101163617.png)

```Python
...
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# REST_FRAMEWORK = {
#     'DEFAULT_PERMISSION_CLASSES': [
#         'rest_framework.permissions.IsAuthenticated',
#     ]
# }

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ]
}

```

solo quitamos el sessionAuthentication que no usaremos ahorita (ojo, si usáramos también el de arriba lo pondríamos poner con una coma, sin repetir REST_FRAMEWORK si no nos dará error)

Listo, ya hecho esto podemos usar la BasicAuthentication en todo nuestro proyecto, ahora ya que esta aplicado a todo nuestro proyecto, vamos a nuestro archivo "views.py" y en neustra class ReviewList modificamos el permission_classes

```Python
...
class ReviewList(generics.ListAPIView):
    # queryset = Review.objects.all()
    serializer_class = ReviewSerializer
	
	# Basic Authentication
    permission_classes = [IsAuthenticated]
...
```

Ojo esto lo sacamos de la documentación

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101165912.png)


ok vamos a probarlo, vamos a obtener nuestra review list a través del link http://127.0.0.1:8000/watch/2/reviews ... pero sera por postman

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101171932.png)

Perfecto, nos regresa ese bonito mensaje de error, ya que no estamos identificados como usuarios pero, como podemos pasarle los datos por postman ya que por la pagina podíamos darle arriba a la derecha donde decía login, pues por los headers, alli le pasaremos ell usuario y contraseña en forma codificada y para esto nos ayudaremos de la pagina, para pasar todo en base 64 https://www.base64encode.org/ 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101173104.png)

esto lo pasamos en el Postman y 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101173159.png)

Perfecto, ya tenemos nuestra Basic Authentication, ahora solo para seguir usando postman, vamos a nuestro archivo principal "watchmate/urls.py" y comentemos el ultimo path que fue el que pusimos para habilitar el login, asi de esta forma podremos seguir usando postman para mandar las autorizaciones

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221101173357.png)


## Token Authentication - Part 1

Empecemos con lo bueno (creo es la tercera ves que lo menciono en este curso), por alguna razón se me complica mucho el asociar las autenticaciones por token, pero en este capitulo lo explica bien con un ejemplo de un estacionamiento.

Para acceder a algún sitio web, necesitamos un username y un password, esto sera algo asi como un Log que contendrá el id o username y el password ``Log(id, password)`` como lo que hicimos en postman que le pasamos en una sola linea estos dos codificados, ok esto lo estamos mandando desde algún lugar a nuestro "endpoint", la cual nosotros definimos en nuestra api mediante las url, al momento de mandarlo al Endpoint y el verificar que si tienes las credenciales correctas el nos regresara un TOKEN, es como en un estacionamiento, al momento de entrar te dan un boleto=token, y a la hora de regresar, enseñas el TOKEN y ya puedes tener acceso a entrar y tomar tu carro

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102145155.png)

si queremos visitar nuestra pagina de cuenta "account page" necesitamos pasar el token dentro del request para que nos puedan regresar el contenido de esa pagina, de igual forma si queremos hacer un review igual debemos pasar el token dentro del request para que nos de chance de acceder o enviar cosas, cada que en el programa de nuestra api le decimos que si "IsAuthenticated" prácticamente lo que estamos checando es si la request lleva este token o no


![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102150732.png)

Entonces, como usaremos esto en nuestra API, pues cada que un usuario se registra, le crearemos un token, este se quedara guardado en la base de datos, este token se le regresara al usuario para que pueda tener acceso a todos los datos, una ves que el usuario haga logout, este token se destruirá y no se volverá a crear uno nuevo hasta que el usuario haga login otra ves

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102151200.png)


Ahora, para implementar esto en nuestra api, tenemos que configurar unas cosas en nuestro archivo "settings.py" y allí según la documentación tenemos que agregar lo siguiente

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102151532.png)

Entonces vamos y de una ves agregamos las que están comentadas de la forma que debería ser (solo un REST_FRAMEWORK y lo demás settings separados por coma)

```Python
...
REST_FRAMEWORK = {
    #     'DEFAULT_PERMISSION_CLASSES': [
    #     'rest_framework.permissions.IsAuthenticated',
    # ],
    # 'DEFAULT_AUTHENTICATION_CLASSES': [
    #     'rest_framework.authentication.BasicAuthentication',
    # ],

    'DEFAULT_AUTHENTICATION_CLASSES': [

        'rest_framework.authentication.TokenAuthentication',

    ]
}
```

Ya poniendo los settings ahora debemos ir a las INSTALLED_APPS y declararla

```Python
...
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # _app's creadas
    'watchlist_app',
    'rest_framework',

    'rest_framework.authtoken',
]
...
```

Ahora, la misma documentación nos pide que hagamos un migrate, esto nos creara los campos que necesitamos para los tokens

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102153941.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102154136.png)

Si entramos al panel de administración veremos que ya tenemos la sección de agregar tokens
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102154329.png)

Agreguemos los tokens manualmente a los dos usuarios que tenemos

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102155037.png)


## Token Authentication - Part 2

Ahora vamos con la parte 2, ya creamos nuestros tokens manualmente para nuestros usuarios ya que el hacerlo de manera normal tendriamos que borrar los usuarios, crear un nuevo super usuario y asi, por eso la hicimos manual, entonces ahorita vamos a hacerlo solo por fines practicos y pa aprender manualmente, asi que notemos bien nuestros tokens y a quien le pertenecen

```
[cf9fd2c4bd24856eac06cd53c8ad31833807dcb0]
keikusanagi

[d9c377b6859f14653187007ec350392f35ad6dba]
test
```

Y vamos a nuestro postman y utilicemos nuestro ultimo request, el de 
http://127.0.0.1:8000/watch/2/reviews
solo que cambiaremos nuestro valor de autorización por Token seguido de cualquiera de los dos tokens que tenemos

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102175217.png)

Al darle sent sin problemas nos mandara la respuesta ya que en nuestras vistas solo pusimos que no tenia ni que estar logeado alguien para poder hacer un request tipo GET, es mas quitémosle el token 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102175236.png)

Esto es como si no estuviéremos autentificados, pero ahora que pasa si hacemos un request para ver un review, normalmente nos dejaría ya que solo estamos haciendo un GET 
http://127.0.0.1:8000/watch/review/5

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102175637.png)

Al ser un GET no hay bronca, nos deja verlo sin problemas, pero si queremos modificarlo con un PUT a nuestro review http://127.0.0.1:8000/watch/review/5 ya que en este lo tenemos en 4 de rating
```Json
{
    "rating": 5,
    "description": "Good Movie!",
    "active": true
}
```

Lo pondremos como PUT, luego en el Body ponemos este Json como raw y tipo JSON

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102180023.png)

Nos regresa un

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102180045.png)

ya que no le estamos pasando el token para demostrar que estamos autorizados para modificarlo, ahora este review es de nuestro usuario de test
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102180131.png)

asi que provemos, dandole el token de nuestro admin 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102180210.png)

nos muestra presisamente que no tenemos permiso para modificartlo, ahora pasemosle el token dentro de la solicitud de neustro usuario de prueba

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102180334.png)

Ahora si nos dejo modificarlo

Ahora la pregunta es como podemos obtener este token, el plan es crear un link por el cual se le manden request por medio de postman por ejemplo por el cual le mandemos nuestro usuario y password y nos regrese promedió de un response un token (claro si el usuario y password están acreditados) este token lo almacenaremos como el que hicimos ahorita y este token sera pasado en cada petición que hagamos, este sera el primer caso
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102191453.png)


El segundo caso sera importante ya que tratara sobre el registro de usuarios, ya saben obtener su usuario, password, confirmar su password y ya dando toda esta información le regresaremos un token

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102191652.png)



Y el tercer caso sera cuando el usuario necesite borrar su token y o pueda regenerarlo como en el caso que cada que hagamos Logout se destruya el token y cuando volvamos a hacer login se regenere

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221102191918.png)

## Token Authentication - Part 3 (Login)

Muy bien, ahora vamos a crear una nueva app que llevemos todo lo que tenga que ver con cuentas, ya sea registrarse, hacer login todo eso. REST framework nos da bastantes herramientas para crearla, yo creí que seria un poco mas complicado pero bueno, empecemos creando una nueva app

``python manage.py startapp user_app ``

y dentro de esta crearemos una carpeta llamada "api" y luego nuestros 3 archivos "urls.py", "serializers.py" y "views.py"

lo primero que agregaremos sera nuestras URL's ya que es nuestro objetivo de crear esta nueva app, el crear una url para hacer login y obtener nuestro token.

Vamos a nuestro archivo "watchamte/urls.py" y agregamos nuestro path de paths jajajaa osease que tome encuenta las direcciones que usaremos en nuestra nueva app y le damos la direccion que sera "user_app.api.urls"

```Python
from django.contrib import admin
from django.urls import path, include
  

urlpatterns = [
    path('admin/', admin.site.urls),
    path('watch/', include('watchlist_app.api.urls')),

	# user_app path
    path('account/',include('user_app.api.urls')),

    # path('api-auth', include('rest_framework.urls')),
]
```

Tambien vamos a nuestro archivo settings y agregamos nuestra nueva app

```Python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # _app's creadas
    'watchlist_app',
    'rest_framework',
    'rest_framework.authtoken',
    'user_app',
]
```

Ya teniendo esto ahora si vamos a nuestro archivo "user_app/api/urls.py" y creemos el path que necesitaremos para que nos regrese el token, empezamos importando ``from rest_framework.authtoken.views import obtain_auth_token`` que es lo que nos regresara el token dependiendo del nombre de usuario y password que le mandemos dentro de nuestras peticiones

```Python
from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token

urlspatterns = [
    path('login/', obtain_auth_token, name='login')
]
```

Listo, ahora vamos a nuestro postman a pedirle nuestro token

Configuramos al direccion como http://127.0.0.1:8000/account/login/ que es la que acabamos de crear, leugo le pasaremos dentro del Body un "form-data" y le pondremos dos KEY, una sera el username y la otra el password y lo mandamos todo como un POST
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103124952.png)

Perfecto, con esto nos esta regresando un token como si hubiéramos echo log in, le mandamos por la petición nuestro usuario y password y nos regresa el token que si vemos en el panel de administration es el mismo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103125153.png)

por ejemplo si le mandamos el password mal me va a decir 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103125231.png)

Pero a ver con este token ya nos permitira por ejemplo crear reviews pasandoselo dentro de nuestras peticiones, ais que hagamos una prueba, vallamos a nuestro link para crear
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103125432.png)

http://127.0.0.1:8000/watch/3/review-create

Pasemosle el siguiente Json
```Json
{

    "rating": 5,

    "description": "Great Movie",

    "active": false

}
```

Configurándolo como un post, recordando en el Header poner la Authorization y nuestro token

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103125927.png)


## Token Authentication - Part 4 (Registration)

Bueno ya teniendo nuestro link para que nos regrese los tokens, debemos hacer nuestro registro, para esto usaremos los mismos campos que ya tenemos creados de nuestro modelos anteriormente así que no debemos sobre escribirlos (como quien dice ya REST framework otra ves nos da ya las herramientas que necesitamos respecto a usuarios, pero si queremos poner algunos campos de mas podemos crearlos dentro de nuestro archivo models.py)
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103142419.png)


Entonces vallamos a nuestro archivo "user_app/api/serielizers.py" y empecemos a crear nuestro serializador

_¿Qué es un serializador? Los serializadores **son unos de los componentes más poderosos que tiene Django Rest Framework**. Estos permiten que estructuras complejas y modelos de nuestro proyecto en Django sean convertidos a estructuras nativas de Python y puedan ser convertidas fácilmente en JSON o XML ._

Aqui importaremos nuestros usuarios del modelo que ya tiene Django como ya lo habíamos mencionado arriba, luego  importaremos nuestro serializadores de Django rest framework

Después de esto crearemos nuestra class y le llamaremos "RegistrationSerializer" luego definimos nuestra class Meta, usaremos model = User y en los campos definiremos un campo extra que corresponderá al password2 para poder confirmarlo, ya que Django de default solo nos da username, email y password, entonces antes de definir el class Meta definimos nuestro campo que sera password2, asignándole que sea un CharFiueld y que sea solo write_only (esto significa que solo podrá escribirse y compararlo pues nosotros dentro del programa pero nadie mas lo podrá leer) y le añadimos un style que sea password pa que salgan los asteriscos esos al ponerlo.

Casi por ultimo añadiremos argumentos extra, y le pasaremos que nuestro password (el normal) sera igual solo escritura.

Ahora si por ultimo crearemos un metodo para validar nuestros datos (si no nos da un error) así que creamos y asignamos nuestras variables password y password2 y creamos nuestro if y le pasamos un raise error diciendo que los password deven ser iguales, después aqui tambien crearemos nuestra validacion de emails, para que 2 usuarios no peudantener el mismo email

```Python
from django.contrib.auth.models import User
from rest_framework import serializers

class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def save(self):
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password == password2:
            raise serializers.ValidationError({'error': 'P1 and P2 should be same!'})
```

ahora si, vamos a nuestro archivo "user_app/api/views.py" y creemos nuestras funciones, empezamos importando nuesta api_view para poder usar los decoradores.

Nuestra función se llamara registration_view, le añadimos antes su decorador api_view que se aplicara solo si es POST, luego ponemos nuestra condicional que si el request.method es POST, llamamos nuestro serializador que creamos "RegistrationSerializer" y le pasamos todos sus datos, si este serializador es valido ".is_valid():" salvamos el serializador y retornamos los datos

```Python
from rest_framework.decorators import api_view

from user_app.api.serializers import RegistrationSerializer

@api_view(['POST',])
def registration_view(request):
  
    if request.method == 'POST':
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return serializer.data
```

Ahora tenemos que crear la url donde mandaremos el registro, asi que vamos a "user_app/api/urls.py" importamos nuestra vista y luego creamos el path

```Python
from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
 
from user_app.api.views import registration_view
 

urlpatterns = [
    path('login/', obtain_auth_token, name='login'),
    path('register/', registration_view, name='register'),
]
```

Listo ya tenemos todo para crear un usuario de prueba, así que vamos al postman y creemos uno, creamos una nueva pestaña, le pasamos la dirección http://127.0.0.1:8000/account/register/ y en el Body, en form-data le pasamos los 4 campos que declaramos y lo mandamos como POST pero el campo de password cambiémosle algún carácter para ver si nos marca el error

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103150103.png)

perfecto, pero si lo ponemos bien aun no nos lo salva ya que no hemos creado la función de que pasa si están bein los dos, así que regresemos a serializers.py y creemos primero la de comparar emails y después la de salvar el usuario

Después del filtro del password ponemos un if que cheque si el mail que nos están pasando en el validated_data (ósea en el request) existe ya dentro de algún usuario usando la función User.objects.filter, si existe entonces le mandamos un raise error, y si no pues procedemos a crear la cuenta

```Python
...
if User.objects.filter(email=self.validated_data['email']).exists():

            raise serializers.ValidationError({'error': 'Email already exists!'})
...
```

entonces creamos la variable "account" donde le asignaremos el User y dentro le pasaremos lo que es el email (validado) y el username que igual vendrán de los validated_data del request, luego le salvaremos el password con .set_password y le pasamos pues el password que habíamos declarado arriba en la función, luego solo queda salvarlo y regresar account para que se vean los datos

```Python
...
    def save(self):

        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'error': 'P1 and P2 should be same!'})

        if User.objects.filter(email=self.validated_data['email']).exists():
            raise serializers.ValidationError({'error': 'Email already exists!'})
        account = User(email=self.validated_data['email'], username=self.validated_data['username'])
        account.set_password(password)
        account.save()

        return account
...
```

Vamos a probar primero lo del e-mail. salvando un email en nuestro usuario keikusanagi y poniéndole el mismo en los datos que estamos pasando por postman

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103152043.png)

Perfecto, nos dice que el Email ya existe, ahora ya solo nos falta pasar el resultado de crear el usuario en nuestra vista (cosa que en el curso no hizo y nos dio un error bien raro), entonces vamos a views.py y en el return añadimos lo siguiente ``return Response(serializer.data)``

```Python
from rest_framework.decorators import api_view
from rest_framework.response import Response
from user_app.api.serializers import RegistrationSerializer
 

@api_view(['POST',])
def registration_view(request):

    if request.method == 'POST':
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
```

Listo, entonces vallamos, pongamos bien todos los datos de usuario correo y password y 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103152410.png)

perfecto, ya tenemos nuestro link para crear usuarios, pero aun nos falta que nos pase nuestro token, ya que si vamos al panel de administracion aun no tenemos nuestro token aunque ya creamos nuestro usuario

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103152530.png)

Así que vamos a nuestro link en postman para crear tokens y mandémosle una petición para crear uno con nuestros datos de usuario que acabamos de crear

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103152652.png)
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103152718.png)

Ahora solo falta que al momento de crear nuestro registro pase el token automáticamente, esto sera seguramente al pasar el response

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103152930.png)

Pero eso lo veremos en nuestro siguiente episodio


## Token Authentication - Part 5 (Registration)

Continuando con nuestra seccion de usuarios, ahora pasaremos con el asignarle sus respectivos tokens a las cuantas que vallamos registrando, para esto la documentacion nos tiene una respuesta

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103181733.png)

Entonces vallamos a nuestro archivo "user_app/models.py" y peguemos lo que nos dice alli

```Python
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
```

Con esto generaremos tokens para cada usuario, ahora vamos a "user_app/api/views.py" y en la parte donde salvamos el serializador hagamos espacio para poder el nuevo método para crear los tokens ya que este validados los datos, los cuales pasaremos con la variable data, pero como tiene que ser un diccionario entonces creémosla en la parte de arriba antes del segundo if, tambien guardemos el serializer.save en la variable account para esta pasarla por medio del response al final, también crearemos una condicional else para pasarle los errores si hay alguno a la hora de salvar los datos. Con todo esto ahora solo falta pasar a llenar el diccionario vacío data que creamos con los datos como es el username, el email y un mensajito de creado satisfactoriamente.

Aquí lo importante es que al momento de crear el token (al cual le llamaremos igual token) pasemos el método que nos esta nombrando la documentación
``token = Token.objects.get(user=account).key``

por ultimo importamos el user_app models que creamos según la documentación para que pueda importar y usar la creacion de tokens

```Python
from rest_framework.decorators import api_view
from rest_framework.response import Response
  
from rest_framework.authtoken.models import Token

from user_app.api.serializers import RegistrationSerializer

from user_app import models


@api_view(['POST',])
def registration_view(request):

    if request.method == 'POST':
        serializer = RegistrationSerializer(data=request.data)

        data = {}

        if serializer.is_valid():
            account = serializer.save()

            data['response'] = "Registration Successful"
            data['username'] = account.username
            data['email'] = account.email

            token = Token.objects.get(user=account).key
            data['token'] = token

        else:
            data = serializer.errors

        return Response(serializer.data)
```


listo, así que vallamos a nuestro postman a crear un nuevo usuario mediante nuestro link de register y pasémosle los datos de usuario (recordando cambiar el username y el email para que no nos salga error)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221103184112.png)


Perfecto, ahora cada que registremos un usuario automáticamente se creara su token, ahora solo tenemos que encontrar una forma de que cada que hagamos logout se destruya ese token, pero eso lo veremos en el siguiente episodio


## Token Authentication - Part 6 (Logout)

Muy bien,  ya tenemos casi todo en nuestra api, nos falta hacer el logout, para esto crearemos un link en nuestras urls y crearemos una api_view que al momento de acceder a este link y pasarle nuestras credenciales pueda borrar el token que tenemos asignado.

Vamos a nuestro archivo "views.py" (el de user_app) y creamos nuestra api_view, esta le asignaremos que sea un método POST, luego la función le daremos el nombre de logout_view y le pasaremos un request, luego hacemos la verificación, si el request method que pasamos es POST entonces le decimos que el ``request.user.auth_token`` lo borre ``.delete()`` que esto quiere decir que el request user (ósea el usuario que este logueado) tomemos su token de autorización y le demos cuello XD, luego regresamos un Response pasando el estatus de todo ok ``HTTP_200_OK`` (para esto tenemos que importar status de rest_framework):

```Python
...
from rest_framework import status
...

@api_view(['POST',])
def logout_view(request):

    if request.method == 'POST':
        request.user.auth_token.delete()
        return Response(status= status.HTTP_200_OK)
...
```

Ahora vamos a nuestro archivo "urls.py" y creamos nuestro link de logout donde mandamos a llamar esta función (la importamos primero arriba )

```Python
from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token

from user_app.api.views import registration_view, logout_view

urlpatterns = [
    path('login/', obtain_auth_token, name='login'),
    path('register/', registration_view, name='register'),
    path('logout/', logout_view, name='logout'),
]
```

Ok tenemos todo listo ahora pongámoslo a prueba, vamos a nuestro postman y pasemosle los datos por medio de un POST (recordemos que asi lo definimos) primero hagamos login

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104132917.png)

Ok todo correcto, alli tenemos nuestro token de nuestro usuario de ejemplo 5, ahora tomamos ese token y pasémoslo con nuestro link de logout http://127.0.0.1:8000/account/logout/ por medio de un POST y en headers pasemos nuestro token

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104133112.png)

Perfecto, si checamos nos regresa nuestro status de 200_OK y en el response tambien a desaparecido el token, es mas si vamos a nuestro apnel de adminitracion veremos que ya no esta

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104133200.png)

Ahora vallamos a nuestro postman a login y volvamos a loguear ese usuario de ejemplo 5

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104133239.png)

Perfecto, nos ah creado un nuevo token, con el cual podemos interactuar nuevamente, incluso si ponemos solo para probar el token anterior nos regresara este error

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104133345.png)

Token invalido, perfecto, ya tenemos todo lo básico, ahora en la próxima lección probáremos toda nuestra app


## Manual Testing Entire Project - Part 1

Muy bien, es hora de empezar a testear todo nuestro proyecto, pero antes de eso tenemos que asegurarnos que es lo que queremos, en si queremos que esta API sea algo así como un clon de IMDb.
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104151850.png)

Si queremos lograr esto tenemos que cambiar algunas cosillas, por ejemplo en IMDb solo los administradores o miembros del staff pueden agregar watchlist, ya luego uno como usuario puede buscarlas y agregar su review y que solo el usuario dueño de la review y o un miembro del staff puedan modificar y o ocultar los reviews (por si alguno es falso o es spam), entonces para hacer todo esto, tenemos que modificar un poquito nuestra api para que en general el proceso luzca algo así

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104151436.png)

Entonces empecemos, vallamos a "watchlist_app/views.py" que es donde tenemos nuestra ASIGNACION de permisos y cambiemos un poco los que tenemos, empecemos con ``WatchDetailAV`` recordemos que esto nos regresa los detalles de una WatchList, entonces el GET esta bien, cualquier usuario puede ver los detalles pero el PUT y DELETE solo debería poder hacerlo los miembros del staff, así que podemos ir a la documentación https://www.django-rest-framework.org/api-guide/permissions/ y revisar esto ``permission_classes = [IsAuthenticated]``

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104152322.png)

Lo ponemos dentro de nuestra class y ahora brincamos a nuestro archivo de permissions.py para customizarlo como queremos

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104152653.png)

Aquí ya tenemos la class que nos proporciona los permisos que queremos, que es esta (bueno antes se llamaba AdminOrReadOnly pero la cambio pa que se vea mejor), entonces esta misma es la que usaremos así que quedaría así

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104152911.png)

Con esto, todo mundo podrá obtener como de lectura esto, pero si es parte del staff podrá hacer PUT y DELETE

El siguiente que revisaremos sera ``WatchListAV`` aqui necesitamos prácticamente el mismo permiso para que todos los usuarios puedan leer solamente y los miembros del staff puedan realizar cambios 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104172731.png)

Seguimos con ``StreamPlataformAV`` igual que los anteriores, nuestro staff puede modificar todo y los usuarios solo lectura

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104172837.png)

Con estos permisos que pusimos prácticamente ya tenemos todo el primer plano de nuestro diagrama referente a la administración, ahora seguiremos con la parte de plataformas de stream

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104172953.png)


Vamos mas arriba en el codigo a nuestra ``class StreamPlataformVS`` los mismos permisos para miembros del staff

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104173219.png)


subimos y en nuestra ``class ReviewDetail`` ya tenemos permisos para que solo quien hiso el review pueda modificarlo o borrarlo y cambiémoslo para que quede ``IsReviewUserOrReadOnly``

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104173707.png)

Nuestra ``class ReviewList`` no necesita cambios ya que todo mundo puede verla así que solo le quitamos la condicion que deva estar autenticado ya que queremos que todo el mundo pueda verla

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104173946.png)


Por ultimo nuestra ``class ReviewCreate`` que nos permite crear reviews pues allí si queremos que solo usuarios puedan crear reviews entonces le ponemos ese permiso

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221104174458.png)

Y listo ya tenemos todo preparado para empezar las pruebas, primero crearemos un nuevo usuario con el cual probáremos todo por medio de post man, pero todo esto sera en el próximo capitulo


## Manual Testing Entire Project - Part 2

Bueno pues siguiendo con el test en general haremos todo desde el principio. eso significa que borremos todos los usuarios (menos el super user) todos los watchlist y plataformas en nuestro panel de administración

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107122020.png)

Cuando borremos los usuarios automáticamente se borraran los tokens relacionados, al igual que los reviews relacionados con las watchlist que teníamos.

Lo primero sera hacer login para que nos de nuestro token http://127.0.0.1:8000/account/login/ llenamos un POST request, le pasamos por medio de form-data nuestro username y password y le damos send
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107123646.png)

esto nos regresara el token con el cual haremos lo siguiente en nuestrs pruebas
```Json
{
    "token": "cf9fd2c4bd24856eac06cd53c8ad31833807dcb0"
}
```

El siguiente paso es crear una plataforma nueva mediante nuestro link http://127.0.0.1:8000/watch/stream/ recordemos que es pasarle una petición POST, luego en header le pasamos nuestro token como "Authorization" 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107124040.png)

Y luego como body le pasamos un raw en formato de Json con los datos de nuestra plataforma none

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107124058.png)

Perfecto ya creamos nuestra primera plataforma y todo pro medio de postman y nuestros links de la API sigamos los mismos pasos para crear Netflix

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107124235.png)


Ok ahora añadiremos una watchlist mediante nuestro link http://127.0.0.1:8000/watch/list/ aquí para saber que campos agregar nos vamos a nuestro model y serán exactamente estos, menos los de avg_rating y eso porque esos se los añadiremos cuando hagamos nuestros reviews en unos minutos mas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107124854.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107125415.png)

Perfecto, como plataform si queremos ver que id tiene las que creamos lo podemos hacer mediante postman, en el link de stream solo cambiamos el post al get (no importando que el body tenga datos) y listo nos regresa la lista de plataformas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107125526.png)


Bien, agreguemos mas watchlist a cada una de las plataformas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107135846.png)


Muy bien, ya tenemos nuestra primera parte de las pruebas, que era hacerlo todo como administrador, ahora tenemos que registrar usuarios, hacer login con estos y registrar 2 o 3 reviews

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107140010.png)


Muy bien entonces vallamos a registrar un usuario de pruebas a nuestro link http://127.0.0.1:8000/account/register/ hagamos una petición POST , luego en body le pasamos los datos de nuestro nuevo usuario, como tip si no sabemos que datos son podemos solo darle en post y nos saldrá un error y los datos que necesitamos

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107141617.png)

entonces llenemos los datos, de echo no nos pide email pero pues como es un campo que pusimos se lo pondremos también

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107141818.png)

Perfecto, ya tenemos nuestro token de usuario, entonces tratemos de agregar una watchlist para ver si nos deja o solo si somos administradores

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107142108.png)

Perfecto, no nos deja ya que no tenemos el rango de staff, igual si queremos añadir una nueva serie no nos dejara

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107142340.png)

Ok entonces podemos decir que check en nuestra primera parte

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107142425.png)

ya pudimos crear cosas como admin, crear usuarios y probar si solo los admins podemos agregar mas cosas, entonces como usuarios debemos poder agregar reviews, así que hagámoslo con nuestro link http://127.0.0.1:8000/watch/5/review-create/ para agregar un review a nuestra serie de Prime Video "The Boys" (bastante buena por cierto)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107143241.png)

Perfecto, ahora solo pa que se vea mas estético, agregamos esto al final de nuestro return en  "watchlist_app/models.py"

```Python
...
def __str__(self):
        return str(self.rating) + " | " + self.watchList.title + " | " + str(self.review_user)
```

Para poder ver quien hico el review en nuestra pagina de administración

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107143506.png)

Perfecto, probemos entonces que sólo podemos hacer un review en esta serie y si podemos modificarla 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107143617.png)

Muy bien ahora démosle el método PUT para modificarla nada mas, para esto tenemos que pasarle un nuevo link indicándole que review queremos modificar,  primero hacemos un GET request de http://127.0.0.1:8000/watch/5/reviews/ para checar que numero tiene nuestro review

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107143944.png)

Ok es el review 8 asi que ahora modifiquemos el link para actualizarlo 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107144101.png)
No olvidemos pasarle nuestro token de usuario y listo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107144314.png)

Ahora intentemos hacer esto nuevamente pero siendo administradores, ya que tal ves su review infringe nuestras normas de comunidad, asi que pasémosle el token de administrador y...

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107144734.png)

Huy, auqui tenemos un problema ya que como administrador debíamos poder cambiar los comentarios de los usuarios, asi que revisemos nuestros permisos, vamos primero a "views.py" y checamos quein tiene permiso para los review's

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107144957.png)


OK aquí nos dice que ``[IsReviewUserOrReadOnly]`` entonces vamos a nuestros permisos y simplemente agréguenosle un ir a nuestro else indicándole que puede ser el usuario que lo creo ó si es staff

```Python
...
class IsReviewUserOrReadOnly(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            return obj.review_user == request.user or request.user.is_staff
```

Ahora probemos nuevamente 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107145256.png)

Perfecto, ya podemos ponerle palomita a esto ya que ahora si hace lo que queremos, solo nos faltaría probar si con otro nuevo usuario podemos modificar esta review

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107145414.png)


Asi que regresemos a nuestro postman, a nuestra pestaña de registro de usuarios y creemos uno nuevo 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107145655.png)

Ahora ponemos ese token de usuario en nuestro Headers y modificamos un poco el body y le damos send

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107145839.png)

Perfecto, no tenemos permiso ya que no somos miembros del staff ni los dueños de ese review, ahora vallamos a nuestro link para crear reviews de esta misma serie, pasémosle el token de test 2

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107150302.png)

Ahora si vamos a nuestro link de watch list podemos ver que en efecto tenemos 2 reviews de esta misma serie, asi como su avg_rating que seria 4.5 y asi

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107150508.png)


Ahora solo nos falta probar el logout, así que pasémosle el link le pasamos en el header nuestro token todo como POST request y listo, nos destruyo el token 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107150815.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107150827.png)

Con esto terminamos las pruebas según el video, solo quiero hacer una mas y es crear un nuevo token de este usuario haciendo login

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107151012.png)

Perfecto, si nos crea un nuevo token, todo luce bastante bien 😁




## JWT Authentication - Access Token and Refresh Token


Muy bien, según el curso esto es algo opcional, pero pues yo particularmente vi que esto es de lo que mas se usa con respecto a las autenticaciones, entonces empezamos yendo a la pagina de la documentation donde nos detalla todos los pormenores https://jwt.io

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107165621.png)

Nos recomienda darle una leída a todo especialmente a la introducción https://jwt.io/introduction ya después de esto checar lo que es los Json Web Token nos dice irnos a la documentación de REST framework y la parte de simplejwt https://django-rest-framework-simplejwt.readthedocs.io/en/latest/ para poder empezar a configurar nuestro proyecto ya hecho para usar esto.

Lo primero a hacer es instalarlo ``pip install djangorestframework-simplejwt``

Así que vamos a nuestro proyecto y estando seguros que corre nuestro env darle el comando de pip install

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107170851.png)

Luego tenemos que ir a nuestro archivo settings.py y agregar su configuración

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107170949.png)

comentamos las anteriores

```Python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        # 'rest_framework.permissions.IsAuthenticated',
        # 'rest_framework.authentication.BasicAuthentication',
        # 'rest_framework.authentication.TokenAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ]
}
```

Con esto estaremos usando el simplejwt en ves de los tokens de autenticación que usábamos anteriormente, ahora necesitamos configurar las urls, esto lo haremos en el archivo "user_app/api/urls.py"

```Python
from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView

from user_app.api.views import registration_view, logout_view

urlpatterns = [
    path('login/', obtain_auth_token, name='login'),
    path('register/', registration_view, name='register'),
    path('logout/', logout_view, name='logout'),
  
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
```

Dejamos los anteriores ya que simplemente no los usaremos y no tiene caso comentarlos, algo que me paso aqui es que me marca error al importar simplejwt pero solo en el editor ya que en la consola el servidor sigue en pie. 

Con esto terminamos al configuración y lo que ahora ara a diferencia a de como lo teníamos es que ya no almacenara los tokens en la base de datos, si no que los mantiene en el cache y ahora con cada login nos dará dos tokens, el Authentication Token "AT" y el Refresh Token "RT" estos tienen una duración de AT 5min y RT 24hrs, el AT nos dará acceso y el RT nos dará un nuevo AT cada que este se destruya, así bajamos el trafico de datos a la base de datos ya que no tendremos que estar checando y accediendo a los tokens cada ves que hagamos un request, estos se almacenaran de forma local de parte del cliente.

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107173430.png)

Todo esto es la primera parte, la segunda vendría siendo la estructura del JWT, que es muy única, si vamos a la documentación veremos que viene un token de ejemplo el cual viene dividido en 3 partes, el HEADER, PAYLOAD y VERIFY SIGNATURE

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221107173754.png)

Aquí la parte importante es la SIGNATURE ya que allí viene la codificación de nuestro token, información que nos ayudara validar nuestros tokens, esa seria la segunda parte importante el como viene configurado el token, y eso es todo por este capitulo, en el siguiente veremos como crear este token con el link de login, refrescarlo y todo eso que suena bieeeeeeeeen complicado pero al parecer no lo es tanto usando este framework.



## JWT Authentication - Login

Muy bien, ahora ya tenemos configurado el como crear nuestros JWT y el REFRESH token, vamos a probarlo, asi que vallamos a postman y pongamos el link http://127.0.0.1:8000/account/api/token/ y en la parte del body pongamos nuestro usuario y contraseña de administradores y pasémoslo como POST request

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108112522.png)

Si vamos a https://jwt.io/#debugger-io y ponemos nuestro token podemos ver su estructura y lo que significa, nos viene el header que nos dice en que algoritmo viene cifrado, nuestro payload diciéndonos que es un token de accesso y el id del jwt y nuestra signature

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108112650.png)

Ahora vamos a  probarlos, para esto añadamos una autorización para lectura para no estarle moviendo tanto a nuestra api, si vamos a nuestro panel de administración veremos que no viene ningún token nuevo, ya que estos como dijimos no se almacenan en la base de datos si no se almacenan temporalmente en el cache del cliente, en este caso nuestra computadora y con esto reducimos el trafico de datos de la base de datos.

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108112947.png)

Entonces ahora si vallamos a nuestro archivo "views.py" y agreguémosle (o des comentemos) el permiso para que solo estando autenticados podamos revisar nuestra lista

```Python
class ReviewList(generics.ListAPIView):
    # queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]
```

Ahora vallamos a Postman y con el link http://127.0.0.1:8000/watch/review/8/ para ver nuestro review #8 y en el body el pasamos nuestra token de autorización pero como Bearer

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108113548.png)

Perfecto, si nos lo da la informacion, pero que pasa si dejamos que pasen lso 5 minutos de vida del token:


Ok, esta caducado, pero ahora como renovamos este token sin tener que loguearnos de nuevo, pues para eso esta el link de refresh que pusimos en el capitulo anterior http://127.0.0.1:8000/account/api/token/refresh/ , entonces se lo pasamos por Postman como un POST request y le pasamos el dato del refresh token pero por medio del body y ahora elegimos ``x-www-form-urlencoded`` como key le pasamos refresh y como value el token de refresh obviamente y esto nos dará un nuevo token de acceso que solo vivirá otros 5 minutos

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108114042.png)


Bien ahora si saltamos a la documentación podemos ver la información respecto a ROTATE_REFRESH_TOKENS https://django-rest-framework-simplejwt.readthedocs.io/en/latest/settings.html#rotate-refresh-tokens con esto podemos hacer que cada que pidamos un nuevo token de acceso también nos refresque el refresh token (valga la redundancia) esto lo haremos en nuestro archivo "settings.py" y ponemos al final nuestro Nuevo setting

```Python
...
SIMPLE_JWT = {
    'ROTATE_REFRESH_TOKENS' : True,
}
```


Ahora si vamos a Postman y volvemos a refrescar nuestro token veremos que nos genera un nuevo token de acceso y de igual manera un nuevo token de refresh

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108115145.png)


Muy bien, ahora probemos nuestro nuevo token de accesso aprovechando que es la cuenta toda poderosa de staff vallamos y actualicemos alguna review y luego borrémosla

Vamos a nuestra review 9 creada por nuestro usuario de pruebas 2 y en el header recordemos ponerle nuestro nuevo token de acceso como Beaber, luego le pasamos un nuevo json cambiando el rating y dejándole un mensajito

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108115801.png)

Perfecto, ahora borremoslo 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108115842.png)

Huy que nos tardamos mucho, pero no hay problema, generemos un nuevo token de acceso y pasémoslo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108115940.png)

Perfecto ya nos borro el comentario, ahora solo nos falta crear un nuevo comentario con nuestros token de acceso solo para ver si todo funciona bien, así que vallamos a  y pasémosle el Bearer y nuestro nuevo token de acceso, luego como body le pasamos el review y listo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108120208.png)



## JWT Authentication - Registration

Muy bien, ya sabemos como se crean los tokens a la hora de hacer login pero como los creamos al momento de registrar un nuevo usuario, primero usemos uno de nuestros usuarios de prueba para generar un token y ver si pasa el id de este.

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108152304.png)

Si checamos en la pagina de https://jwt.io/#debugger-io veremos que en efecto nos da que es el usuario 8, sic hecamos en nuestra pagina de administracion veremos que tambien es el id de este usuario

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108152353.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108152437.png)

si le mandamos el token de refresh también nos dirá la misma información

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108152530.png)

Ahora, como podemos crear este token manualmente, si nos vamos a nuestro código en el archivo "user_app/api/views.py" lo creamos manualmente en la función "registration_view"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108152929.png)

Entonces para hacer algo similar vamos a la documentación y busquemos como crearlos manualmente
https://django-rest-framework-simplejwt.readthedocs.io/en/latest/creating_tokens_manually.html
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108153043.png)

Aquí nos viene explicado que si importamos el simplejwt RefreshToken este nos dejara crearlo con el objeto ``RefreshToken.for_user(user)`` y luego tenemos que retornar ese diccionario para tener acceso al refresh token y al access token

Tenemos que pasarle a la variable refresh = el usuario que en este caso lo declaramos arriba con el serializador en el account y luego el data (que es lo que regresamos) le asignamos el diccionario que nos dice en la documentación.

```Python
...
refresh = RefreshToken.for_user(account)
            data['token'] = {
                                'refresh': str(refresh),
                                'access': str(refresh.access_token),
                            }
...
```

Ahora ya podremos usar nuestro link de register sin problemas, solo no olvidemos comentar nuestro ``from user_app import models`` porque no estamos generando los tokens por este metodo, ahora registremos un nuevo usuario para comprobar que esto sirve, vamos al link http://127.0.0.1:8000/account/register/ en Postman y agreguémosle unos datos para crear otro usuario de prueba

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108154120.png)

Perfecto, nos regresa nuestro usuario y los tokens de acceso y refresh

Ahora hablemos de las ventajas y desventajas de JWT, una de las ventajas es que podemos controlar el tiempo de vida del token, si checamos la documentacion https://django-rest-framework-simplejwt.readthedocs.io/en/latest/settings.html 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108154415.png)

Podemos aquí cambiar estos settings para que nuestro token viva mas tiempo o menos tiempo, esa es una de las ventajas de usar estos ya que podemos controlar su vida útil

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108154542.png)

Otra vetaja como ya la mencionamos es que no ocupa el trafico de la base de datos, pero una desventaja es que no tenemos control sobre ese token durante los proximos 5 minutos, ya que si nos vamos a nuestro panel de administracion vemos que alli no nos aparece este token en ningun lado

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108154723.png)

Lo único que podríamos hacer para "cortar" el acceso a este usuario seria quitarle el permiso de Active, o directamente borrar este usuario, ahora como pequeña tarea nos deja el cambiar el tiempo de vida del token cambiando los settings así que háganosla 

simplemente si en los settings importamos el ``timedelta`` y luego añadimos el tiempo de vida que menciono que se usa normalmente (el access de 1 minuto y el refresh de 14 días) y listo

```Python
...
from datetime import timedelta

SIMPLE_JWT = {
    'ROTATE_REFRESH_TOKENS' : True,
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=14),
}
```



## Throttling Introduction

Muy bien, hagan de cuenta que lo anterior no ocurrio y quitamos todo lo de JWT que pusimos, ya hice pruebas y al parecer todo sigue funcionando bien, pero ahora veremos lo que es el "Throttling" que se traduce como 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108175916.png)

y esto es para proteger nuestra api ya que si la volvemos una open api fácilmente un bot podría mandarnos miles de solicitudes y saturar nuestro trafico de datos, entonces para esto existe el Throttling, si vamos a la documentación podemos ver lo siguiente
https://www.django-rest-framework.org/api-guide/throttling/#throttling

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108180107.png)

Podemos configurarlo en las settings gracias a restframework, lo que haremos sera limitar el numero de peticiones que podrán hacer los usuarios anónimos y también aunque siendo un numero un poco mas holgado el nuemro de peticiones que podrán hacer los usuarios ya registrados. 

Como ejemplo toma la pagina de https://medium.com donde sin registrarte te dan de 25 a 30 request y después de registrarte y crear una cuenta gratis te dan mucho mas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108180503.png)

En nuestro caos le daremos este tipo de restricción a nuestra "Watch List" ya que esta se puede mandar a llamar cualquier cantidad de veces ya sea este registrado o no, para esto lo mas común seria usar ``UserRateThrottle`` y ``AnonRateThrottle``

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221108180641.png)

Entonces empecemos con el estrangulamiento pero esto lo veremos en la próxima clase.



## Throttle Rate (Anon and User)


Muy bien, ahora nos toca implementar esto del Throttle, lo que necesitamos hacer primero es importar los settings que nos venían en la documentación a nuestro propio archivo de "settings.py"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109123835.png)

Quedando así, solo modificaremos la parte de ``THROTTLE_CLASSES`` para que nos deje siendo usuario anónimo ``anon`` hacer 1 consulta por día y siendo usuario registrado ``user`` 3 por dia

```Python
...
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        # 'rest_framework.permissions.IsAuthenticated',
        # 'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        # JWT Authentication - Registration
        # 'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '1/day',
        'user': '3/day'
    }
}
```

Listo,  ahora esto se aplica a TODAS nuestras vistas que tenemos si lo dejamos asi como esta solo configurado en los settings, por lo cual cualquier consulta que haga contara ya sea ver los reviews, las watchlist, las plataformas de streaming todo y no importa si eres usuario registrado, si haces una consulta en cada una de las listas te contara como en un contador global hasta llegar a alcanzar las 3, así que vamos a nuestro Postman a probar http://127.0.0.1:8000/watch/5/review/ este link nos dará los reviews de nuestra serie The Boys, le pasamos un request SIN poner nada de nuestros tokens de usuarios y:

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109125726.png)

Perfecto, solo nos dejo hacer un request y al siguiente nos salió ese mensaje y un response nuevo "429 Too Many Request", ahora pasémosle nuestro token de usuario para probar si nos deja hacer solo 3 por día como lo configuramos en settings

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109125915.png)

Perfecto, solo 3 por día aun siendo el admin todo mamalon (osea el usuario keikusanagi), entonces, recordemos que esto se aplica de manera global gracias a los settings, pero como aplicarlo en determinadas vistas, por ejemplo, quiero que al revisar las listas de watchlist no tenga limite pero si al revisar los reviews, para esto entonces comentamos en "settings.py" esto

```Python
...
    #'DEFAULT_THROTTLE_CLASSES': [
    #    'rest_framework.throttling.AnonRateThrottle',
    #    'rest_framework.throttling.UserRateThrottle'
    #],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '3/day',
        'user': '5/day'
    }
}
```

Y dejamos solo nuestras preferencias a la hora de cuantos comentarios se podrán por usuario anónimo y registrado, es mas, cámbienosla a 3 y 5 respectivamente, ahora vamos a nuestras vistas en "views.py" y revisamos la documentación que nos dice

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109130455.png)

Y como siempre no solo copiemos y peguemos, tenemos que importar primero no solo el ``UserRateThrottle``si no también el ``AnonRateThrottle`` y después pegar en cada vista en la cual queramos usar el Throttle el ``throttle_classes = [UserRateThrottle, AnonRateThrottle]`` 


```Python
...
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
...
class ReviewList(generics.ListAPIView):
    # queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    # permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle, AnonRateThrottle]

    def get_queryset(self):
        pk = self.kwargs['pk']
        return Review.objects.filter(watchList=pk)

class ReviewDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsReviewUserOrReadOnly]
    throttle_classes = [UserRateThrottle, AnonRateThrottle]
...
```

Con esto le estamos diciendo que si quieren revisar las listas de reviews ``class ReviewList`` y ``class ReviewDetail`` solo podrán hacerlo 3 veces si son anónimos y 5 si son usuarios registrados

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109131556.png)

Perfecto, le quitamos el token como si fuéramos anónimos y solo nos dejo 3 veces, ahora con el token

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109131632.png)

Igual, 5 veces y luego "429 Too Many Requests".


Ahora que pasa si queremos acceder a un DetailReview, por ejemplo el http://127.0.0.1:8000/watch/review/8/ 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109132157.png)

Con o sin token también nos saldrá el error 429 ya que ya agotamos nuestros intentos por día al hacer los intentos anteriores, entonces en el próximo capitulo veremos como podemos personalizar esta cuenta.


## Throttle Rate (Custom and Scope)

Ahora intentemos personalizar un poco mas nuestros Thorttle, para esto y usar Thorttle mas personalizados, tenemos que crear un nuevo archivo "watchlist_app/api/throttling.py" y en el crearemos nuestras nuevas class que usaremos para customizar las veces que un usuario registrado y uno anónimo podrán acceder a nuestras api, para esto primero comenzamos importando ``from rest_framework.throttling import UserRateThrottle`` luego creamos nuestras class ``class ReviewCreateThorttle`` y le pasamos ``(UserRateThorttle)`` dentro definiremos nuestro "scope" de igual manera creamos nuestra class ``class ReviewListThorttle`` y le asignamos su "scope"

```Python
from rest_framework.throttling import UserRateThrottle

class ReviewCreateThorttle(UserRateThrottle):
    scope = 'review-create'

class ReviewListThorttle(UserRateThrottle):
    scope = 'review-list'
```

Echo esto ahora vamos a definir la restricción de este "scope" esto lo haremos en nuestro archivo de "settings.py" justo debajo de las demás restricciones que tenemos para usuario anónimo y registrado 

```Python
...
'DEFAULT_THROTTLE_RATES': {
        'anon': '3/day',
        'user': '5/day',
        'review-create': '1/day',
        'review-list': '10/day',
    }
...
```

Ya creado esto ahora debemos ir a nuestro "views.py" e importar estas class para poder usarlas

```Python
...
from watchlist_app.api.throttling import ReviewCreateThorttle, ReviewListThorttle
...
```

Ahora nos falta mencionar nuestras "Throttle class" en nuestra ``ReviewCreate`` y en ``ReviewList``

```Python
...
class ReviewCreate(generics.CreateAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [ReviewCreateThorttle]
...
class ReviewList(generics.ListAPIView):
    # queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    # permission_classes = [IsAuthenticated]
    throttle_classes = [ReviewListThorttle, AnonRateThrottle]
...
```

Y listo, ahora vamos a checarlo, ponemos en Postman nuestro link http://127.0.0.1:8000/watch/6/review-create/ para añadirle una review a nuestra serie de Moon Knight, nos autenticamos, luego le pasamos un Json y lo pasamos como POST

```Json
{
    "rating": 5,
    "description": "New review",
    "active": true
}
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109160638.png)


Ahora con este mismo usuario, intentemos hacer otro review, ahora a nuestra serie de Lucifer http://127.0.0.1:8000/watch/8/review-create/

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109161229.png)

De igual forma si queremos checar alguna review solo nos dejara 10 veces, pongamos http://127.0.0.1:8000/watch/review/8/ en Postman e identifiquémonos como usuario y démosle GET 10 veces

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109161447.png)

Ahora tenemos que hablar de "ScopedRateThrottle" donde haremos algo similar a lo que hicimos pero en ves de crear un nuevo archivo, haremos lo que hicimos directamente 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109161814.png)

Vamos a "views.py" y si quiero definir nuestra throttle class aquí mismo, y luego puedo definir mi throttle scope aquí y luego el count for throttle. Bueno, esto puede sonar confuso(bastante de echo), lo que voy a hacer es importar mi ScopedRateThrottle, luego vamos a nuestra ``class ReviewDetail`` donde podemos acceder a un elemento individualmente y cambiamos nuestra ``throttle_classes`` por esta, ahora nos falta poner nuestro scope, definimos la variable ``throttle_scope = 'review-detail'``

```Python
...
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle, ScopedRateThrottle
...
class ReviewDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsReviewUserOrReadOnly]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'review-detail'
...
```

Ya con esto configurado vamos a "settings.py" y allí definimos el tiempo de nuestro scope

```Python
...
    'DEFAULT_THROTTLE_RATES': {
        'anon': '3/day',
        'user': '5/day',
        'review-create': '1/day',
        'review-list': '10/day',
        'review-detail': '2/day',
    }
```

Listo, vamos a postman al mismo link y chequemos los "reviewdetail" y chequémoslo 2 veces y a la tercera http://127.0.0.1:8000/watch/review/8/

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109163229.png)

Cabe recalcar que estos scope se convinan, por ejemplo aqui tenemos 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109163630.png)

Esto significa que se pueden ver 12 veces por dia, pero lo podemos modificar para que el detail lo puedan ver 5 veces los que no sean usuarios y luego ponerle que si se registran puedan ver 100 al día, o lo que mas podría ser usado seria que se puedan solo ver 1 registro por segundo (ósea 60 por minuto) pero solo deje 100 por día.


## Filtering Introduction

Muy bien, hablemos de Filtering, esto es la forma en la que podemos mandar a buscar un elemento por medio de un link, es como por ejemplo en amazon al momento de buscar algo, si nos checamos en la barra de direcciones podemos ver lo que pasa, si le damos buscar Wiskas alimento humedo para gatos nosotros solo veremos que nos aparecen varias opciones, pero en la barra de direcciones vemos que aparece www.amazon.com.mx/s?k=Whiskas+Alimento+Húmedo+Gatos donde la ``/s`` nos esta diciendo que es una busqueda, la ``k=``  es de la key a buscar y luego ``Whiskas+Alimento+Húmedo+Gatos`` que es justo lo que pusimos en la barra de busqueda

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109185043.png)

Este es un tipo de  filtering mejor conocida como busqueda, otro es en la parte izquierda que podemos darle a alguna opcion y nos aparecera lo que buscamos "filtrado" por marca por ejemplo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109185938.png)

y el ultimo tipo seria el Ordering que se refiere a ordenar los resultados respecto al mejor valorado, el menos o mayor precio etc 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109190017.png)


Ahora si vamos a la documentación https://www.django-rest-framework.org/api-guide/filtering/  podemos ver que Django REST framework nos puede ayudar a configurar un link de búsqueda al cual le podemos pasar unos parámetros y hacernos un filtering respecto a esto 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109190143.png)

Ya habíamos hecho algo similar en  el ReviewList donde creamos un queryset y luego lo reemplazamos por el resultado, aqui haremos algo similar 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109190930.png)

Usaremos el "pk" y le añadiremos el nombre de usuario 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221109191213.png)


Entonces para implementarlo vallamos a "views.py" y creemos una nueva class ``UserReview`` como va a ser simplemente una lista usemos el ``generics.CreateAPIView`` , ahora definamos el ``get_queryset`` y asignémosles el user al "pk" y luego regresamos el objeto filtrado por username

```Python
...
class UserReview(generics.ListAPIView):
    serializer_class = ReviewSerializer

    def get_queryset(self):
        username = self.kwargs['username']
        return Review.objects.filter(review_user__username=username)
...
```

Ahora vamos a crear nuestra URL, vamos a "watchlist_app/api/urls.py" y creemos nuestro link

```Python
...
from watchlist_app.api.views import ReviewList, ReviewDetail, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV, ReviewCreate, StreamPlataformVS, UserReview
...
    # Filtering
    path('review/<str:username>/', UserReview.as_view(), name='user_review-detail'),
]
```

Ya tenemos todo listo, ahora vallamos a nuestro Postman para realizar un filtro/búsqueda por usuario http://127.0.0.1:8000/watch/reviews/keikusanagi/ le pasamos ese link a Postman que es igual a como lo conformamos en el path, esto nos regresa todos los reviews hechos por mi usuario "keikusanagi"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110122621.png)

Si vamos a la pagina de administración podemos corroborar esto

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110122751.png)

Probemos con "test4"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110122827.png)

Muy bien, nuestro método de filtrado esta completo, ahora nos falta hacer el Filtering por medio de los parametrons de un  query "Filtering against query parameters"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110122956.png)

Entonces esto es como la búsqueda que mencionábamos de amazon, tenemos un link de búsqueda que termina en ``/s`` y luego un "key value" que sera algo así como ``k=keikusanagi`` para que nos busque o filtre todo lo relacionado a este usuario, entonces lo que haremos sera ir a "views.py" y comentemos el query set que habíamos hecho, para esto solo cambiaremos un poco nuestra función haciendo que haga un mapeo del username 
``username = self.request.query_params.get('username')``


```Python
...
class UserReview(generics.ListAPIView):
    serializer_class = ReviewSerializer

    # def get_queryset(self):
    #     username = self.kwargs['username']
    #     return Review.objects.filter(review_user__username=username)
    def get_queryset(self):
        username = self.request.query_params.get('username')
        return Review.objects.filter(review_user__username=username)
...
```


Ahora vamos a "urls.py" y quitamos esto del path ``<str:username>/`` ya que el maeo lo estamos haciendo en la funcion

```Python
...
    path('<int:pk>/review-create/', ReviewCreate.as_view(), name='review-create'),
    path('<int:pk>/reviews/', ReviewList.as_view(), name='review-list'),
    path('review/<int:pk>/', ReviewDetail.as_view(), name='review-detail'),

	# Filtering
    # path('reviews/<str:username>/', UserReview.as_view(), name='user_review-detail'),
    path('reviews/', UserReview.as_view(), name='user_review-detail'),
]
```

ahora solo tendremos que pasarle por postman el link de esta manera http://127.0.0.1:8000/watch/reviews/?username=test4

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110124902.png)

De echo si vemos, en la parte de Params se pone automáticamente ``username ! test4`` ya que son los parámetros de búsqueda que le estamos pasando, incluso si escribimos directamente en los parámetros nos a completa el link

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110125030.png)




## Filter, Search, Order


Muy bien, ahora para usar esto necesitamos instalar un paquete ``pip install django-filter`` solo tengamos cuidado de que nuestro entorno virtual este activo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110130729.png)

Luego vamos a "settings.py" y declaramos esta nueva app en INSTALED_APPS 


```Python
...
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # _app's creadas
    'watchlist_app',
    'rest_framework',
    'rest_framework.authtoken',
    'user_app',
    'django_filters',
]
...
```

Algo importante que debemos considerar es que este tipo de filtro no se puede aplicar en nuestras "APIView"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110132018.png)

si queremos aplicar un método de filtering aquí debemos aplicar el que vimos en la lección pasada, este método de dejango-filter lo podremos usar en nuestras clases genéricas como ListAPIView

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110132030.png)

En nuestro caos solo la usaremos en nuestra ``class ReviewList`` porque extraeremos información, asi que si queremos una pequeño demo vamos a la documentacion de "DjangoFilterBackend"
https://www.django-rest-framework.org/api-guide/filtering/#djangofilterbackend
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110132225.png)

Y de echo alli viene los pasos a seguir, nosotros ya seguimos 2 solo falta agregar a los settings ``'DEFAULT_FILTER_BACKENDS'`` si queremos aplicar esto a todas nuestras class, pero como queremos aplicarlo solo a una class especifica nos vamos con el siguiente

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110132621.png)


Vamos a nuestro archivo "views.py" a nuestra ``class ReviewList`` y agregamos nuestro filtro, y abajo le especificamos que campos "fields" son los que deberá reconocer para buscar

```Python
...
# django-filter
from django_filters.rest_framework import DjangoFilterBackend
...
class ReviewList(generics.ListAPIView):
    # queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    # permission_classes = [IsAuthenticated]
    throttle_classes = [ReviewListThorttle, AnonRateThrottle]
    # django-filter
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['revieww_user__username', 'active']
...
```

Ahora vamos a postman y seleccionemos el link de nuestra serie "The Boys" http://127.0.0.1:8000/watch/5/reviews/ y para hacer la búsqueda añadiremos unos parámetros, eso añadiéndole un sino de interrogación al final del link y con esto se activara la casilla de params y le podemos pasar alli alguno de los dos campos que declaramos arriba, el username y si esta active
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110133642.png)

Primero pasémosle el de si esta activo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110133812.png)

Si queremos revisar el username le ponemos como parametro

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110134056.png)

De echo podemos mandar a buscar dos campos sol añadiéndole un ``&`` o añadiendo un nuevo parámetro en la parte de abajo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110134314.png)

Ahora solo por propósitos de entender un poco mejor este método, haremos esta búsqueda pero en nuestra WatchList, pero si nos fijamos esta es una APIView no una generic, entonces creemos temporalmente una vista genérica de esta
```Python
...
# Filter, Search, Order
class WatchList(generics.ListAPIView):
    queryset = WatchList.objects.all()
    serializer_class = WatchListSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['title', 'plataform__name']
...
```

Y tambien añadimos su path, recordemos que todo esto es temporal

```Python
...
# Filter, Search, Order
path('list2/', WatchList.as_view(), name='watch-list'),
...
```

Ahora vamos a Postman a poner el link http://127.0.0.1:8000/watch/list2/ y añadimos detalles específicos a buscar, recordamos que le dimos como campos de referencia 'title' y 'plataform__name' así que busquemos alguno de estos, busquemos nuestra serie de "The boys" así que solo pongamos "boy" a ver que sale

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110140436.png)

Con esto vemos que tenemos que hacer un perfect match para que nos de nuestro resultado, esto es importante porque esto lo podremos usar cuando quermos saver exactamente el resultado de algo muy en especifico, por ejemplo en Amazon cuando le damos buscar laptops le podemos dar que nos filtre por solo las computadoras Asus o Lenovo, en este caso seria buscar algo en especifico

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110140726.png)


Esto como recordemos es la explicación de "DjangoFilterBackend" y recordemos que son 3

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110140907.png)

Entonces si queremos como tal realizar una búsqueda (no como ahorita que mas bien realizamos un filtro donándole específicamente lo que queríamos buscar) entonces necesitamos usar "SearchFilter" https://www.django-rest-framework.org/api-guide/filtering/#searchfilter

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110141005.png)

Vamos a "views.py" a nuestro ejemplo que hicimos de busqueda y pongamos ``filter_backends = [filters.SearchFilter]`` como dice la documentacion

```Python
...
from rest_framework import filters
...
class WatchList(generics.ListAPIView):
    queryset = WatchList.objects.all()
    serializer_class = WatchListSerializer
    # filter_backends = [DjangoFilterBackend]
	# filterset_fields = ['title', 'plataform__name']

# searchFilter
    filter_backends = [filters.SearchFilter]
    search_fields = ['title', 'plataform__name']
...
```

Vamos a Postman y usemos el mismo link http://127.0.0.1:8000/watch/list2/ pero ahora le agregaremos como Params ``search=boys`` para que nos busque dentro de todas nuestras watchlist algo relacionado con boys (automaticamente Postman completara el link a quedar asi http://127.0.0.1:8000/watch/list2/?search=boys)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110153403.png)

Perfecto, vemos que nos da los reviews que tiene la sere y aparte la serie aunque no escribimos la frase perfecta, por ejemplo si vamos al panel de administración vemos que si escribimos "the"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110153552.png)

tenemos dos watchlist que tienen ese elemento, vallamos a Postman y pongamos http://127.0.0.1:8000/watch/list2/?search=the 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110153622.png)

Perfecto, nos aparece todo lo relacionado con ">>The<< Boys" y "House of >>>the<<< Dragon" porque contienen the, no importando si es mayuscula o minuscula, si por ejemplo ponemos "on"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110153800.png)

nos salen "House of the Dragon" y "Moon Knight"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110153834.png)

Ya que terminan en "on" pero si ponemos solo "Dragon" (ósea la palabra especifica)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110153908.png)

Nos da específicamente solo "House of the Dragon", pero que pasa si queremos por ejemplo una busqueda "exacta" en el titulo pero en la plataforma puedan poner net y la api entienda que se refieren a netflix, o por ejemplo pongamos una condicional para que el titulo sea exacto por ejemplo con la serie de Netflix de "Lucifer"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110154621.png)

Si usamos entonces estas condicionales en el 'title'

```Python
...
    # searchFilter
    filter_backends = [filters.SearchFilter]
    search_fields = ['=title', 'plataform__name']
...
```

al momento de solo poner como 'title' "luci"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110154736.png)

Nos saldra que no lo encuentra porque esta buscando exactamente una serie llamada lucif solamente, pero si le quitamos el signo de igual


```Python
...
    # searchFilter
    filter_backends = [filters.SearchFilter]
    search_fields = ['title', 'plataform__name']
...
```

Nos dara el resultado aproximado que seria nuestra serie de "Lucifer"

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110154837.png)

si usamos el símbolo de ``^`` al inicio ![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110154938.png]] nos buscara cosas que empieza)con lo que le estamos pasando de búsqueda, como el ejemplo que ya usamos donde pusimos "the" y nos salieron dos resultados
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110155038.png)

si ahora usamos esto nos saldra solo "The boys"

```Python
...
    # searchFilter
    filter_backends = [filters.SearchFilter]
    search_fields = ['^title', 'plataform__name']
...
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110155128.png)

Muy bien ya solo nos queda el "OrderingFilter" igual que en los anteriores nos basaremos en lo que nos pide la documentación.
https://www.django-rest-framework.org/api-guide/filtering/#orderingfilter

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110155512.png)

Primero regresamos prácticamente todo a como estaba en la primera opción de "DjangoFilterBackend" pero le ponemos ``[filters.SearchFilter]``

```Python
...
# OrderingFilter
    filter_backends = [filters.SearchFilter]
    search_fields = ['title', 'plataform__name']
...
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110160718.png)

Nos dara ese bonito boton de busqueda pero nosotros queremos ordenarlos asi que le pondremos 

```Python
...
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['title', 'plataform__name']
...
```

Y con esto nos lo ordenara dependiendo los campos que le pasamos, en este caso title y plataform name

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110161544.png)


Por ejemplo digamos que los ordene por el 'avg_rating'

```Python
...
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['avg_rating']
...
```


![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110161745.png)

esto tambien lo podemos hacer en Postman, pasandole el link http://127.0.0.1:8000/watch/list2/?ordering=avg_rating

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110162418.png)

Asi como nos los muestra es de pequeño a mas grande, pero si usamos como en la documentación dice el símbolo ``-`` en solo el link

http://127.0.0.1:8000/watch/list2/?ordering=-avg_rating

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110162451.png)

Nos da en orden inverso los ratings, del mas grande al mas pequeño

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110162807.png)



## Project Update

Muy bien, en este capitulo haremos algunos cambios respecto a nuestro proyecto, relacionados con links y algunas menciones como por ejemplo WatchList, que causa un error por estar declarado arriba igual entonces causa conflicto, entonces vamos a nuestro archivo "views.py" y renombremos nuestra "class WatchList" por "WatchListGV" (osea de General View)

```Python
...
class WatchListGV(generics.ListAPIView):
    queryset = WatchList.objects.all()
    serializer_class = WatchListSerializer
...
```

Tambien en "watchlist_app/api/urls.py" Tambien actualizamos esto, e las importaciones y en el path (valla, por eso me salía que había un error en objects en el archivo views pero aun así em dejaba correr el programa 😅)

```Python
...
from watchlist_app.api.views import (ReviewList, ReviewDetail, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV, ReviewCreate, StreamPlataformVS, UserReview, WatchListGV)

from rest_framework.routers import DefaultRouter
...
urlpatterns = [
    path('list/', WatchListAV.as_view(), name='movie-list'),
    path('<int:pk>/', WatchDetailAV.as_view(), name='movie-detail'),

    # Filter, Search, Order
    path('list2/', WatchListGV.as_view(), name='watch-list'),
```

El siguiente cambio es en esta vista general cambiar que al momento de hacer un request de nuestro path nos aparece toda la informacion de las reviews

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110181525.png)

Ok es mucha información cuando realmente abajo ya tenemos el avg_rating y si queremos revisar las reviews podemos usar nuestro otro link para revisar una película en particular, y en esta que es una lista de películas pues sobra tanto detalle entonces vamos a nuestro "serializers.py" y comentemos la relación a los reviews que hicimos hace algunos capítulos

```Python
...
class WatchListSerializer(serializers.ModelSerializer):

	# reviews = ReviewSerializer(many=True, read_only=True)
    
    class Meta:
        model = WatchList
        fields = "__all__"
...
```

Con esto tendremos una vision mas limpia de nuestra lista Genérica de películas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110181808.png)

Nuestro siguiente cambio sera cambiar que aparece el Id de la plataforma a la que pertenece un watchlist y no el nombre como tal.

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110181956.png)

Para lograr esto tenemos que recurrir a nuestro serializador, justo donde comentamos el anterior, llamaremos a nuestra variable "plataform" le decimos que sera un serializador con "serializers" del tipo "CharField" y luego le pasamos como fuente que modelo ira aquí o al cual hara objetivo y este sera "plataform.name"

```Python
...
class WatchListSerializer(serializers.ModelSerializer):
    # reviews = ReviewSerializer(many=True, read_only=True)
    plataform = serializers.CharField(source='plataform.name')
...
```

Vamos a Postman y volvemos a dar send a nuestra lista generica 2 http://127.0.0.1:8000/watch/list2/ 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110182433.png)


Perfecto ya se ven los nombres de las plataformas en ves de ese ID, que aun existe, pero estamos haciéndole overrating por medio del serializador.

Ahora si viene lo bueno, la pagination, lo que nos hara trabajar con multiples paginas asi que vallamos a nuestro panel de administración y añadamos unas 15 o 20 peliculas/series

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221110184458.png)

Listo, ahora si la siguiente lección entraremos de lleno con esto de la paginación con todas estas películas y series que hemos agregado.


## Pagination Part 1 - PageNumber

Muy Bien, hablemos de la pagination, como hicimos en la parte final del capitulo anterior agregamos alrededor de 20 series y peliculas a nuestro proyecto, esto tratando de emular un poco a paginas como Amazon donde al buscar algo como Xbox, obtendremos miles y miles de resultados 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111132200.png)

Si vemos en la parte de abajo nos esta indicando que hay 7 paginas en total y en cada una nos muestran alrededor de 50 resultados, esto es porque Amazon no va a gastar recursos de su ancho de banda mostrándonos los mas de 350 resultados con imágenes y datos de un jalón, sabiendo que posiblemente entre los primeros 10 a 20 resultados este lo que buscamos, entonces nosotros haremos algo similar, si vamos a la documentación [Pagination](https://www.django-rest-framework.org/api-guide/pagination/#pagination) 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111132536.png)

Vemos que Django REST Framework tambien nos tiene una herramienta para poder realizar esta sin moverle tanto al proyecto, simplemente agregando algunos settings

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111132625.png)

Asi que vamos a nuestro archivo de "settings.py" y echemos manos a la obra, solo cambiemos el 'PAGE_SIZE'  a 5 para que nos de un limite de 5 paginas

```Python
...
REST_FRAMEWORK = {

    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '3/day',
        'user': '5/day',
        'review-create': '1/day',
        'review-list': '10/day',
        'review-detail': '2/day',
    },
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 5,
}
```

Ahora vallamos a Postman y en nuestro link de lista2 demosle enviar un GET

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111133016.png)

Ahora nos da varios datos relacionados con la paginación como son 

```Json
"count": 20,
    "next": "http://127.0.0.1:8000/watch/list2/?limit=5&offset=5",
    "previous": null,
    "results": [
```

Aqui vemos que nos da una cuenta de cuantas peliculas tenemos, luego nos da un link para la "next" o siguiente pagina, otra para la "previous" o la pagina anterior y lo resultados, de echo si le damos clcik al enlace automaticamente Postman nos abrira una nueva pestaña donde podremos darle sent de nuevo y nos dara los siguientes 5 resultados

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111133534.png)

Ahora, así como en los anteriores capítulos, la paginación tiene varias maneras de configurarse y se divide en este caso en estos 3
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111133842.png)
ahorita la que vimos fue ``LimitOffsetPagination`` y esta se esta aplicando a nuestro proyecto entero, entonces que pasa si queremos aplicarla solo a nuestra lista de películas pero no a los previews por ejemplo.

Entonces ahora probemos el "PageNumberPagination", comenzamos comentando los settings que pusimos globalmente en la parte anterior, y creamos dentro de "watchlist_app/api/" un archivo llamado "pagination.py" aquí crearemos nuestras classes para poderlas aplicar por separado, empesamos importando ``from rest_framework. pagination import PageNumberPagination`` y luego tenemos un montón de settings que podemos agregar

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111135056.png)

Ahorita dejémoslo con el "PageNumberPagination" y digámosle que lo deje en 5 (para que tengamos 4 paginas pa nuestras 20 películas y series agregadas)

```Python
from rest_framework. pagination import PageNumberPagination

class WatchListPagination(PageNumberPagination) :
    page_size = 5
```

Ahora debemos ir a "views.py" importar esta nueva class y luego declararla en la class "WatchListGV" 


```Python
...
# Pagination
from watchlist_app.api.pagination import WatchListPagination
...
class WatchListGV(generics.ListAPIView):
    queryset = WatchList.objects.all()
    serializer_class = WatchListSerializer
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['avg_rating']
# Pagination
    pagination_class = WatchListPagination
...
```

Probemos en postman con nuestro link http://127.0.0.1:8000/watch/list2/

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111135917.png)

Perfecto nos da 5 resultados por pagina, llegando hasta la pagina 4 y de alli nos dice que "next" es null porque ya no hay mas paginas

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111140008.png)

Ahora usemos otra configuración que tal
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111140243.png)
Este nos servirá para controlas el nombre del parámetro a pasar, esto no se entiende con solo decirlo pero pongámoslo a prueba, vallamos nuevamente a nuestro archivo de "pagination.py" y pongamos esta nueva configuración abajo de la anterior

```Python
from rest_framework. pagination import PageNumberPagination

class WatchListPagination(PageNumberPagination) :
    page_size = 5
    page_query_param = "Pag"
```

Ahora vamos a Postman y vemos que al darle send al get el link de "next" cambiara al final diciéndonos solo "Pag" en ves de "Page" como era antes

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111140847.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111140908.png)

Este parámetro lo podemos cambiar a lo que queramos por ejemplo Takeshi (el nombre de mi gato)

```Python
from rest_framework. pagination import PageNumberPagination

class WatchListPagination(PageNumberPagination) :
    page_size = "Takeshi"
```


![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111141009.png)

Bueno, regresémoslo a "P" para mantener la seriedad de la API , ahora probemos
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111141210.png)
Este nuevo parámetro deja que el usuario decida el numero de resultados que quiere por pagina y se brinca el numero que le pusimos nosotros ``page_size = 5``, solo tenemos que ponerlo de bajo y todo listo

```Python
from rest_framework. pagination import PageNumberPagination

class WatchListPagination(PageNumberPagination) :
    page_size = 5
    page_query_param = "p"
    page_size_query_param = "size"
```

Ahora si vamos a Postman y damos un request normal parece que nada a cambiado
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111141705.png)

Pero ahora le podemos pasar el parámetro anterior ya sea escribiéndolo directo en el link empezando con un ``/?size=7`` o ponerlo directamente en la caja de Params

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111141838.png)


Si le damos en siguiente incluso podemos ver que el link junta los dos parámetros (el de pagina y el de size) con una ``&`` .

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111141930.png)


Ahora si seguimos con nuestras configuraciones personalizadas, podemos ver que hay 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111142406.png)
Esta se refiere a que podemos limitar el numero de elementos por pagina que le podemos dar a alegir a nuestro usuario, algo asi como en la pagina https://coinmarketcap.com donde podemos ver que tienen miles y miles de paginas y si un usuario le da que le muestre 1000000000 datos no lo dejara ya que esta limitado a 20, 50 o 100 resultados por pagina

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111142520.png)

Entonces hagamos algo similar en nuestro proyecto, añadiremos esto al final de nuestro archivo "pagination.py" y dejémoslo en 10

```Python
from rest_framework. pagination import PageNumberPagination

class WatchListPagination(PageNumberPagination) :
    page_size = 5
    page_query_param = "p"
    page_size_query_param = "size"
    max_page_size = 10
```

Entonces si vamos a Postman y le escribimos que nos de 100000000 resultados, aun asi solo nos dara 10 ya que es el maximo permitido

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111142851.png)

Si nos dejara ver 100000 resultados, no nos saltaría "next", saldría como null, en cambio aquí nos esta dejando ver solo 10 resultados ya que este es el máximo, es mas si le damos a "next" ya no nos dara otra ves la opcion de "next" ya que llegaremos al resultado #20

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111143754.png)

Ahora el siguiente parámetro que podemos configurar es 
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111143928.png)
que nos llevara a la ultima pagina, incluso ahora sin moverle nada al código si le damos en ``p=last`` (como lo dice la documentación) nos llevara a la ultima pagina segun el maximo de resultados que le dimos al principio

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111144154.png)

Pero tambien podemos editar la palabra last para poner la que nosotros queramos, solo tenemos que agregar al codigo


```Python
from rest_framework. pagination import PageNumberPagination

class WatchListPagination(PageNumberPagination) :
    page_size = 5
    page_query_param = "p"
    page_size_query_param = "size"
    max_page_size = 10
    last_page_strings = "Takeshi"
```

Ahora si vamos a Postman y le volvemos a dar "last" saldra que es una pagina invalida

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111144358.png)

En cambio si mencionamos a mi gato, nos lleva a la ultima pagina 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111144419.png)

Bueno cambiémoslo a "end" pa que se siga viendo professional, aunque en el capitulo comenta que normalmente omite usar el ``page_query_param`` y el ``last_page_strings`` ya que por default tienen page y last así que no habría tanto problema a menos que enserio queramos usar una palabra clave en especifico, así que podríamos comentarlas y aun así quedaría bien

```Python
from rest_framework. pagination import PageNumberPagination

class WatchListPagination(PageNumberPagination) :
    page_size = 5
    # page_query_param = "p"
    page_size_query_param = "size"
    max_page_size = 10
    # last_page_strings = "end"
```


## Pagination Part 2 - LimitOffset

Nos  falto ver este tercer termino de la paginación que merece su propio capitulo porque la neta al principio no le entendí y al final tampoco, bueno me ayudo la documentación, por lo que entiendo el limit sigue siendo la cantidad limitada de "películas" por pagina que veremos por ejemplo si el limite es 3, de las 20 que tenemos solo nos mostrara 3 por pagina y el Offset, por lo que vi en un video de SQL, es desde que película vamos a empezar a enseñar, por ejemplo si le ponemos limit 3 offset 3 nos enseñara 3 películas por pagina empezando por la película 3 que tengamos agregada, bueno menos blablabla y mas pongámoslo a prueba.

[LimitOffsetPagination](https://www.django-rest-framework.org/api-guide/pagination/#limitoffsetpagination)
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111165900.png)

Empecemos configurando nuestro proyecto, para esto debemos agregarlo a nuestros settings en "settings.py" y luego vamos a nuestro archivo "pagination.py" para agregar una nueva class

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111171002.png)

```Python
...
# LimitOffsetPagination
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination'
    # 'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    # 'PAGE_SIZE': 5,
}
```

Luego en "pagination.py" primero importamos nuestro ``LimitOffsetPagination`` y luego creamos la class y le ponemos ``WatchListLOPagination`` y definimos como limite 5

```Python
from rest_framework. pagination import PageNumberPagination, LimitOffsetPagination
...
class WatchListLOPagination(LimitOffsetPagination):
    default_limit =5
```

Bien ahora vallamos a nuestros "views.py" y en nuestra class ``WatchListGV`` añadámosla al final comentando la ``WatchListPagination`` anterior y no olvidemos importarla

```Python
...
from watchlist_app.api.pagination import WatchListPagination, WatchListLOPagination
...
class WatchListGV(generics.ListAPIView):
    queryset = WatchList.objects.all()
    serializer_class = WatchListSerializer
#LimitOffsetPagination
    # pagination_class = WatchListPagination
    pagination_class = WatchListLOPagination
    
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['avg_rating']
...
```

Ya esta todo configurado, saltemos a nuestro Postman y probemos nuestro amado link http://127.0.0.1:8000/watch/list2/  si lo ponemos así como esta nos devolverá nuestros 5 primeros resultados ya que recordemos que le pusimos un ``default_limit = 5`` y el orden nos esta mostrando desde el primero que se creo al 5to 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111172417.png)

si le damos click al link que nos manda como "next" y mandamos la peticion, podemos ver que el siguiente "next" nos dice que el limit es 5 y el siguiente offset sera de 10, esto tiene sentido ya que la primera pagina nos mostro el offset 0 (osease empezando desde la primera serie) luego cuando le dimos next, este marcaba offset 5 (ósea estamos empezando desde el 5to elemento) entonces el siguiente (si sumamos 5+5) seria que empieza en el 10

Si por ejemplo cambiamos el link de

http://127.0.0.1:8000/watch/list2/?limit=5&offset=10

a

http://127.0.0.1:8000/watch/list2/?limit=10&offset=2

Esto en teoría nos mostrara 10 elementos (limit) pero empezando desde el segundo elemento (offset), en nuestro caso seria la serie de Lucifer de Netflix

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111173109.png)

En efecto empieza por esta y como nota, nos da aun asi un link "previous" en el cual podremos ver desde el inicio de la lista pero solo con el limite a 10, y el link de "next" si nos muestra el mismo limite pero el offset seria que empiece donde este acabo, ósea en el 12


![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111173142.png)

Ahora hablemos de una customization que tiene que es
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111173452.png)

Si ahorita le damos http://127.0.0.1:8000/watch/list2/?limit=20&offset=2 que significa que empiece en la segunda serie pero que nos enseñe 20 resultados, si nos fijamos tenemos solamente 20 entradas así que nos da opción de ver la anterior que seria las primeras 2 que se salto gracias al offset, entonces podemos configurar que el limite máximo sea el que queremos nosotros así

```Python
...
class WatchListLOPagination(LimitOffsetPagination):
    default_limit =5
    max_limit = 10
```

Esto le dice a nuestra api que mostrar solo 10 elementos, no importando que el usuario le ponga que muestre 100000

Ahora solo nos falta hablar de
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111174051.png)
Esto es como cuando le cambiamos el nombre de "page" a "Takeshi", osea que podemos personalizar la manera en que nuestro link muestra cual seria el limit y el inicio, asi que en nuestro archivo "pagination.py" pongamos

```Python
...
class WatchListLOPagination(LimitOffsetPagination):
    default_limit =5
    max_limit = 10
    limit_query_param = "limit"
    offset_query_param = "start"
```

Y si vamos a Postman y mandamos nuestra lista veremos como cambia nuestro link de "next" de
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111174538.png)

A esto 

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111174559.png)

Se ven casi iguales así que cambiémoslo a español para que se vea la diferencia

```Python
...
class WatchListLOPagination(LimitOffsetPagination):
    default_limit =5
    max_limit = 10
    limit_query_param = "limite_de_resultados"
    offset_query_param = "incia_en"
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221111174719.png)


## Pagination Part 2 - Cursor

A que se refiere esta -   [CursorPagination](https://www.django-rest-framework.org/api-guide/pagination/#cursorpagination) que es la que nos faltaba por ver? es como lo dice en su documentacion

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114110611.png)

Por ejemplo si nos metemos allí mismo en la paginación vemos que en la parte de arriba no viene el numero de pagina, al ser algo así como un curso nos viene solo Previous y Next:
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114110658.png)

Entonces vamos a llevarlo al código, solo recordemos que esta paginación depende de nuestro Datatime, va a ordenar siempre de las nuevas a las viejas publicaciones  

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114111015.png)

Vamos a nuestro archivo de "pagination.py" e importamos ``CursorPagination``, agreguemos una nueva class a la cual llamaremos ``WatchListLCPagination`` (ósea nada mas le cambiamos a CP por lo de Cursor Pagination) y luego solo le establecemos un limite de 5 paginas para hacer una prueba.

```Python
from rest_framework. pagination import PageNumberPagination, LimitOffsetPagination, CursorPagination
...
class WatchListLCPagination(CursorPagination ):
    page_size = 5
```

Ya tenemos nuestra paginación, ahora tenemos que ir a nuestro archivo "views.py" a aplicarla, primero comenzamos importando nuestra nueva paginación ``WatchListLCPagination`` y luego en nuestra class ``WatchListGV`` agregamos esta como ``pagination_class = WatchListLCPagination``, no olvidemos comentar la anterior de ``LimitOffsetPagination`` y también el ``ordering_fields`` ya que si no nos dará un error, ya que tratara de ordenarla por el orden de ``-created`` y al darle que los ordene según el ``avg_rating`` nos dará error

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114112130.png)


```Python
...
from watchlist_app.api.pagination import WatchListPagination, WatchListLOPagination, WatchListLCPagination
...
class WatchListGV(generics.ListAPIView):
    queryset = WatchList.objects.all()
    serializer_class = WatchListSerializer
#LimitOffsetPagination
    # pagination_class = WatchListPagination
    # pagination_class = WatchListLOPagination

#CursorPagination
    pagination_class = WatchListLCPagination

	# filter_backends = [filters.OrderingFilter]
    # ordering_fields = ['avg_rating']
...
```

Ya teniendo esto configurado, pasemos a Postman con el link que ya conocemos http://127.0.0.1:8000/watch/list2/ y al mandarle ese request nos mostrara nuestros solo 5 resultados, ordenados del mas nuevo creado al mas viejo, sin tener numero de pagina, solo next

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114112747.png)

Perfecto, ahora veamos otro aspecto personalizable de este método como lo que es ``ordering`` (que justo fue lo que cambiamos arriba para no tener el error)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114112130.png)

```Python
...
class WatchListCPagination(CursorPagination):
    page_size = 5
    ordering = 'created'
...
```


Si le damos así como esta nos traerá la lista ahora empezando por el mas viejo al mas nuevo (siguiendo la instrucción de mostrar solo 5 por pagina)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114115002.png)

Otra cosa que podemos personalizar es el link, en ves de que nos diga cursor, podemos decirle que nos ponga lo que nosotros queramos
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114115240.png)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114115111.png)

Solo agregamos esa variable y le asignamos el valor del nombre que queramos cambiar:

```Python
...
class WatchListCPagination(CursorPagination):
    page_size = 5
    ordering = 'created'
    cursor_query_param = 'takeshi'
...
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114115325.png)

Esto para que nos podría servir? pues si por ejemplo tenemos un contrato o un convenio y queremos que el usuario no salte a la ultima pagina con solo dar un click entonces podemos usar este  ``CursorPagination`` para que tenga mínimo que darle en "next" hasta que llegue hasta la ultima pagina.

Esto no viene en el curso pero quise hurgar un poco mas en lo que era ``ordering`` para ver si podia ordenarlo como lo hicimos en el anterior capitulo según nuestro ``avg_rating``
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114112130.png)

Segun esto podemos ponerle dentro de esta variable el método que queramos para ordenarlos por el 'slug', entonces cambie esto por el ``avg_rating`` y le puse un signo negativo para que me muestre del mayor al menor (algo así como en amazon cuando le das en ordenar según los mejor valorados)

```Python
...
class WatchListCPagination(CursorPagination):
    page_size = 5
    ordering = '-avg_rating'
...
```

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114120117.png)

Y perfecto, si nos lo ordena del mas alto rating al menor 😁.



## Browsable API Update

Muy bien, vamos con el ultimo capitulo de este tema, convertir nuestra app en algo que pueda ser buscable, a que nos referimos con esto? 

Hace tiempo ya pude conectar una api ya existente de Pokémon, en el cual al pasarle algunos request me devolvía un Json y este lo convertía yo ya en algo mas presentable 

Convirtiendo la respuesta de la [PokeAPI](https://pokeapi.co/) de esto
![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114141413.png)

A esto

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114141248.png)

Entonces si por ejemplo ponemos nuestra api ahorita como esta a producción al momento de ingresar un request por medio de un link les saldría esto:

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114141534.png)

Esto gracias a la interfaz de Django REST Framework, entonces para poder cambiar esto como si ya estuviéremos en producción simplemente tenemos que configurar un setting en nuestro archivo "settings.py" y checamos nuestra documentacion # [API Reference](https://www.django-rest-framework.org/api-guide/settings/#api-reference)

Tambien en el video nos muestra que lo busco en stackoverflow 
 [How to disable admin-style browsable interface of django-rest-framework?](https://stackoverflow.com/questions/11898065/how-to-disable-admin-style-browsable-interface-of-django-rest-framework)

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114142519.png)

Y allí nos viene la respuesta de poner eso en los settings

```Python
...
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '3/day',
        'user': '5/day',
        'review-create': '1/day',
        'review-list': '10/day',
        'review-detail': '2/day',
    },
# LimitOffsetPagination
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
# Browsable API Update
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer' ,
    )
}
```

Lo guardamos y listo

![image](/wiki/REST%20APIs%20Django%20REST%20Framework/IMG/Pasted%20image%2020221114142642.png)

Ya nos sale un JSON que fácilmente otros programas podrán interpretar