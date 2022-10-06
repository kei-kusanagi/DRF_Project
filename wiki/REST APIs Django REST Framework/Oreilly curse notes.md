Ya tenia el proyecto creado pero la regué tratando de añadirle archivos estáticos y una pagina de login, entonces opte por crearlo nuevamente (sirve practico)

## Creating JSON Response - Individual Elements

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

            return Response(serializer.errorsm, status=status.HTTP_400_BAD_REQUEST)

  

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
	
	            return Response(serializer.errorsm, status=status.HTTP_400_BAD_REQUEST)

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