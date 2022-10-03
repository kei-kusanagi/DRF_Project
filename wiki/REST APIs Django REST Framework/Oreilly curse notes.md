Ya tenia el proyecto creado pero la regué tratando de añadirle archivos estáticos y una pagina de login, entonces opte por crearlo nuevamente (sirve practico)

creamos nuestro proyecto de Django y de aquí es de donde saque la buena practica de ponerle ``_app`` para saber cuales son

hacemos nuestras migraciones

luego creamos un super usuario

![[Pasted image 20221003175917.png]]

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

pa que aplique todas las migraciones y con esto tener completa nuestra estructura inicial de nuestra base de datos asi que saltamos a nuestro archivo admin.py y registramos nuestro modelo alli _(esto es para que nos aparezca en el panel de administración)_

![[Pasted image 20221003183911.png]]

vamos a llenar los campos para crear unas 3 películas solo para probar, ya que después lo haremos directamente con peticiones a la API