from django.contrib import admin
from watchlist_app.models import WatchList, StreamPlataform, Review

# Register your models here.
admin.site.register(WatchList)
admin.site.register(StreamPlataform)
admin.site.register(Review)