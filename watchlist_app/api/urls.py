from django.urls import path, include
from watchlist_app.api.views import ReviewList, ReviewDetail, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV

urlpatterns = [
    path('list/', WatchListAV.as_view(), name='movie-list'),
    path('<int:pk>', WatchDetailAV.as_view(), name='movie-detail'),
    path('stream/', StreamPlataformAV.as_view(), name='stream'),
    path('stream/<int:pk>', StreamPlataformDetailAV.as_view(), name='stream-detail'),


    # path('review/', ReviewList.as_view(), name='review-list'),
    # path('review/<int:pk>', ReviewDetail.as_view(), name='review-detail'),

    path('stream/<int:pk>/review', ReviewList.as_view(), name='review-list'),
    path('stream/review/<int:pk>', ReviewDetail.as_view(), name='review-detail'),
]