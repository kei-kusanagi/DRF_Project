from django.urls import path, include
from watchlist_app.api.views import ReviewList, ReviewDetail, WatchListAV, WatchDetailAV, StreamPlataformAV,StreamPlataformDetailAV

urlpatterns = [
    path('list/', WatchListAV.as_view(), name='movie-list'),
    path('<int:pk>', WatchDetailAV.as_view(), name='movie-detail'),
    path('stream/', StreamPlataformAV.as_view(), name='stream'),
    path('stream/<int:pk>', StreamPlataformDetailAV.as_view(), name='stream-detail'),

    #GenericAPIView and Mixins
    path('review/', ReviewList.as_view(), name='review-list'),
    # GenericAPIView and Mixins
    path('review/<int:pk>', ReviewDetail.as_view(), name='review-detail'),
]