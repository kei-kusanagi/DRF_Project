from django.shortcuts import get_object_or_404
from rest_framework.response import Response

from rest_framework.exceptions import ValidationError

from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
# from rest_framework import mixins
from rest_framework import viewsets
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle, ScopedRateThrottle

from watchlist_app.models import WatchList, StreamPlataform, Review
from watchlist_app.api.serializers import WatchListSerializer, StreamPlataformSerializer, ReviewSerializer
# Permissions
from watchlist_app.api.permissions import IsAdminOrReadOnly, IsReviewUserOrReadOnly
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly

from watchlist_app.api.throttling import ReviewCreateThorttle, ReviewListThorttle

# django-filter
from django_filters.rest_framework import DjangoFilterBackend
# searchFilter
from rest_framework import filters

# Pagination
from watchlist_app.api.pagination import WatchListPagination, WatchListLOPagination, WatchListCPagination

class UserReview(generics.ListAPIView):
    serializer_class = ReviewSerializer

    # def get_queryset(self):
    #     username = self.kwargs['username']
    #     return Review.objects.filter(review_user__username=username)
    
    def get_queryset(self):
        username = self.request.query_params.get('username')
        return Review.objects.filter(review_user__username=username)


class ReviewCreate(generics.CreateAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [ReviewCreateThorttle]

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
            watchlist.avg_rating = (watchlist.avg_rating + serializer.validated_data['rating'])/2

        watchlist.number_ratging = watchlist.number_ratging + 1

        watchlist.save()

        serializer.save(watchList=watchlist, review_user=review_user)

class ReviewList(generics.ListAPIView):
    # queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    # permission_classes = [IsAuthenticated]
    throttle_classes = [ReviewListThorttle, AnonRateThrottle]
    # django-filter
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['review_user__username', 'active']

    def get_queryset(self):
        pk = self.kwargs['pk']
        return Review.objects.filter(watchList=pk)

class ReviewDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsReviewUserOrReadOnly]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'review-detail'
    
'''
class ReviewDetail(mixins.RetrieveModelMixin, generics.GenericAPIView) :
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    
    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)
class ReviewList(mixins.ListModelMixin, mixins.CreateModelMixin, generics.GenericAPIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
'''
class StreamPlataformDetailAV(APIView):

    def get(self, request, pk):
        try:
            plataform = StreamPlataform.objects.get(pk=pk)
        except StreamPlataform.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = StreamPlataformSerializer(plataform, context={'request': request})
        return Response(serializer.data)
    
    def put(self, request, pk):
        plataform = StreamPlataform.objects.get(pk=pk)
        serializer = StreamPlataformSerializer(plataform, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        plataform = StreamPlataform.objects.get(pk=pk)
        plataform.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class StreamPlataformVS(viewsets.ModelViewSet):

    queryset = StreamPlataform.objects.all()
    serializer_class = StreamPlataformSerializer
    permission_classes = [IsAdminOrReadOnly]

'''
# class StreamPlataformVS(viewsets.ViewSet):

#     def list(self, request):
#         queryset = StreamPlataform.objects.all()
#         serializer = StreamPlataformSerializer(queryset, many=True)
#         return Response(serializer.data)

#     def retrieve(self, request, pk=None):
#         queryset = StreamPlataform.objects.all()
#         watchlist = get_object_or_404(queryset, pk=pk)
#         serializer = StreamPlataformSerializer(watchlist)
#         return Response(serializer.data)

#     def create(self, request):
#         serializer = StreamPlataformSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
'''

class StreamPlataformAV(APIView):

    permission_classes = [IsAdminOrReadOnly]
    
    def get(self, request):
        plataform = StreamPlataform.objects.all()
        # serializer = StreamPlataformSerializer(plataform, many=True, context={'request': request})
        serializer = StreamPlataformSerializer(plataform, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = StreamPlataformSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Filter, Search, Order
class WatchListGV(generics.ListAPIView):
    queryset = WatchList.objects.all()
    serializer_class = WatchListSerializer
    # filter_backends = [DjangoFilterBackend]
    # filterset_fields = ['title', 'plataform__name']
#LimitOffsetPagination
    # pagination_class = WatchListPagination
    # pagination_class = WatchListLOPagination
#CursorPagination 
    pagination_class = WatchListCPagination
    
    # searchFilter
    # filter_backends = [filters.SearchFilter]
    # search_fields = ['^title', 'plataform__name']

    # OrderingFilter
    # filter_backends = [filters.OrderingFilter]
    # ordering_fields = ['avg_rating']

    # filter_backends = [filters.OrderingFilter]
    # ordering_fields = ['avg_rating']


class WatchListAV(APIView):

    permission_classes = [IsAdminOrReadOnly]

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
    
    permission_classes = [IsAdminOrReadOnly]

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