from rest_framework import serializers
from watchlist_app.models import Review, WatchList, StreamPlataform, Review

class ReviewSerializer(serializers.ModelSerializer):
    review_user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Review
        exclude = ('watchList',)
        # fields = "__all__"

class WatchListSerializer(serializers.ModelSerializer):
    # reviews = ReviewSerializer(many=True, read_only=True)
    plataform = serializers.CharField(source='plataform.name')
    class Meta:
        model = WatchList
        fields = "__all__"

class StreamPlataformSerializer(serializers.ModelSerializer):
    watchlist = WatchListSerializer(many=True, read_only=True)
    class Meta:
        model = StreamPlataform
        fields = "__all__"