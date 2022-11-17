from django.contrib.auth.models import User
from django.urls import reverse

from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token

from watchlist_app.api import serializers
from watchlist_app import models


class StreamP1atformTestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="example", password="Passwors@123")
        self.token = Token.objects.get(user__username=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

        self.stream = models.StreamPlataform.objects.create(
            name= "Netflix",
            about= "#1 Streaming Plataform",
            website= "http://www.netflix.com",
        )

    def test_streamplataform_create(self):
        data = {
            "name": "Netflix",
            "about": "#1 Streaming Plataform",
            "website": "http://www.netflix.com",
        }
        response = self.client.post(reverse('streamplataform-list'), data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_streamplataform_list(self):
        response = self.client.get(reverse('streamplataform-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_streamplataform_ind(self):
        response = self.client.get(reverse('streamplataform-detail', args=(self.stream.id,)))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

class WatchListTestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="example", password="Passwors@123")
        self.token = Token.objects.get(user__username=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

        self.stream = models.StreamPlataform.objects.create(
            name= "Netflix",
            about= "#1 Streaming Plataform",
            website= "http://www.netflix.com",
        )
        
        self.watchlist = models.WatchList.objects.create(
            plataform=self.stream,
            title= "Example Movie",
            storyline="Example Story",
            active= True
        )

    def test_watchlist_create(self):
        data = {
            "plataform": self.stream,
            "title": "Example Movie",
            "storyline": "Example Story",
            "active": True
        }
        response = self.client.post(reverse('movie-list'), data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
    def test_watchlist_list(self):
        response = self.client.get(reverse('movie-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_watchlist_ind(self):
        response = self.client.get(reverse('movie-detail', args=(self.watchlist.id,)))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(models.WatchList.objects.get().title, 'Example Movie')
        self.assertEqual(models.WatchList.objects.count(), 1)
        
    
class ReviewTestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="example", password="Passwors@123")
        self.token = Token.objects.get(user__username=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

        self.stream = models.StreamPlataform.objects.create(
            name= "Netflix",
            about= "#1 Streaming Plataform",
            website= "http://www.netflix.com",
        )
        
        self.watchlist = models.WatchList.objects.create(
            plataform=self.stream,
            title= "Example Movie",
            storyline="Example Story",
            active= True
        )
        self.watchlist2 = models.WatchList.objects.create(
            plataform=self.stream,
            title= "Example Movie",
            storyline="Example Story",
            active= True
        )
        self.review = models.Review.objects.create(
            review_user = self.user,
            rating = 5,
            description = "Great Movie!",
            watchList=self.watchlist2,
            active= True
        )
        
    def test_review_create(self):
        data = {
            "review_user" :self.user,
            "rating" : 5,
            "description": "Great Movie!",
            "watchlist" : self.watchlist,
            "active" : True
        }
        response = self.client.post(reverse('review-create', args=(self.watchlist.id,)), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.Review.objects.count(), 2)
        # self.assertEqual(models.Review.objects.get().rating, 5)

        response = self.client.post(reverse('review-create', args=(self.watchlist.id,)), data)
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
    
    def test_review_create_anauth(self):
        data = {
            "review_user": self.user,
            "rating" : 5,
            "description": "Great Movie!",
            "watchlist" : self.watchlist,
            "active" : True
        }

        self.client.force_authenticate(user=None)
        response = self.client.post(reverse('review-create', args=(self.watchlist.id,)), data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_review_update(self):
        data = {
            "review_user": self.user,
            "rating" : 4,
            "description": "Great Movie! - Updated",
            "watchlist" : self.watchlist,
            "active" : False
        }

        response = self.client.put(reverse('review-detail', args=(self.review.id,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_review_list(self):
        response = self.client.get(reverse('review-list', args=(self.watchlist.id,)))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_review_ind(self):
        response = self.client.get(reverse('review-detail', args=(self.review.id,)))
        self.assertEqual(response.status_code, status.HTTP_200_OK)