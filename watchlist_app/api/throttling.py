from rest_framework.throttling import UserRateThrottle

class ReviewCreateThorttle(UserRateThrottle):
    scope = 'review-create'

class ReviewListThorttle(UserRateThrottle):
    scope = 'review-list'