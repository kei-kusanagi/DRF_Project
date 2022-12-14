from rest_framework. pagination import PageNumberPagination, LimitOffsetPagination, CursorPagination 

class WatchListPagination(PageNumberPagination) :
    page_size = 5
    # page_query_param = "p"
    page_size_query_param = "size"
    max_page_size = 10
    # last_page_strings = "end"

class WatchListLOPagination(LimitOffsetPagination):
    default_limit =5
    max_limit = 10
    limit_query_param = "limite_de_resultados"
    offset_query_param = "incia_en"

class WatchListCPagination(CursorPagination):
    page_size = 5
    ordering = '-avg_rating'
    # cursor_query_param = 'takeshi'