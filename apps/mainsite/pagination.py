from rest_framework.pagination import CursorPagination


class BadgrCursorPagination(CursorPagination):
    ordering = '-created_at'

    def __init__(self, ordering=None, page_size=None):
        if ordering is not None:
            self.ordering = ordering
        if page_size is not None:
            self.page_size = page_size
        super(BadgrCursorPagination, self).__init__()

    def get_link_header(self):
        links = []
        if self.has_next:
            links.append('<{}>; rel="next"'.format(self.get_next_link()))
        if self.has_previous:
            links.append('<{}>; rel="prev"'.format(self.get_previous_link()))
        if len(links):
            return ', '.join(links)

