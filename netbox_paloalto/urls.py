from django.urls import path
from . import views


urlpatterns = [
    path('<str:name>/', views.FirewallRulesView.as_view(), name='firewall_rule'),
]
