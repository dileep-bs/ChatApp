from django.urls import path


from . import views

urlpatterns =[
               path('',views.index,name='index'),
               path("register",views.register,name='register'),
               path("login",views.login,name='login'),
               path("verify/<token>/",views.verify,name='verify'),
               path("logout",views.logout,name='logout'),
               path('activate/<token>/',views.activate,name='activate'),
               path('sendmail',views.sendmail,name='sendmail'),
               path('reset_password/<token>/',views.reset_password,name='resetpassword'),]
