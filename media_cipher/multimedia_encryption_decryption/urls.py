from django.urls import path,include
from multimedia_encryption_decryption import views

urlpatterns = [
    path('', views.home, name='home'),
    path('register/',views.register,name='register'),
    path('login/',views.login,name='login'),
    path('landing/', views.landing,name="landing"),
    path("encrypt/", views.encrypt_text, name="encrypt_text"),
    path("decrypt/", views.decrypt_text, name="decrypt_text"),
    path("encrypt_image/", views.encrypt_image, name="encrypt_image"),
    path('decrypt_image/', views.decrypt_image, name='decrypt_image'),
    #path("download/<str:image_type>/<int:image_id>/", views.download_image, name="download_image"),
    path('audio/', views.audio_encrypt_decrypt, name='audio_encrypt_decrypt'),
    path('encrypt_audio/', views.encrypt_audio, name='encrypt_audio'),
    path('decrypt_audio/', views.decrypt_audio, name='decrypt_audio'),
    path('encrypt_document/', views.encrypt_document, name='encrypt_document'),
    path('decrypt_document/', views.decrypt_document, name='decrypt_document'),
    #path('download_file/<str:file_name>/', views.download_file, name='download_file'),
    path('encrypt_video/', views.encrypt_video, name='encrypt_video'),
    path('decrypt_video/', views.decrypt_video, name='decrypt_video'),
    path('logout/', views.logout_view, name='logout'),
]