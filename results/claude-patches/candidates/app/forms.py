from django import forms
from .models import User
#TODO: cpassword is an unknown field from user, figure out how to include it
class UserForm(forms.ModelForm):
    #TODO: password and cpassword structure doesn't match the User
    # - user object should maintain same structure
    # - form should be changed
    class Meta:
        model = User
        fields = [
            'username','password','blab_name','real_name'
        ]
        widgets = {
            'password': forms.PasswordInput(),
        }

class RegisterForm(forms.Form):
    password = forms.CharField(max_length=100, widget=forms.PasswordInput)
    cpassword = forms.CharField(max_length=100, widget=forms.PasswordInput)
    blabName = forms.CharField(max_length=100)
    realName = forms.CharField(max_length=100)
    