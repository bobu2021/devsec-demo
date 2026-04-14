from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from .models import Profile


class RegistrationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("philemon_mutabazi:register")

    def test_register_success(self):
        response = self.client.post(
            self.url,
            {
                "username": "newuser",
                "email": "new@example.com",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username="newuser").exists())

    def test_register_rejects_duplicate_email(self):
        User.objects.create_user(username="existing", email="dup@example.com", password="StrongPass123!")
        response = self.client.post(
            self.url,
            {
                "username": "other",
                "email": "dup@example.com",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "A user with this email already exists.")


class LoginLogoutTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="tester", password="StrongPass123!")

    def test_login_success(self):
        response = self.client.post(
            reverse("philemon_mutabazi:login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_logout_requires_post(self):
        self.client.login(username="tester", password="StrongPass123!")
        response = self.client.get(reverse("philemon_mutabazi:logout"))
        self.assertEqual(response.status_code, 200)
        response = self.client.post(reverse("philemon_mutabazi:logout"))
        self.assertEqual(response.status_code, 302)


class AccessControlTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="authuser", password="StrongPass123!")

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("philemon_mutabazi:dashboard"))
        self.assertEqual(response.status_code, 302)

    def test_profile_requires_login(self):
        response = self.client.get(reverse("philemon_mutabazi:profile"))
        self.assertEqual(response.status_code, 302)

    def test_dashboard_allows_authenticated_user(self):
        self.client.login(username="authuser", password="StrongPass123!")
        response = self.client.get(reverse("philemon_mutabazi:dashboard"))
        self.assertEqual(response.status_code, 200)


class PasswordAndProfileTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="profileuser",
            email="profile@example.com",
            password="StrongPass123!",
        )
        self.client.login(username="profileuser", password="StrongPass123!")

    def test_password_change(self):
        response = self.client.post(
            reverse("philemon_mutabazi:password_change"),
            {
                "old_password": "StrongPass123!",
                "new_password1": "UpdatedPass123!",
                "new_password2": "UpdatedPass123!",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_profile_update(self):
        response = self.client.post(
            reverse("philemon_mutabazi:profile"),
            {
                "username": "profileuser",
                "email": "updated@example.com",
                "bio": "Updated bio",
                "date_of_birth": "1999-01-15",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "updated@example.com")
        self.assertTrue(Profile.objects.filter(user=self.user).exists())
