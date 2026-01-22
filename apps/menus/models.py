from decimal import Decimal

from django.core.validators import MinValueValidator
from django.db import models

from apps.common.constants import MenuType
from apps.common.models import BaseModel


class CategoryManager(models.Manager):
    def get_by_natural_key(self, name):
        return self.get(name=name)


class Category(BaseModel):
    name = models.CharField(max_length=120, unique=True)
    display_order = models.IntegerField(default=0)

    objects = CategoryManager()

    class Meta:
        db_table = "category"
        ordering = ("display_order", "name")
        verbose_name_plural = "Categories"

    def natural_key(self):
        return (self.name,)

    def __str__(self):
        return self.name


class ItemManager(models.Manager):
    def get_by_natural_key(self, name):
        return self.get(name=name)


class Item(BaseModel):
    category = models.ForeignKey(
        Category,
        on_delete=models.PROTECT,
        related_name="items",
        db_column="category_id",
    )
    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    base_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal("0.00"))],
    )

    objects = ItemManager()

    class Meta:
        db_table = "item"
        indexes = [
            models.Index(fields=["category"]),
            models.Index(fields=["name"]),
        ]
        unique_together = [("category", "name")]

    def natural_key(self):
        return (self.name,)

    natural_key.dependencies = ["menus.category"]

    def __str__(self):
        return self.name


class MenuManager(models.Manager):
    def get_by_natural_key(self, name):
        return self.get(name=name)


class Menu(BaseModel):
    name = models.CharField(max_length=120)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    type = models.CharField(choices=MenuType.choices, max_length=20, default=MenuType.BREAKFAST)

    items = models.ManyToManyField(
        "Item",
        through="MenuItem",
        through_fields=("menu", "item"),
        related_name="menus",
        related_query_name="menu",
    )

    objects = MenuManager()

    class Meta:
        db_table = "menu"
        indexes = [
            models.Index(fields=["start_time"]),
            models.Index(fields=["end_time"]),
        ]

    def natural_key(self):
        return (self.name,)

    def __str__(self):
        return f"{self.name} ({self.start_time} - {self.end_time})"


class MenuItem(BaseModel):
    menu = models.ForeignKey(
        Menu,
        on_delete=models.CASCADE,
        related_name="menu_items",
        db_column="menu",
    )
    item = models.ForeignKey(
        Item,
        on_delete=models.PROTECT,
        related_name="menu_items",
        db_column="item",
    )
    display_order = models.IntegerField(default=0)
    quantity = models.PositiveIntegerField()
    override_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    is_permanent = models.BooleanField(default=False)

    class Meta:
        db_table = "menu_item"
        unique_together = [("menu", "item")]
        indexes = [
            models.Index(fields=["menu", "display_order"]),
            models.Index(fields=["item"]),
        ]
        ordering = ["menu", "display_order"]
        permissions = [
            ("change_menuitem_price", "Can set override price on a menu item"),
            ("change_menuitem_quantity", "Can change available quantity on a menu item"),
            ("set_menuitem_permanent", "Can mark a menu item as permanent"),
        ]

    def __str__(self):
        return f"{self.menu} · {self.item}"
