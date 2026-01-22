def is_authenticated(user) -> bool:
    return getattr(user, "is_authenticated", False)


def get_user_groups_set(user) -> set:
    if hasattr(user, "_group_names_cache") and user._group_names_cache is not None:
        return user._group_names_cache

    if not hasattr(user, "groups"):
        return set()

    names = set(user.groups.values_list("name", flat=True))
    user._group_names_cache = names
    return names


def is_in_group(user, group_name: str) -> bool:
    return group_name in get_user_groups_set(user)


def is_admin_or_staff(user) -> bool:
    if getattr(user, "is_superuser", False) or getattr(user, "is_staff", False):
        return True

    user_groups = get_user_groups_set(user)
    return "admin" in user_groups or "staff" in user_groups


def is_customer(user) -> bool:
    user_groups = get_user_groups_set(user)
    return "customer_verified" in user_groups or "customer_unverified" in user_groups


def is_verified_customer(user) -> bool:
    if "customer_verified" in get_user_groups_set(user):
        return True
    return getattr(user, "role", None) == "customer" and getattr(user, "is_verified", False)
