# ------------------------------------------------------------
# models/recipe_model.py
# ------------------------------------------------------------
class Ingredient:
    """
    Represents an ingredient in the database.
    """
    def __init__(self, ingredient_id, name, supplier, pu, puc, ru, ruc, conversion_ratio=None, yield_percentage=100):
        self.ingredient_id = ingredient_id
        self.name = name
        self.supplier = supplier
        self.pu = pu
        self.puc = puc
        self.ru = ru
        self.ruc = ruc
        self.conversion_ratio = conversion_ratio
        self.yield_percentage = yield_percentage

    @staticmethod
    def from_dict(data):
        return Ingredient(
            ingredient_id=data.get("ingredient_id"),
            name=data.get("name"),
            supplier=data.get("supplier"),
            pu=data.get("pu"),
            puc=data.get("puc"),
            ru=data.get("ru"),
            ruc=data.get("ruc"),
            conversion_ratio=data.get("conversion_ratio"),
            yield_percentage=data.get("yield_percentage", 100)
        )

    def to_dict(self):
        return {
            "ingredient_id": self.ingredient_id,
            "name": self.name,
            "supplier": self.supplier,
            "pu": self.pu,
            "puc": self.puc,
            "ru": self.ru,
            "ruc": self.ruc,
            "conversion_ratio": self.conversion_ratio,
            "yield_percentage": self.yield_percentage
        }

    def save(self):
        """
        Save the ingredient to the database.
        """
        collection = get_db("ingredients")
        collection.update_one(
            {"ingredient_id": self.ingredient_id},
            {"$set": self.to_dict()},
            upsert=True
        )

    @staticmethod
    def find_by_id(ingredient_id):
        """
        Find an ingredient by its ID.
        """
        collection = get_db("ingredients")
        data = collection.find_one({"ingredient_id": ingredient_id})
        return Ingredient.from_dict(data) if data else None

    @staticmethod
    def find_all():
        """
        Retrieve all ingredients.
        """
        collection = get_db("ingredients")
        return [Ingredient.from_dict(doc) for doc in collection.find()]

class Recipe:
    """
    Represents a recipe in the database.
    """
    def __init__(self, recipe_id, name, ingredients, sub_recipes=None):
        self.recipe_id = recipe_id
        self.name = name
        self.ingredients = ingredients
        self.sub_recipes = sub_recipes or []

    @staticmethod
    def from_dict(data):
        return Recipe(
            recipe_id=data.get("recipe_id"),
            name=data.get("name"),
            ingredients=data.get("ingredients", []),
            sub_recipes=data.get("sub_recipes", [])
        )

    def to_dict(self):
        return {
            "recipe_id": self.recipe_id,
            "name": self.name,
            "ingredients": self.ingredients,
            "sub_recipes": self.sub_recipes
        }

    def save(self):
        """
        Save the recipe to the database.
        """
        collection = get_db("recipes")
        collection.update_one(
            {"recipe_id": self.recipe_id},
            {"$set": self.to_dict()},
            upsert=True
        )

    @staticmethod
    def find_by_id(recipe_id):
        """
        Find a recipe by its ID.
        """
        collection = get_db("recipes")
        data = collection.find_one({"recipe_id": recipe_id})
        return Recipe.from_dict(data) if data else None

    @staticmethod
    def find_all():
        """
        Retrieve all recipes.
        """
        collection = get_db("recipes")
        return [Recipe.from_dict(doc) for doc in collection.find()]