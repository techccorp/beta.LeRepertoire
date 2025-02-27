# ------------------------------------------------------------
# utils/recipe_utils.py
# ------------------------------------------------------------
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def lookup_ingredient(db, ingredient_name):
    """
    Look up an ingredient in the product_list collection using partial matches.
    Now returns PU, PUC, RU, RUC, along with SUPPLIER and INGREDIENT.
    """
    # partial match on INGREDIENT field
    result = db.product_list.find_one({'INGREDIENT': {'$regex': f'{ingredient_name}', '$options': 'i'}})
    if result:
        print(f"Lookup result for ingredient '{ingredient_name}': {result}")  # Debug log
        return {
            'SUPPLIER':  result.get('SUPPLIER', '-'),
            'INGREDIENT': result.get('INGREDIENT', 'Unknown'),
            'PU':         result.get('PU', 'N/A'),      # Purchase Unit
            'PUC':        float(result.get('PUC', 0)),  # Purchase Unit Cost
            'RU':         result.get('RU', 'N/A'),      # Recipe Unit
            'RUC':        float(result.get('RUC', 0))   # Recipe Unit Cost
        }
    print(f"No match found for ingredient: {ingredient_name}")  # Debug log
    return None

def lookup_recipeIngredient(db, recipeIngredient_name):
    """
    Look up a recipe ingredient in the global_recipes collection using partial matches.
    Returns the recipe details such as ingredients, quantities, etc.
    """
    # partial match on ingredient name within global recipe ingredients
    query = {'ingredients': {'$regex': f'{recipeIngredient_name}', '$options': 'i'}}
    recipes = db.global_recipes.find(query)
    
    # Convert MongoDB cursor to list and return the recipe details
    recipes_list = list(recipes)
    if recipes_list:
        print(f"Lookup result for recipe ingredient '{recipeIngredient_name}': {recipes_list}")  # Debug log
        return recipes_list
    print(f"No match found for recipe ingredient: {recipeIngredient_name}")  # Debug log
    return None

def lookup_globalRecipe(db, globalRecipe_name, filters=None):
    """
    Look up a recipe in the global_recipes collection using partial matches on the recipe name.
    Supports additional filters for ingredients, cuisine, method, and dietary requirements.
    """
    query = {'title': {'$regex': f'{globalRecipe_name}', '$options': 'i'}} if globalRecipe_name else {}

    # Apply additional filters
    if filters:
        if 'ingredient' in filters:
            query['ingredients'] = {'$regex': filters['ingredient'], '$options': 'i'}
        if 'cuisine' in filters:
            query['cuisine'] = {'$regex': filters['cuisine'], '$options': 'i'}
        if 'method' in filters:
            query['method'] = {'$regex': filters['method'], '$options': 'i'}
        if 'dietary' in filters:
            query['dietaryRequirement'] = {'$regex': filters['dietary'], '$options': 'i'}

    recipes = db.global_recipes.find(query)
    recipes_list = list(recipes)
    if recipes_list:
        print(f"Lookup result for global recipe '{globalRecipe_name}' with filters: {recipes_list}")  # Debug log
        return recipes_list
    print(f"No match found for global recipe: {globalRecipe_name} with filters {filters}")  # Debug log
    return []

def lookup_tag(db, tag_name):
    """
    Look up a tag by name in the tags collection.
    """
    result = db.tags.find_one({'name': {'$regex': f'^{tag_name}$', '$options': 'i'}})
    if result:
        print(f"Lookup result for tag '{tag_name}': {result}")  # Debug log
        return result['name']
    print(f"No match found for tag: {tag_name}")  # Debug log
    return None

def lookup_cuisine(db, cuisine_name):
    """
    Look up a cuisine by name in the cuisine collection.
    """
    result = db.cuisine.find_one({'name': {'$regex': f'^{cuisine_name}$', '$options': 'i'}})
    if result:
        print(f"Lookup result for cuisine '{cuisine_name}': {result}")  # Debug log
        return result['name']
    print(f"No match found for cuisine: {cuisine_name}")  # Debug log
    return None

def lookup_method(db, method_name):
    """
    Look up a method by name in the method collection.
    """
    result = db.method.find_one({'name': {'$regex': f'^{method_name}$', '$options': 'i'}})
    if result:
        print(f"Lookup result for method '{method_name}': {result}")  # Debug log
        return result['name']
    print(f"No match found for method: {method_name}")  # Debug log
    return None

def lookup_dietary(db, dietary_name):
    """
    Look up a dietary requirement by name in the dietary collection.
    """
    result = db.dietary.find_one({'name': {'$regex': f'^{dietary_name}$', '$options': 'i'}})
    if result:
        print(f"Lookup result for dietary requirement '{dietary_name}': {result}")  # Debug log
        return result['name']
    print(f"No match found for dietary requirement: {dietary_name}")  # Debug log
    return None

def lookup_mealtype(db, mealtype_name):
    """
    Look up a meal type by name in the mealtype collection.
    """
    result = db.mealtype.find_one({'name': {'$regex': f'^{mealtype_name}$', '$options': 'i'}})
    if result:
        print(f"Lookup result for meal type '{mealtype_name}': {result}")  # Debug log
        return result['name']
    print(f"No match found for meal type: {mealtype_name}")  # Debug log
    return None

def lookup_allergen(db, ingredient_name):
    """
    Look up allergens in the allergens collection using partial matches on the ingredient name.
    Returns allergen data including ingredient name, severity, reaction type, etc.
    """
    # Partial match on INGREDIENT field in allergens collection
    query = {'ingredient': {'$regex': f'{ingredient_name}', '$options': 'i'}}
    allergens = db.allergens.find(query)
    
    # Convert MongoDB cursor to list and return the allergen details
    allergens_list = list(allergens)
    if allergens_list:
        print(f"Lookup result for allergen '{ingredient_name}': {allergens_list}")  # Debug log
        return allergens_list
    print(f"No match found for allergen: {ingredient_name}")  # Debug log
    return None
