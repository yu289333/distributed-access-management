"""Compatibility facade; use conditionExpression for new code."""
from .conditionFormat import literal, join, regex_escape, cel_activation
from .awsCondition import aws
from .azureCondition import azure
from .conditionExpression import condition_to_cel, populate_condition_cel
