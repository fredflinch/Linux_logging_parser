import pandas as pd
from lib.parser import parser

pObj = parser('..\exampledata\webaccess.log', '../out.csv', True)
pObj.parse_webaccess()
