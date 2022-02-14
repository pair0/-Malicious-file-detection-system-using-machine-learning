import os
import pandas
import numpy
import pickle
import pefile
import sklearn.ensemble as ek
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn import tree, linear_model
from sklearn.feature_selection import SelectFromModel
import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn import preprocessing
from sklearn import svm
from sklearn.linear_model import LinearRegression

dataset = pandas.read_csv('/manalyze_de/data.csv', sep='|', low_memory=False)

X = dataset.drop(['Name','md5','legitimate'],axis=1).values
y = dataset['legitimate'].values

extratrees = ek.ExtraTreesClassifier().fit(X,y)
model = SelectFromModel(extratrees, prefit=True)
X_new = model.transform(X)
nbfeatures = X_new.shape[1]

X_train, X_test, y_train, y_test = train_test_split(X_new, y, test_size = 0.2)

features = []
index = numpy.argsort(extratrees.feature_importances_)[::-1][:nbfeatures]

for f in range(nbfeatures):
    print("%d. feature %s (%f)" % (f + 1, dataset.columns[2+index[f]], extratrees.feature_importances_[index[f]]))
    features.append(dataset.columns[2+index[f]])

model = { #"DecisionTree":tree.DecisionTreeClassifier(max_depth=10),
         "RandomForest":ek.RandomForestClassifier(n_estimators=50),
         #"Adaboost":ek.AdaBoostClassifier(n_estimators=50),
         #"GradientBoosting":ek.GradientBoostingClassifier(n_estimators=50),
         #"GNB":GaussianNB(),
         #"LinearRegression":LinearRegression()
}
results = {}
for algo in model:
    clf = model[algo]
    clf.fit(X_train,y_train)
    score = clf.score(X_test,y_test)
    print ("%s : %s " %(algo, score))
    results[algo] = score
winner = max(results, key=results.get)
joblib.dump(model[winner],'/manalyze_de/classifier.pkl')
open('/manalyze_de/features.pkl', 'wb').write(pickle.dumps(features))

