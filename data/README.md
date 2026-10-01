# Data

`urls.csv` holds 11,430 URLs labelled `phishing` or `legitimate` (5,715 each).

It comes from the dataset *Web page phishing detection* by Abdelhakim Hannousse
and Salima Yahiouche, Mendeley Data, version 3 (2020),
[doi:10.17632/c2gw7fy2j4.3](https://doi.org/10.17632/c2gw7fy2j4.3), licensed
under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). It is
described in: A. Hannousse and S. Yahiouche, "Towards benchmark datasets for
machine learning based website phishing detection: An experimental study",
*Engineering Applications of Artificial Intelligence*, 2021.

**Changes made:** only the `url` and `status` columns of
`dataset_B_05_2020.csv` (SHA-256
`21093e2902e5441c86a6daf95e86e7c332046e477fdf109a579d7bd81e586d6c`) are kept;
the 87 precomputed features, many of which need the web page or third-party
services, are dropped. Version 1 of this project used the same file through its
Kaggle mirror.

The phishing URLs were live phishing pages in 2020. Treat them as text: do not
open them.
