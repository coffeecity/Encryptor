# DO NOT DELETE OR Encryptor (Ultimate).py WON'T WORK

def av(): #adverb_list = [word for word, tag in pos_tag(word_list) if tag.startswith("RB")
    from nltk.corpus import brown
    from nltk import pos_tag
    from collections import Counter
    import pickle

    # Get words from Brown corpus & tag
    wf = Counter(brown.words())
    wl = brown.words()  # Get a list of words
    av_ls = [word for word, tag in pos_tag(wl) if tag.startswith("RB") and len(word) > 6 and wf[word] > 5]  # Tag words with part of speech (POS)

    # Cache av list for next time
    with open("av.pkl", "wb") as f:
        pickle.dump(av_ls, f)

    return av_ls


def v():
    from nltk.corpus import brown
    from nltk import pos_tag
    from collections import Counter
    import pickle

    # Get words from Brown corpus & tag
    wf = Counter(brown.words())
    wl = brown.words()  # Get a list of words
    v_ls = [word for word, tag in pos_tag(wl) if tag.startswith("VB") and len(word) > 6 and wf[word] > 5] # Tag words with part of speech (POS)

    # Cache noun list for next time
    with open("v.pkl", "wb") as f:
        pickle.dump(v_ls, f)

    return v_ls

def aj():
    from nltk.corpus import brown
    from nltk import pos_tag
    from collections import Counter
    import pickle

    # Get words from Brown corpus & tag
    wf = Counter(brown.words())
    wl = brown.words()  # Get a list of words
    aj_ls = [word for word, tag in pos_tag(wl) if tag.startswith("JJ") and len(word) > 6 and wf[word] > 5] # Tag words with part of speech (POS)

    # Cache noun list for next time
    with open("aj.pkl", "wb") as f:
        pickle.dump(aj_ls, f)

    return aj_ls

def n():
    from nltk.corpus import brown
    from nltk import pos_tag
    from collections import Counter
    import pickle

    # Get words from Brown corpus & tag
    wf = Counter(brown.words())
    wl = brown.words()  # Get a list of words
    n_ls = [word for word, tag in pos_tag(wl) if tag.startswith("NN") and len(word) > 6 and wf[word] > 5]  # Tag words with part of speech (POS)

    # Cache noun list for next time
    with open("n.pkl", "wb") as f:
        pickle.dump(n_ls, f)

    return n_ls
