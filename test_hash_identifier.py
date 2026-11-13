from hash_identifier import PREFIX_RULES, identify


def test_md5_ranked_first():
    candidates = identify("5f4dcc3b5aa765d61d8327deb882cf99")
    assert candidates[0].algorithm == "MD5"
    assert candidates[0].confidence == "medium"
    assert len(candidates) == 4


def test_sha256_ranked_first():
    candidates = identify(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert candidates[0].algorithm == "SHA-256"
    assert candidates[0].confidence == "medium"


def test_bcrypt_high():
    candidates = identify(
        "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"
    )
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].confidence == "high"


def test_unknown_returns_empty():
    assert identify("helloworld") == []


def test_every_prefix_rule_recognized():
    for prefix, algorithm, note in PREFIX_RULES:
        candidates = identify(prefix + "abcdefgh")
        assert candidates, f"no match for {prefix}"
        assert candidates[0].algorithm == algorithm
        assert candidates[0].confidence == "high"


def main():
    test_md5_ranked_first()
    test_sha256_ranked_first()
    test_bcrypt_high()
    test_unknown_returns_empty()
    test_every_prefix_rule_recognized()
    print("All tests passed.")


if __name__ == "__main__":
    main()
