"""Every stats.py function against hand-computed values, plus degenerate
inputs (empty, single sample, all-identical)."""
from __future__ import annotations

import math

import pytest

from netaudit.threat import stats


class TestCoefficientOfVariation:
    def test_hand_computed(self):
        # mean=10, population stdev = sqrt(((8-10)^2+(10-10)^2+(12-10)^2)/3) = sqrt(8/3) = 1.633
        cv = stats.coefficient_of_variation([8, 10, 12])
        assert cv == pytest.approx(1.6329931618554518 / 10)

    def test_empty(self):
        assert stats.coefficient_of_variation([]) is None

    def test_single_sample(self):
        assert stats.coefficient_of_variation([5.0]) is None

    def test_all_identical(self):
        # stdev is 0, mean is nonzero -> CV is exactly 0.0, not None
        assert stats.coefficient_of_variation([4.0, 4.0, 4.0]) == 0.0

    def test_zero_mean(self):
        assert stats.coefficient_of_variation([-1.0, 1.0]) is None


class TestInterArrivalTimes:
    def test_hand_computed_unsorted_input(self):
        assert stats.inter_arrival_times([0, 30, 10, 20]) == [10, 10, 10]

    def test_empty(self):
        assert stats.inter_arrival_times([]) == []

    def test_single(self):
        assert stats.inter_arrival_times([5.0]) == []


class TestShannonEntropy:
    def test_empty(self):
        assert stats.shannon_entropy("") == 0.0

    def test_single_char_repeated_is_zero(self):
        assert stats.shannon_entropy("aaaa") == 0.0

    def test_two_equal_symbols_is_one_bit(self):
        assert math.isclose(stats.shannon_entropy("ab"), 1.0)

    def test_four_equal_symbols_is_two_bits(self):
        assert math.isclose(stats.shannon_entropy("abcd"), 2.0)


class TestLongestConsonantRun:
    def test_empty(self):
        assert stats.longest_consonant_run("") == 0

    def test_all_vowels(self):
        assert stats.longest_consonant_run("aeiou") == 0

    def test_hand_computed(self):
        assert stats.longest_consonant_run("xkqzbrjmthq") == 11  # all consonants
        assert stats.longest_consonant_run("google") == 2  # 'gl' at most

    def test_case_insensitive(self):
        assert stats.longest_consonant_run("XKQZ") == 4


class TestDigitRatio:
    def test_empty(self):
        assert stats.digit_ratio("") == 0.0

    def test_hand_computed(self):
        assert stats.digit_ratio("a1b2") == 0.5

    def test_no_digits(self):
        assert stats.digit_ratio("abcd") == 0.0


class TestUniqueCharRatio:
    def test_empty(self):
        assert stats.unique_char_ratio("") == 0.0

    def test_all_unique(self):
        assert stats.unique_char_ratio("abcd") == 1.0

    def test_all_same(self):
        assert stats.unique_char_ratio("aaaa") == 0.25


class TestEwma:
    def test_empty(self):
        assert stats.ewma([]) == []

    def test_single(self):
        assert stats.ewma([5.0]) == [5.0]

    def test_hand_computed(self):
        out = stats.ewma([10.0, 20.0], alpha=0.5)
        assert out[0] == 10.0
        assert out[1] == 15.0

    def test_update_seeds_from_none(self):
        assert stats.ewma_update(None, 42.0) == 42.0

    def test_update_hand_computed(self):
        assert stats.ewma_update(10.0, 20.0, alpha=0.5) == 15.0


class TestMedianAndMad:
    def test_median_empty(self):
        assert stats.median([]) == 0.0

    def test_median_odd(self):
        assert stats.median([1, 3, 2]) == 2

    def test_median_even(self):
        assert stats.median([1, 2, 3, 4]) == 2.5

    def test_mad_empty(self):
        assert stats.mad([]) == 0.0

    def test_mad_hand_computed(self):
        # median=3, deviations=[2,1,0,1,2], median of that = 1
        assert stats.mad([1, 2, 3, 4, 5]) == 1


class TestModifiedZscoresAndOutliers:
    def test_empty(self):
        assert stats.modified_zscores([]) == []

    def test_all_identical_gives_zero_not_error(self):
        assert stats.modified_zscores([5, 5, 5]) == [0.0, 0.0, 0.0]

    def test_outlier_detected(self):
        values = [10, 11, 9, 10, 11, 9, 500]
        flags = stats.mad_outliers(values)
        assert flags[-1] is True
        assert all(f is False for f in flags[:-1])

    def test_no_outliers_when_identical(self):
        assert stats.mad_outliers([5, 5, 5]) == [False, False, False]


class TestZscore:
    def test_hand_computed(self):
        population = [8, 10, 12]  # mean 10, pstdev sqrt(8/3)
        z = stats.zscore(10, population)
        assert z == pytest.approx(0.0)

    def test_insufficient_population(self):
        assert stats.zscore(5.0, [1.0]) is None

    def test_zero_variance_population(self):
        assert stats.zscore(5.0, [4.0, 4.0, 4.0]) is None


class TestPayloadUniformity:
    def test_perfectly_uniform(self):
        u = stats.payload_uniformity([100.0, 100.0, 100.0])
        assert u == 1.0

    def test_empty_or_single_is_none(self):
        assert stats.payload_uniformity([]) is None
        assert stats.payload_uniformity([1.0]) is None

    def test_high_variance_is_low_uniformity(self):
        u = stats.payload_uniformity([1.0] * 19 + [1000000.0])
        assert u < 0.2


class TestUniqueRatio:
    def test_empty(self):
        assert stats.unique_ratio([]) == 0.0

    def test_hand_computed(self):
        assert stats.unique_ratio([1, 1, 2, 3]) == 0.75


class TestSafeRatio:
    def test_zero_denominator(self):
        assert stats.safe_ratio(5, 0) == 0.0

    def test_hand_computed(self):
        assert stats.safe_ratio(3, 6) == 0.5
