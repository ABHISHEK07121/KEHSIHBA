import unittest

from scripts.train_email_model import MODEL_PATH, METRICS_PATH, _grouped_split, _normalized_group


class EmailTrainingSplitTests(unittest.TestCase):
    def test_synthetic_baseline_does_not_overwrite_active_email_model(self) -> None:
        self.assertEqual(MODEL_PATH.name, "email_synthetic_baseline.joblib")
        self.assertEqual(METRICS_PATH.name, "email_synthetic_baseline_metrics.json")

    def test_duplicate_email_texts_stay_in_one_split(self) -> None:
        texts = []
        labels = []
        for label in (0, 1):
            for index in range(10):
                text = f" class {label} message {index} "
                texts.extend((text, text.upper()))
                labels.extend((label, label))

        train_indices, test_indices = _grouped_split(texts, labels)
        train_groups = {_normalized_group(texts[index]) for index in train_indices}
        test_groups = {_normalized_group(texts[index]) for index in test_indices}

        self.assertFalse(train_groups & test_groups)
        self.assertEqual({labels[index] for index in train_indices}, {0, 1})
        self.assertEqual({labels[index] for index in test_indices}, {0, 1})


if __name__ == "__main__":
    unittest.main()
