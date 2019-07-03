from hvm.utils.padding import propogate_timestamp_item_list_to_present


def test_propogate_timestamp_item_list_to_present_1():
    test_data = [[100,1], [200,1],[300,1],[400,1],[500,2]]

    fixed_data = propogate_timestamp_item_list_to_present(test_data, 100, 900)

    print(fixed_data)

# test_propogate_timestamp_item_list_to_present_1()


def test_propogate_timestamp_item_list_to_present_2():
    test_data = [[100,1]]

    fixed_data = propogate_timestamp_item_list_to_present(test_data, 100, 900)

    print(fixed_data)

# test_propogate_timestamp_item_list_to_present_2()