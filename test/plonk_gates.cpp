//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE crypto3_marshalling_plonk_gates_test

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <iomanip>
#include <random>
#include <experimental/random>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/math/variable.hpp>
#include <nil/crypto3/marshalling/zk/types/math/non_linear_term.hpp>
#include <nil/crypto3/marshalling/zk/types/math/non_linear_combination.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::dec << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp2<FieldParams> &e) {
    os << "[" << e.data[0].data << "," << e.data[1].data << "]" << std::endl;
}

template<typename Field>
bool are_variables_equal(const nil::crypto3::zk::snark::plonk_variable<Field> &lhs,
                         const nil::crypto3::zk::snark::plonk_variable<Field> &rhs) {
    if (lhs.index != rhs.index)
        return false;
    if (lhs.relative != rhs.relative)
        return false;
    if (lhs.rotation != rhs.rotation)
        return false;
    if (lhs.type != rhs.type)
        return false;
    return true;
}

template<typename Field>
bool are_non_linear_terms_equal(
    const nil::crypto3::math::non_linear_term<nil::crypto3::zk::snark::plonk_variable<Field>> &lhs,
    const nil::crypto3::math::non_linear_term<nil::crypto3::zk::snark::plonk_variable<Field>> &rhs) {
    if (lhs.coeff != rhs.coeff) {
        return false;
    }
    if (lhs.vars.size() != rhs.vars.size()) {
        return false;
    }
    for (auto i = 0; i < lhs.vars.size(); i++) {
        if (!are_variables_equal(lhs.vars[i], rhs.vars[i])) {
            return false;
        }
    }
    return true;
}

template<typename Field>
bool are_non_linear_combinations_equal(
    const nil::crypto3::math::non_linear_combination<nil::crypto3::zk::snark::plonk_variable<Field>> &lhs,
    const nil::crypto3::math::non_linear_combination<nil::crypto3::zk::snark::plonk_variable<Field>> &rhs) {
    if (lhs.terms.size() != rhs.terms.size())
        return false;
    for (auto i = 0; i < lhs.terms.size(); i++) {
        if (!are_non_linear_terms_equal(lhs.terms[i], rhs.terms[i]))
            return false;
    }
    return true;
}

template<typename Field>
bool are_plonk_gates_equal(const nil::crypto3::zk::snark::plonk_gate<Field> &lhs,
                           const nil::crypto3::zk::snark::plonk_gate<Field> &rhs) {
    if (lhs.selector_index != rhs.selector_index)
        return false;
    if (lhs.constraints.size() != rhs.constraints.size())
        return false;
    for (auto i = 0; i < lhs.constraints.size(); i++) {
        if (!are_non_linear_combinations_equal(lhs.constraints[i], rhs.constraints[i]))
            return false;
    }
    return true;
}

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
    generate_random_data(std::size_t leaf_number) {
    std::random_device rd;
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return rd() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

template<typename PlonkVariable>
PlonkVariable generate_random_plonk_variable() {
    return PlonkVariable(std::random_device()(),
                         std::experimental::randint(int(PlonkVariable::rotation_type::pre_previous),
                                                    int(PlonkVariable::rotation_type::after_next)),
                         std::experimental::randint(0, 1),
                         typename PlonkVariable::column_type(std::experimental::randint(
                             int(PlonkVariable::column_type::witness), int(PlonkVariable::column_type::selector))));
}

template<typename PlonkVariable>
nil::crypto3::math::non_linear_term<PlonkVariable> generate_random_plonk_non_linear_term(std::size_t vars_n) {
    nil::crypto3::math::non_linear_term<PlonkVariable> result;
    nil::crypto3::random::algebraic_random_device<typename PlonkVariable::field_type> d;
    result.coeff = d();
    for (auto i = 0; i < vars_n; i++) {
        result.vars.emplace_back(generate_random_plonk_variable<PlonkVariable>());
    }
    return result;
}

template<typename PlonkVariable>
nil::crypto3::math::non_linear_combination<PlonkVariable>
    generate_random_plonk_non_linear_combination(std::size_t vars_n, std::size_t terms_n) {
    nil::crypto3::math::non_linear_combination<PlonkVariable> comb;
    for (auto i = 0; i < terms_n; i++) {
        comb.terms.template emplace_back(generate_random_plonk_non_linear_term<PlonkVariable>(vars_n));
    }
    return comb;
}

template<typename Field>
nil::crypto3::zk::snark::plonk_gate<Field> generate_random_plonk_gate(std::size_t vars_n, std::size_t terms_n,
                                                                      std::size_t constr_n) {
    std::size_t selector_index = std::random_device()();
    std::vector<typename nil::crypto3::zk::snark::plonk_gate<Field>::constraint_type> constraints;
    for (auto i = 0; i < constr_n; i++) {
        constraints.template emplace_back(
            generate_random_plonk_non_linear_combination<nil::crypto3::zk::snark::plonk_variable<Field>>(vars_n,
                                                                                                         terms_n));
    }
    return {selector_index, constraints};
}

template<typename Field, typename Endianness>
void test_plonk_variable() {
    using namespace nil::crypto3::marshalling;

    using value_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_marshalling_type = typename types::variable<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_variable<value_type>();

    auto filled_val = types::fill_variable<value_type, Endianness>(val);
    auto _val = types::make_variable<value_type, Endianness>(filled_val);
    BOOST_CHECK(are_variables_equal(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_variable<value_type, Endianness>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
    BOOST_CHECK(are_variables_equal(val, constructed_val_read));
}

template<typename Field, typename Endianness>
void test_plonk_non_linear_term(std::size_t vars_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_type = nil::crypto3::math::non_linear_term<variable_type>;
    using value_marshalling_type =
        typename types::non_linear_term<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_non_linear_term<variable_type>(vars_n);

    auto filled_val = types::fill_non_linear_term<value_type, Endianness>(val);
    auto _val = types::make_non_linear_term<value_type, Endianness>(filled_val);
    BOOST_CHECK(are_non_linear_terms_equal(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_non_linear_term<value_type, Endianness>(test_val_read);
    BOOST_CHECK(are_non_linear_terms_equal(val, constructed_val_read));
}

template<typename Field, typename Endianness>
void test_non_linear_combination(std::size_t vars_n, std::size_t terms_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_type = nil::crypto3::math::non_linear_combination<variable_type>;
    using value_marshalling_type =
        typename types::non_linear_combination<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_non_linear_combination<variable_type>(vars_n, terms_n);

    auto filled_val = types::fill_non_linear_combination<value_type, Endianness>(val);
    auto _val = types::make_non_linear_combination<value_type, Endianness>(filled_val);
    BOOST_CHECK(are_non_linear_combinations_equal(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_non_linear_combination<value_type, Endianness>(test_val_read);
    BOOST_CHECK(are_non_linear_combinations_equal(val, constructed_val_read));
}

template<typename Field, typename Endianness>
void test_plonk_constraint(std::size_t vars_n, std::size_t terms_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_marshalling_type = types::plonk_constraint<nil::marshalling::field_type<Endianness>, value_type>;

    auto val = value_type(generate_random_plonk_non_linear_combination<variable_type>(vars_n, terms_n));

    auto filled_val = types::fill_plonk_constraint<value_type, Endianness>(val);
    auto _val = types::make_plonk_constraint<value_type, Endianness>(filled_val);
    BOOST_CHECK(are_non_linear_combinations_equal(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_constraint<value_type, Endianness>(test_val_read);
    BOOST_CHECK(are_non_linear_combinations_equal(val, constructed_val_read));
}

template<typename Field, typename Endianness>
void test_plonk_gate(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n) {
    using namespace nil::crypto3::marshalling;

    using value_type = nil::crypto3::zk::snark::plonk_gate<Field>;
    using value_marshalling_type = types::plonk_gate<nil::marshalling::field_type<Endianness>, value_type>;

    auto val = generate_random_plonk_gate<Field>(vars_n, terms_n, constr_n);

    auto filled_val = types::fill_plonk_gate<value_type, Endianness>(val);
    auto _val = types::make_plonk_gate<value_type, Endianness>(filled_val);
    BOOST_CHECK(are_plonk_gates_equal(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_gate<value_type, Endianness>(test_val_read);
    BOOST_CHECK(are_plonk_gates_equal(val, constructed_val_read));
}

template<typename Field, typename Endianness>
void test_plonk_gates(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n, std::size_t gates_n) {
    using namespace nil::crypto3::marshalling;

    using value_type = nil::crypto3::zk::snark::plonk_gate<Field>;
    using value_marshalling_type = types::plonk_gates<nil::marshalling::field_type<Endianness>, value_type>;

    std::vector<value_type> val;
    for (auto i = 0; i < gates_n; i++) {
        val.template emplace_back(generate_random_plonk_gate<Field>(vars_n, terms_n, constr_n));
    }

    auto filled_val = types::fill_plonk_gates<value_type, Endianness>(val);
    auto _val = types::make_plonk_gates<value_type, Endianness>(filled_val);
    BOOST_CHECK(val.size() == _val.size());
    for (auto i = 0; i < val.size(); i++) {
        BOOST_CHECK(are_plonk_gates_equal(val[i], _val[i]));
    }

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_gates<value_type, Endianness>(test_val_read);
    BOOST_CHECK(val.size() == constructed_val_read.size());
    for (auto i = 0; i < val.size(); i++) {
        BOOST_CHECK(are_plonk_gates_equal(val[i], constructed_val_read[i]));
    }
}

BOOST_AUTO_TEST_SUITE(plonk_variable_marshalling_test_suite)

BOOST_AUTO_TEST_CASE(alt_bn128_254_scalar) {
    using curve_type = nil::crypto3::algebra::curves::alt_bn128_254;
    using field_type = typename curve_type::scalar_field_type;
    using endianness = nil::marshalling::option::big_endian;
    for (auto i = 0; i < 100; i++) {
        test_plonk_variable<field_type, endianness>();
    }
    test_plonk_non_linear_term<field_type, endianness>(50);
    test_non_linear_combination<field_type, endianness>(50, 50);
    test_plonk_constraint<field_type, endianness>(50, 50);
    test_plonk_gate<field_type, endianness>(50, 50, 50);
    test_plonk_gates<field_type, endianness>(50, 50, 50, 50);
}

BOOST_AUTO_TEST_SUITE_END()
