#define BOOST_TEST_MODULE crypto3_marshalling_plonk_constraint_system_test

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <iomanip>
#include <random>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/math/expression.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>

#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>
#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/copy_constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include "detail/circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::marshalling;

template<typename Field>
bool are_lookup_constraints_equal(
    const nil::crypto3::zk::snark::plonk_lookup_constraint<Field> &lhs,
    const nil::crypto3::zk::snark::plonk_lookup_constraint<Field> &rhs
){
    if(lhs.lookup_input.size() != rhs.lookup_input.size() ) return false;
    for( size_t i = 0; i < lhs.lookup_input.size(); i++ ){
        if(lhs.lookup_input[i] != rhs.lookup_input[i]) return false;
    }

    if(lhs.lookup_value.size() != rhs.lookup_value.size() ) return false;
    for( size_t i = 0; i < lhs.lookup_value.size(); i++ ){
        if(lhs.lookup_value[i] != rhs.lookup_value[i]) return false;
    }
    return true;
}

template<typename Field>
bool are_plonk_gates_equal(
        const nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_constraint<Field, nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>>> &lhs,
        const nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_constraint<Field, nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>>> &rhs) {
    if (lhs.selector_index != rhs.selector_index)
        return false;
    if (lhs.constraints.size() != rhs.constraints.size())
        return false;
    for (auto i = 0; i < lhs.constraints.size(); i++) {
        if (lhs.constraints[i] != rhs.constraints[i])
            return false;
    }
    return true;
}

template<typename Field>
bool are_plonk_lookup_gates_equal(
    const nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_lookup_constraint<Field, nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>>> &lhs,
    const nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_lookup_constraint<Field, nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>>> &rhs
) {
    if (lhs.selector_index != rhs.selector_index)
        return false;
    if (lhs.constraints.size() != rhs.constraints.size())
        return false;
    for (auto i = 0; i < lhs.constraints.size(); i++) {
        if (!are_lookup_constraints_equal<Field>(lhs.constraints[i], rhs.constraints[i]))
            return false;
    }
    return true;
}

template<typename ConstraintSystem>
bool are_constraint_systems_equal(const ConstraintSystem &s1, const ConstraintSystem &s2) {
    if (s1.gates().size() != s2.gates().size()) return false;
    for (size_t i = 0; i < s1.gates().size(); i++) {
        if (!are_plonk_gates_equal(s1.gates()[i], s2.gates()[i])) return false;
    }

    if (s1.copy_constraints().size() != s2.copy_constraints().size()) return false;
    for (size_t i = 0; i < s1.copy_constraints().size(); i++) {
        if (std::get<0>(s1.copy_constraints()[i]) != std::get<0>(s2.copy_constraints()[i])) return false;
        if (std::get<1>(s1.copy_constraints()[i]) != std::get<1>(s2.copy_constraints()[i])) return false;
    }

    // TODO check lookup gates are equal
    if (s1.lookup_gates().size() != s2.lookup_gates().size())return false;
    for (size_t i = 0; i < s1.lookup_gates().size(); i++) {
    }

    return true;
}

template<typename ConstraintSystem, typename Endianness>
void test_constraint_system(ConstraintSystem val) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using value_marshalling_type = nil::crypto3::marshalling::types::plonk_constraint_system<TTypeBase, ConstraintSystem>;

    auto filled_val = nil::crypto3::marshalling::types::fill_plonk_constraint_system<ConstraintSystem, Endianness>(val);
    auto _val = types::make_plonk_constraint_system<ConstraintSystem, Endianness>(filled_val);
    BOOST_CHECK(are_constraint_systems_equal<ConstraintSystem>(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_constraint_system<ConstraintSystem, Endianness>(test_val_read);

    BOOST_CHECK(are_constraint_systems_equal<ConstraintSystem>(val, constructed_val_read));
}

// lpc params
constexpr static const std::size_t m = 2;

constexpr static const std::size_t table_rows_log = 4;
constexpr static const std::size_t table_rows = 1 << table_rows_log;
constexpr static const std::size_t permutation_size = 4;
constexpr static const std::size_t usable_rows = (1 << table_rows_log) - 3;

struct placeholder_test_params {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 2;

    using arithmetization_params =
            nil::crypto3::zk::snark::plonk_arithmetization_params<
                    witness_columns,
                    public_input_columns,
                    constant_columns,
                    selector_columns
            >;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

struct placeholder_test_params_lookups {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 0;
    constexpr static const std::size_t constant_columns = 3;
    constexpr static const std::size_t selector_columns = 1;

    using arithmetization_params =
            nil::crypto3::zk::snark::plonk_arithmetization_params<
                    witness_columns,
                    public_input_columns,
                    constant_columns,
                    selector_columns
            >;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

BOOST_AUTO_TEST_SUITE(plonk_constraint_system_marshalling_test_suite)

    BOOST_AUTO_TEST_CASE(circuit_3_test) {
        using endianness = nil::marshalling::option::big_endian;
        using TTypeBase = nil::marshalling::field_type<endianness>;

        using curve_type = nil::crypto3::algebra::curves::pallas;
        using FieldType = typename curve_type::base_field_type;
        using VariableType = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

        using circuit_2_params = nil::crypto3::zk::snark::placeholder_params<
                FieldType,
                typename placeholder_test_params::arithmetization_params
        >;
        using circuit_3_params = nil::crypto3::zk::snark::placeholder_params<
                FieldType,
                typename placeholder_test_params_lookups::arithmetization_params
        >;


        using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_3_params>;

        nil::crypto3::zk::snark::circuit_description<FieldType, circuit_3_params, table_rows_log, 3> circuit =
                nil::crypto3::zk::snark::circuit_test_3<FieldType>();

//    using constraint_system_type = typename nil::crypto3::zk::snark::plonk_constraint_system<
//        FieldType,
//        placeholder_test_params_lookups::arithmetization_params
//    >;

        using constraint_system_type = typename policy_type::constraint_system_type;
        constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                 circuit.lookup_gates);

        test_constraint_system<constraint_system_type, endianness>(constraint_system);
    }

    BOOST_AUTO_TEST_CASE(circuit_2_test) {
        using endianness = nil::marshalling::option::big_endian;
        using TTypeBase = nil::marshalling::field_type<endianness>;

        using curve_type = nil::crypto3::algebra::curves::pallas;
        using FieldType = typename curve_type::base_field_type;
        using VariableType = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

        using circuit_2_params = nil::crypto3::zk::snark::placeholder_params<
                FieldType,
                typename placeholder_test_params::arithmetization_params
        >;

        using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_2_params>;

        nil::crypto3::zk::snark::circuit_description<FieldType, circuit_2_params, table_rows_log, 4> circuit =
                nil::crypto3::zk::snark::circuit_test_2<FieldType>();

//    using constraint_system_type = typename nil::crypto3::zk::snark::plonk_constraint_system<
//        FieldType,
//        placeholder_test_params_lookups::arithmetization_params
//    >;

        using constraint_system_type = typename policy_type::constraint_system_type;
        constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                 circuit.lookup_gates);

        test_constraint_system<constraint_system_type, endianness>(constraint_system);
    }

BOOST_AUTO_TEST_SUITE_END()
