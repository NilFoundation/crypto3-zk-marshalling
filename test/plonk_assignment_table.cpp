#define BOOST_TEST_MODULE crypto3_marshalling_plonk_assignment_table_test

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <iomanip>
#include <random>
#include <regex>
#include <fstream>
#include <filesystem>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include "detail/circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::marshalling;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

bool has_argv(std::string name){
    bool result = false;
    for (std::size_t i = 0; i < boost::unit_test::framework::master_test_suite().argc; i++) {
        if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--print") {
            result = true;
        }
    }
    return result;
}

template<typename TIter>
void print_hex_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end, bool endl) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::dec;
    if (endl) {
        os << std::endl;
    }
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
bool are_lookup_constraints_equal(
        const nil::crypto3::zk::snark::plonk_lookup_constraint<Field> &lhs,
        const nil::crypto3::zk::snark::plonk_lookup_constraint<Field> &rhs) {
    if (lhs.lookup_input.size() != rhs.lookup_input.size()) return false;
    for (size_t i = 0; i < lhs.lookup_input.size(); i++) {
        if (lhs.lookup_input[i] != rhs.lookup_input[i]) return false;
    }

    if( lhs.table_id != rhs.table_id ) return false;

    return true;
}

template<typename Field>
bool are_plonk_lookup_gates_equal(
        const nil::crypto3::zk::snark::plonk_lookup_gate<Field, nil::crypto3::zk::snark::plonk_lookup_constraint<Field, nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>>> &lhs,
        const nil::crypto3::zk::snark::plonk_lookup_gate<Field, nil::crypto3::zk::snark::plonk_lookup_constraint<Field, nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>>> &rhs) {
    if (lhs.tag_index != rhs.tag_index)
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

    if (s1.lookup_gates().size() != s2.lookup_gates().size()) return false;
    for (size_t i = 0; i < s1.lookup_gates().size(); i++) {
        if (!are_plonk_lookup_gates_equal(s1.lookup_gates()[i], s2.lookup_gates()[i])) return false;
    }

    if(s1.lookup_tables() != s2.lookup_tables()) return false;
    return true;
}

template<typename Endianness, typename PlonkTable>
void test_assignment_table(std::size_t usable_rows, PlonkTable val, std::string folder_name = "") {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using value_marshalling_type = nil::crypto3::marshalling::types::plonk_assignment_table<TTypeBase, PlonkTable>;
    std::size_t _usable_rows;

    auto filled_val = nil::crypto3::marshalling::types::fill_assignment_table<Endianness, PlonkTable>(usable_rows, val);
    PlonkTable _val;
    std::tie(_usable_rows, _val) = types::make_assignment_table<Endianness, PlonkTable>(filled_val);
    BOOST_CHECK(val == _val);
    BOOST_CHECK(usable_rows == _usable_rows);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    PlonkTable constructed_val_read;
    std::tie(_usable_rows, constructed_val_read) = types::make_assignment_table<Endianness, PlonkTable>(test_val_read);

    BOOST_CHECK(val == constructed_val_read);
    BOOST_CHECK(usable_rows == _usable_rows);

    if(folder_name != "") {
        std::filesystem::create_directory(folder_name);
        std::ofstream out;
        out.open(folder_name + "/assignment.tbl");
        out << "0x";
        print_hex_byteblob(out, cv.begin(), cv.end(), false);
        out.close();
    }
}

// *******************************************************************************
// * Randomness setup
// *******************************************************************************/
using dist_type = std::uniform_int_distribution<int>;
std::size_t test_global_seed = 0;
boost::random::mt11213b test_global_rnd_engine;
template<typename FieldType>
nil::crypto3::random::algebraic_engine<FieldType> test_global_alg_rnd_engine;

struct test_initializer {
    // Enumerate all fields used in tests;
    using field1_type = algebra::curves::pallas::base_field_type;

    test_initializer() {
        test_global_seed = 0;

        for (std::size_t i = 0; i < boost::unit_test::framework::master_test_suite().argc - 1; i++) {
            if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--seed") {
                if (std::string(boost::unit_test::framework::master_test_suite().argv[i + 1]) == "random") {
                    std::random_device rd;
                    test_global_seed = rd();
                    std::cout << "Random seed = " << test_global_seed << std::endl;
                    break;
                }
                if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                     std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                    test_global_seed = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                    break;
                }
            }
        }

        BOOST_TEST_MESSAGE("test_global_seed = " << test_global_seed);
        test_global_rnd_engine = boost::random::mt11213b(test_global_seed);
        test_global_alg_rnd_engine<field1_type> = nil::crypto3::random::algebraic_engine<field1_type>(test_global_seed);
    }

    void setup() {
    }

    void teardown() {
    }

    ~test_initializer() {
    }
};

BOOST_AUTO_TEST_SUITE(placeholder_circuit1)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;
    constexpr static const std::size_t table_rows_log = 4;

    struct placeholder_test_params {
        constexpr static const std::size_t table_rows = 1 << table_rows_log;
        constexpr static const std::size_t permutation_size = 4;
        constexpr static const std::size_t usable_rows = (1 << table_rows_log) - 3;


        constexpr static const std::size_t witness_columns = witness_columns_1;
        constexpr static const std::size_t public_input_columns = public_columns_1;
        constexpr static const std::size_t constant_columns = constant_columns_1;
        constexpr static const std::size_t selector_columns = selector_columns_1;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };
    typedef placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        placeholder_test_params::lambda,
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

BOOST_FIXTURE_TEST_CASE(assignment_table_marshalling_test, test_initializer) {
    auto circuit = circuit_test_1<field_type>();

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = placeholder_test_params::table_rows;
    desc.usable_rows_amount = placeholder_test_params::usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    if(has_argv("--print"))
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments, "circuit1");
    else
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit2)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

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
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<
        field_type,
        typename placeholder_test_params::arithmetization_params
    >;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::lambda,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_t_params>;

BOOST_FIXTURE_TEST_CASE(assignment_table_marshalling_test, test_initializer) {
    auto pi0 = nil::crypto3::algebra::random_element<field_type>();
    auto circuit = circuit_test_t<field_type>(pi0, test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type, typename circuit_t_params::arithmetization_params> desc;
    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    if(has_argv("--print"))
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments, "circuit2");
    else
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit3)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 4;
    constexpr static const std::size_t usable_rows = 4;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_3;
        constexpr static const std::size_t public_input_columns = public_columns_3;
        constexpr static const std::size_t constant_columns = constant_columns_3;
        constexpr static const std::size_t selector_columns = selector_columns_3;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::lambda,
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(assignment_table_marshalling_test, test_initializer) {
    auto circuit = circuit_test_3<field_type>();

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    if(has_argv("--print"))
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments, "circuit3");
    else
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments);
}
BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(placeholder_circuit4)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 4;
    constexpr static const std::size_t usable_rows = 5;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_4;
        constexpr static const std::size_t public_input_columns = public_columns_4;
        constexpr static const std::size_t constant_columns = constant_columns_4;
        constexpr static const std::size_t selector_columns = selector_columns_4;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::lambda,
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(assignment_table_marshalling_test, test_initializer) {
    auto circuit = circuit_test_4<field_type>();

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    if(has_argv("--print"))
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments, "circuit4");
    else
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments);
}
BOOST_AUTO_TEST_SUITE_END()

#if 0
BOOST_AUTO_TEST_SUITE(placeholder_circuit5)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    constexpr static const std::size_t table_rows_log = 4;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 4;
    constexpr static const std::size_t usable_rows = (1 << table_rows_log) - 3;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = 3;
        constexpr static const std::size_t public_input_columns = 2;
        constexpr static const std::size_t constant_columns = 0;
        constexpr static const std::size_t selector_columns = 2;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<
        field_type,
        typename placeholder_test_params::arithmetization_params
    >;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::lambda,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_t_params>;

BOOST_FIXTURE_TEST_CASE(assignment_table_marshalling_test, test_initializer) {
    auto pi0 = nil::crypto3::algebra::random_element<field_type>();
    auto pi1 = nil::crypto3::algebra::random_element<field_type>();
    auto circuit = circuit_test_t<field_type>(pi0, pi1);

    plonk_table_description<field_type, typename circuit_t_params::arithmetization_params> desc;
    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    if(has_argv("--print"))
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments, "circuit5");
    else
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments);
}
BOOST_AUTO_TEST_SUITE_END()
#endif

BOOST_AUTO_TEST_SUITE(placeholder_circuit6)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 3;
    constexpr static const std::size_t usable_rows = 6;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_6;
        constexpr static const std::size_t public_input_columns = public_columns_6;
        constexpr static const std::size_t constant_columns = constant_columns_6;
        constexpr static const std::size_t selector_columns = selector_columns_6;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::lambda,
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(assignment_table_marshalling_test, test_initializer) {
    auto circuit = circuit_test_6<field_type>();

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;
    if(has_argv("--print"))
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments, "circuit6");
    else
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit7)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 4;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 3;
    constexpr static const std::size_t usable_rows = 14;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_7;
        constexpr static const std::size_t public_input_columns = public_columns_7;
        constexpr static const std::size_t constant_columns = constant_columns_7;
        constexpr static const std::size_t selector_columns = selector_columns_7;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::lambda,
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(assignment_table_marshalling_test, test_initializer) {
    auto circuit = circuit_test_7<field_type>();
    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    if(has_argv("--print"))
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments, "circuit7");
    else
        test_assignment_table<Endianness, typename policy_type::variable_assignment_type>(desc.usable_rows_amount, assignments);
}
BOOST_AUTO_TEST_SUITE_END()
