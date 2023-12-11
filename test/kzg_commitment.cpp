//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2023 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_kzg_commitment_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <random>
#include <regex>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>

#include "detail/circuits.hpp"

//using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::zk::commitments;

template<typename kzg_type>
typename kzg_type::params_type create_kzg_params(std::size_t degree_log) {
    // TODO: what cases t != d?
    typename kzg_type::field_type::value_type alpha (7);
    std::size_t d = 1 << degree_log;

    typename kzg_type::params_type params(d, d, alpha);
    return params;
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

        for (std::size_t i = 0; i + 1 < boost::unit_test::framework::master_test_suite().argc; i++) {
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

BOOST_TEST_GLOBAL_FIXTURE(test_initializer);

BOOST_AUTO_TEST_SUITE(marshalling_kzg_proof_elements)
    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using transcript_hash_type = hashes::keccak_1600<512>;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;

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

    using kzg_type = zk::commitments::batched_kzg<curve_type, transcript_hash_type>;
    using kzg_scheme_type = typename zk::commitments::kzg_commitment_scheme<kzg_type>;
    using kzg_placeholder_params_type = placeholder_params<circuit_t_params, kzg_scheme_type>;
    using commitment_scheme_params_type = commitment_scheme_params_type<field_type, std::vector<std::uint8_t>>;
    //using commitment_scheme_dummy_type = dummy_commitment_scheme_type<commitment_scheme_params_type, transcript_hash_type>;
    using placeholder_params_type = placeholder_params<circuit_t_params, kzg_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, placeholder_params_type>;

BOOST_AUTO_TEST_CASE(polynomial_test) {
    typename field_type::value_type pi0 = test_global_alg_rnd_engine<field_type>();
    auto circuit = zk::snark::circuit_test_t<field_type>(pi0, test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type, typename circuit_t_params::arithmetization_params> desc;
    
    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;

    std::size_t table_rows_log = 4;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;
    
    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    // KZG commitment scheme
    auto kzg_params = create_kzg_params<kzg_type>(table_rows_log);
    kzg_scheme_type kzg_scheme(kzg_params);

    typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
        kzg_preprocessed_public_data = placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, kzg_scheme, columns_with_copy_constraints.size()
        );

    typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
        kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
        kzg_preprocessed_public_data, kzg_preprocessed_private_data, desc, constraint_system, assignments, kzg_scheme
    );

    bool verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
        kzg_preprocessed_public_data, kzg_proof, constraint_system, kzg_scheme
    );
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_CASE(marshalling_kzg_basic_test) {
    BOOST_TEST(true);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(marshalling_kzg_real_proof)
BOOST_AUTO_TEST_CASE(polynomial_test) {
    BOOST_TEST(true);
}
BOOST_AUTO_TEST_CASE(marshalling_kzg_basic_test) {
    BOOST_TEST(true);
}
BOOST_AUTO_TEST_SUITE_END()

