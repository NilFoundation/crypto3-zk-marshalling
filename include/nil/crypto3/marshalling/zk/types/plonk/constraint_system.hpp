//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_SYSTEM_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_SYSTEM_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/copy_constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/lookup_constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/lookup_gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/lookup_table.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename PlonkConstraintSystem>
                using plonk_constraint_system = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                        plonk_gates< TTypeBase, typename PlonkConstraintSystem::gates_container_type::value_type >, // gates
                        plonk_copy_constraints< TTypeBase, typename PlonkConstraintSystem::variable_type >,              // copy constraints
                        plonk_lookup_gates< TTypeBase, typename PlonkConstraintSystem::lookup_gates_container_type::value_type >,  // lookup constraints
                        // If we don't have lookup gates, we don't need lookup tables
                        plonk_lookup_tables< TTypeBase, typename PlonkConstraintSystem::lookup_tables_type::value_type >  // lookup tables
                    >
                >;

                template<typename Endianness, typename PlonkConstraintSystem>
                plonk_constraint_system<nil::marshalling::field_type<Endianness>, PlonkConstraintSystem>
                fill_plonk_constraint_system(const PlonkConstraintSystem &system) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = plonk_constraint_system<nil::marshalling::field_type<Endianness>, PlonkConstraintSystem>;

                    return result_type(std::make_tuple(
                        fill_plonk_gates<Endianness, typename PlonkConstraintSystem::gates_container_type::value_type>(system.gates()),
                        fill_plonk_copy_constraints<Endianness, typename PlonkConstraintSystem::variable_type>(system.copy_constraints()),
                        fill_plonk_lookup_gates<Endianness, typename PlonkConstraintSystem::lookup_gates_container_type::value_type>(system.lookup_gates()),
                        fill_plonk_lookup_tables<Endianness, typename PlonkConstraintSystem::lookup_tables_type::value_type>(system.lookup_tables())
                    ));
                }

                template<typename Endianness, typename PlonkConstraintSystem>
                PlonkConstraintSystem
                make_plonk_constraint_system(
                    const plonk_constraint_system<nil::marshalling::field_type<Endianness>, PlonkConstraintSystem> &filled_system
                ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    return PlonkConstraintSystem(
                        make_plonk_gates<Endianness, typename PlonkConstraintSystem::gates_container_type::value_type>(std::get<0>(filled_system.value())),
                        make_plonk_copy_constraints<Endianness, typename PlonkConstraintSystem::variable_type>(std::get<1>(filled_system.value())),
                        make_plonk_lookup_gates<Endianness, typename PlonkConstraintSystem::lookup_gates_container_type::value_type>(std::get<2>(filled_system.value())),
                        make_plonk_lookup_tables<Endianness, typename PlonkConstraintSystem::lookup_tables_type::value_type>(std::get<3>(filled_system.value()))
                    );
                }
            } //namespace types
        } // namespace marshalling
    } // namespace crypto3
} // namespace nil

#endif
