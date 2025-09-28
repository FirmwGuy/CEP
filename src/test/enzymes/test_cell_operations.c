/* To the extent possible under law, the authors have dedicated this
 * work to the public domain by waiving all rights to the work worldwide
 * under CC0 1.0. You can copy, modify, distribute, and perform this work,
 * even for commercial purposes, without asking permission.
 * See https://creativecommons.org/publicdomain/zero/1.0/. */

/* Verify the enzyme registration for cell operations exposes the expected
   descriptors so higher level tests can rely on the catalogue being complete. */


#include "test.h"
#include "cep_enzyme.h"
#include "../../enzymes/cep_cell_operations.h"

#include <stddef.h>


typedef struct {
    unsigned length;
    unsigned capacity;
    cepPast  past[2];
} CepPathStatic2;

static const cepPath* make_signal_path(CepPathStatic2* buf, const cepDT* segments, size_t count) {
    buf->length = (unsigned)count;
    buf->capacity = 2u;
    for (size_t i = 0; i < count; ++i) {
        buf->past[i].dt = segments[i];
        buf->past[i].timestamp = 0u;
    }
    return (const cepPath*)buf;
}

static const cepDT* dt_sig_cell(void) { return CEP_DTAW("CEP", "sig_cell"); }
static const cepDT* dt_op_add(void)   { return CEP_DTAW("CEP", "op_add"); }
static const cepDT* dt_op_update(void){ return CEP_DTAW("CEP", "op_upd"); }
static const cepDT* dt_op_delete(void){ return CEP_DTAW("CEP", "op_delete"); }
static const cepDT* dt_op_move(void)  { return CEP_DTAW("CEP", "op_move"); }
static const cepDT* dt_op_clone(void) { return CEP_DTAW("CEP", "op_clone"); }

MunitResult test_cell_operations_enzymes(const MunitParameter params[], void* user_data_or_fixture) {
    (void)params;
    (void)user_data_or_fixture;

    cep_cell_system_initiate();

    cepEnzymeRegistry* registry = cep_enzyme_registry_create();
    munit_assert_not_null(registry);

    munit_assert_true(cep_cell_operations_register(registry));
    cep_enzyme_registry_activate_pending(registry);

    size_t registered = cep_enzyme_registry_size(registry);
    munit_assert_size(registered, ==, 5u);

    const struct {
        const cepDT* segments[2];
        const char*  label;
    } expectations[] = {
        {{ dt_sig_cell(), dt_op_add()    }, "cell.add"   },
        {{ dt_sig_cell(), dt_op_update() }, "cell.update"},
        {{ dt_sig_cell(), dt_op_delete() }, "cell.delete"},
        {{ dt_sig_cell(), dt_op_move()   }, "cell.move"  },
        {{ dt_sig_cell(), dt_op_clone()  }, "cell.clone" },
    };

    for (size_t i = 0; i < cep_lengthof(expectations); ++i) {
        CepPathStatic2 path_buf = {0};
        const cepDT segments[2] = { *expectations[i].segments[0], *expectations[i].segments[1] };
        const cepPath* signal_path = make_signal_path(&path_buf, segments, 2u);
        cepImpulse impulse = {
            .signal_path = signal_path,
            .target_path = NULL,
        };
        const cepEnzymeDescriptor* resolved[1] = {0};
        size_t found = cep_enzyme_resolve(registry, &impulse, resolved, cep_lengthof(resolved));
        munit_assert_size(found, ==, 1u);
        munit_assert_not_null(resolved[0]);
        munit_assert_string_equal(resolved[0]->label, expectations[i].label);
        munit_assert_int(resolved[0]->match, ==, CEP_ENZYME_MATCH_EXACT);
    }

    cep_enzyme_registry_destroy(registry);
    cep_cell_system_shutdown();
    return MUNIT_OK;
}
