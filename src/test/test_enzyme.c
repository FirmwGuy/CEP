/*
 *  Copyright (c) 2024-2025 Victor M. Barrientos
 *  (https://github.com/FirmwGuy/CEP)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is furnished to do
 *  so.
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */


#include "test.h"


//#include "cep_enzyme.h"
#include <stdio.h>      // getc()
#include <ctype.h>      // isdigit()


#if 0

bool DONE;




static int agent_stdin(cepCell* client, void** returned, cepCell* self, unsigned action, cepCell* cell, cepValue value) {
    assert(client && self);
    static cepCell* inp;

    switch (action) {
      case CEP_ACTION_INSTANCE_NEW: {
        cep_cell_set_data(self, cep_data_new_value(CEP_ACRO("CEP"), CEP_ACRO("FLOAT64"), (cepID)0, (cepID)0, sizeof(double), 0.0));
        cep_cell_set_store(self, cep_store_new(CEP_ACRO("CEP"), CEP_WORD("list"), CEP_STORAGE_LINKED_LIST, CEP_INDEX_BY_NAME));
        return CEP_STATUS_SUCCESS;
      }

      case CEP_ACTION_INSTANCE_INLET: {
        assert_uint64(value.id, ==, CEP_WORD("tic"));
        CEP_PTR_SEC_SET(returned, self);
        return CEP_STATUS_SUCCESS;
      }
      case CEP_ACTION_INSTANCE_CONNECT: {
        assert_uint64(value.id, ==, CEP_WORD("inp"));
        inp = cep_dict_add_link(self, value.id, cell);
        CEP_PTR_SEC_SET(returned, inp);
        return CEP_STATUS_SUCCESS;
      }
      case CEP_ACTION_INSTANCE_UNPLUG: {
        cep_cell_delete_children(self);
        inp = NULL;
        return CEP_STATUS_SUCCESS;
      }

      case CEP_ACTION_DATA_UPDATE: {
      #ifdef _WIN32
        int c = _getchar_nolock();
      #elif __linux__
        int c = getc_unlocked(stdin);
      #endif
        if (EOF != c) {
            if (isdigit(c)) {
                char s[] = {(char) c, 0};
                double d = atof(s);
                cep_instance_data_update(client, inp, sizeof(d), sizeof(d), CEP_V(d));
            } else if ('q' == tolower(c)) {
                DONE = true;
            }
        }
        return CEP_STATUS_SUCCESS;
      }
    }

    return CEP_STATUS_OK;
}



static int agent_adder(cepCell* client, void** returned, cepCell* self, unsigned action, cepCell* cell, cepValue value) {
    assert(client && self);

    static cepCell* num;
    static cepCell* ans;

    switch (action) {
      case CEP_ACTION_INSTANCE_NEW: {
        cep_cell_set_data(self, cep_data_new_value(CEP_ACRO("CEP"), CEP_ACRO("FLOAT64"), (cepID)0, (cepID)0, sizeof(double), 0.0));

        // FixMe! FixMe! FixMe!
        //cep_cell_set_store(self, cep_store_new(CEP_ACRO("CEP"), CEP_WORD("list"), CEP_STORAGE_ARRAY, CEP_INDEX_BY_NAME, 2));
        cep_cell_set_store(self, cep_store_new(CEP_ACRO("CEP"), CEP_WORD("list"), CEP_STORAGE_LINKED_LIST, CEP_INDEX_BY_NAME));
        return CEP_STATUS_SUCCESS;
      }

      case CEP_ACTION_INSTANCE_INLET: {
        assert_uint64(value.id, ==, cep_text_to_word("num"));
        num = cep_dict_add_value(self, value.id, CEP_ACRO("CEP"), CEP_WORD("adder"), (cepID)0, (cepID)0, 0.0, sizeof(double), sizeof(double));
        cep_data_add_agent(num->data, CEP_ACRO("CEP"), CEP_WORD("adder"), cep_heartbeat_agent(CEP_ACRO("CEP"), CEP_WORD("adder")));
        CEP_PTR_SEC_SET(returned, num);
        return CEP_STATUS_SUCCESS;
      }
      case CEP_ACTION_INSTANCE_CONNECT: {
        assert_uint64(value.id, ==, cep_text_to_word("ans"));
        ans = cep_dict_add_link(self, value.id, cell);
        CEP_PTR_SEC_SET(returned, ans);
        return CEP_STATUS_SUCCESS;
      }
      case CEP_ACTION_INSTANCE_UNPLUG: {
        cep_cell_remove_hard(num, NULL);
        num = NULL;
        return CEP_STATUS_SUCCESS;
      }

      case CEP_ACTION_DATA_UPDATE: {
        cepCell* adder = cep_cell_parent(self);
        cep_cell_update_value(num, sizeof(double), value);

        double d = value.float64 + cep_cell_value(adder).float64;

        cep_cell_update_value(adder, sizeof(d), CEP_V(d));
        cep_instance_data_update(client, ans, sizeof(d), sizeof(d), CEP_V(d));
        return CEP_STATUS_SUCCESS;
      }
    }

    return CEP_STATUS_OK;
}




static int agent_stdout(cepCell* client, void** returned, cepCell* self, unsigned action, cepCell* cell, cepValue value) {
    assert(client && self);

    switch (action) {
      case CEP_ACTION_INSTANCE_NEW: {
        cep_cell_set_data(self, cep_data_new_value(CEP_ACRO("CEP"), CEP_ACRO("FLOAT64"), (cepID)0, (cepID)0, sizeof(double), 0.0));
        return CEP_STATUS_SUCCESS;
      }

      case CEP_ACTION_INSTANCE_INLET: {
        assert_uint64(value.id, ==, CEP_ACRO("IN1"));
        CEP_PTR_SEC_SET(returned, self);
        return CEP_STATUS_SUCCESS;
      }

      case CEP_ACTION_DATA_UPDATE: {
        cep_cell_update_value(self, sizeof(value), value);
        printf("%f\n", value.float64);
        return CEP_STATUS_SUCCESS;
      }
    }

    return CEP_STATUS_OK;
}

#endif


void* test_enzyme_setup(const MunitParameter params[], void* user_data) {
  #if 0
    cep_enzyme_register_agent(CEP_WORD("test"), CEP_WORD("stdin"), CEP_WORD("system-step"), agent_stdin);
    cep_enzyme_set_output(CEP_WORD("test"), CEP_WORD("stdin"), CEP_WORD("number"));

    cep_enzyme_register_agent(CEP_WORD("test"), CEP_WORD("adder"), CEP_WORD("operand"), agent_adder);
    cep_enzyme_set_output(CEP_WORD("test"), CEP_WORD("adder"), CEP_WORD("answer"));

    cep_enzyme_register_agent(CEP_WORD("test"), CEP_WORD("stdout"), CEP_WORD("number"), agent_stdout);

    cep_heartbeat_startup();
  #endif
    return NULL;
}


void test_enzyme_tear_down(void* fixture) {
  #if 0
    cep_heartbeat_shutdown();
  #endif
}


MunitResult test_enzyme(const MunitParameter params[], void* user_data_or_fixture) {
  #if 0
    const char* param_value = munit_parameters_get(params, "stdio");
    if (!param_value)
        DONE = true;

    extern cepCell* CASCADE;

    // Instance initiation
    cepCell* instances = cep_dict_add_list(CASCADE, CEP_AUTOID, CEP_ACRO("CEP"), CEP_WORD("list"), CEP_STORAGE_LINKED_LIST);       assert_not_null(instances);

    cepCell* self    = cep_dict_add_agency_instance(instances, CEP_ACRO("INST00"), CEP_ACRO("CEP"), CEP_WORD("self"),   NULL);     assert_not_null(stdinp);

    cepCell* stdinp  = cep_dict_add_agency_instance(instances, CEP_ACRO("INST01"), CEP_ACRO("CEP"), CEP_WORD("stdin"),  NULL);     assert_not_null(stdinp);
    cepCell* adder   = cep_dict_add_agency_instance(instances, CEP_ACRO("INST02"), CEP_ACRO("CEP"), CEP_WORD("adder"),  NULL);     assert_not_null(adder);
    cepCell* stdoutp = cep_dict_add_agency_instance(instances, CEP_ACRO("INST03"), CEP_ACRO("CEP"), CEP_WORD("stdout"), NULL));    assert_not_null(stdoutp);

    // Link pipeline
    bool status;
    cepCell* systep = cep_heartbeat_step_instance();

    cep_enzyme_pipeline_create(self, CEP_WORD("my_pipeline"));

    status = cep_enzyme_output_connect(self, CEP_WORD("my_pipeline"), systep, CEP_WORD("system-step"), stdinp, CEP_WORD("system-step"));   assert_true(status);
    status = cep_enzyme_output_connect(self, CEP_WORD("my_pipeline"), stdinp, CEP_WORD("number"),      adder,  CEP_WORD("operand"));       assert_true(status);
    status = cep_enzyme_output_connect(self, CEP_WORD("my_pipeline"), adder,  CEP_WORD("answer"),      stdout, CEP_WORD("number"));        assert_true(status);

    cep_enzyme_pipeline_state(self, CEP_WORD("my_pipeline"), CEP_WORD("start"));

    // Execute pipeline
    while (!DONE) {
        cepCell* cell = cep_heartbeat_step();
        if (!cell) {
            //
            break;
        }
    }

    // Terminate instances
    cep_enzyme_pipeline_dispose(self, CEP_WORD("my_pipeline"));
    cep_cell_delete(instances);
    
  #endif
    return MUNIT_OK;
}

