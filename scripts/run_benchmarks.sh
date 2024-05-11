
# flight_append
python3 scripts/benchmark.py --parameter "NUM_OUT_RECORDS=[2,4,6,8,10,12,14,16,18,20]" --tests ssl_msg_flight_append_ownsem_harness ssl_msg_flight_append_shadow_harness --seahorn_root $SEAHORN_ROOT_REL --runs 1 --const_parameters="NUM_FLIGHT_APPEND_OPS=4"
# write_records
python3 scripts/benchmark.py --parameter "NUM_OUT_RECORDS=[2,4,6,8,10]" --tests ssl_msg_write_records_ownsem_harness ssl_msg_write_records_shadow_harness --seahorn_root $SEAHORN_ROOT_REL --runs 1 --const_parameters="NUM_SSL_CTX=2"
#many_buffers main memory
python3 scripts/benchmark.py --parameter "NUM_OUT_RECORDS=[2,10,20,30,40,50,60,70,80,90,100]" --tests many_buffers_harness many_buffers_ownsem_harness --seahorn_root $SEAHORN_ROOT_REL --runs 1 --const_parameters="NUM_SSL_CTX=2"
