output_flight_append='results_flight_append.json'
output_write_records='results_write_records.json'
output_write_handshake_shad='results_write_handshake_shad.json'
output_write_handshake_main='results_write_handshake_main.json'
output_many_buffers='result_many_buffers.json'
# flight_append
# till 20
python3 scripts/benchmark.py --output=${output_flight_append}  --parameter "NUM_OUT_RECORDS=[2,4,6,8,10,12,14,16,18,20]" --tests ssl_msg_flight_append_ownsem_harness ssl_msg_flight_append_shadow_harness --seahorn_root $SEAHORN_ROOT_REL --runs 1 --const_parameters="NUM_FLIGHT_APPEND_OPS=4"
# write_records ill 8 to keep graph small
python3 scripts/benchmark.py --output=${output_write_records}   --parameter "NUM_OUT_RECORDS=[2,4,6,8]" --tests ssl_msg_write_records_ownsem_harness ssl_msg_write_records_shadow_harness --seahorn_root $SEAHORN_ROOT_REL --runs 1 --const_parameters="NUM_SSL_CTX=2"
# write_handshake_msgs_ext vs shad till 10
python3 scripts/benchmark.py --output=${output_write_handshake_shad} --parameter "NUM_SSL_CTX=[2,4,6,8,10]" --tests ssl_msg_write_handshake_msgs_ext_ownsem_harness ssl_msg_write_handshake_msgs_ext_shadow_harness --seahorn_root $SEAHORN_ROOT_REL --runs 1 --const_parameters="NUM_OUT_RECORDS=5"
# write_handshake_msgs_ext vs main till 10
python3 scripts/benchmark.py --output=${output_write_handshake_main} --parameter "NUM_SSL_CTX=[2,4,6,8,10]" --tests ssl_msg_write_handshake_msgs_ext_ownsem_harness ssl_msg_write_handshake_msgs_ext_main_harness --seahorn_root $SEAHORN_ROOT_REL --runs 1 --const_parameters="NUM_OUT_RECORDS=5"
#many_buffers main memory till 100
python3 scripts/benchmark.py --output=${output_many_buffers}  --parameter "NUM_OUT_RECORDS=[2,10,20,30,40,50,60,80,100]" --tests many_buffers_harness many_buffers_ownsem_harness --seahorn_root $SEAHORN_ROOT_REL --runs 1 --const_parameters="NUM_SSL_CTX=2"
        
                