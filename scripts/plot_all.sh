output_flight_append='results_flight_append.json'
output_write_records='results_write_records.json'
output_write_handshake_shad='results_write_handshake_shad.json'
output_write_handshake_main='results_write_handshake_main.json'
output_many_buffers='result_many_buffers.json'

# plot results
python3 scripts/plot.py --input ${output_flight_append} \
                                ${output_write_records} \
                                ${output_write_handshake_shad} \
                                ${output_write_handshake_main} \
                                ${output_many_buffers}  \
                        --job_names "flight_append_shad" \
                        "write_records_shad" \
                        "write_handshake_shad" \
                        "write_handshake_main" \
                        "many_buffers_main"      