// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <tio/data.h>
#include <stdio.h>
#include <inttypes.h>

int main(int argc, char *argv[])
{
  if (argc < 2)
    return 1;

  FILE *fp = fopen(argv[1], "r");
  if (!fp)
    return 1;

  // read stream description
  tl_packet_header hdr;
  tl_data_stream_desc_header desc;
  fread(&hdr, sizeof(hdr), 1, fp);
  fread(&desc, sizeof(desc), 1, fp);
  {
    size_t name_len = hdr.payload_size - sizeof(desc);
    char name[name_len+1];
    fread(&name, name_len, 1, fp);
    name[name_len] = '\0';
    double period = 1.0e-6 * desc.period_numerator / desc.period_denominator;
    double rate = 1/period;
    fprintf(stderr, "Dumping stream '%s', %d channels, %zd bytes "
            "at %lf Hz (%lf us)\n",
            name, desc.channels, tl_data_type_size(desc.type),
            rate, period * 1e6);
  }

  size_t sample_size = desc.channels * tl_data_type_size(desc.type);

  uint64_t next_sample = 0;
  while (fread(&hdr, sizeof(hdr), 1, fp) == 1) {
    tl_data_stream_packet data;
    fread(&data.start_sample, hdr.payload_size, 1, fp);

    uint32_t delta = data.start_sample - (uint32_t)next_sample;
    uint64_t start = next_sample + delta;

    size_t n_samples = (hdr.payload_size - sizeof(uint32_t)) / sample_size;
    for (size_t end = start + n_samples; next_sample < end; next_sample++) {
      double tstamp = next_sample * 1e-6 *
        desc.period_numerator / desc.period_denominator;
      printf("%f", tstamp);
      for (size_t i = 0; i < desc.channels; i++) {
        if (next_sample < start) {
          printf(" nan");
        } else {
          void *n = &data.data[sample_size * (next_sample-start) +
                               i * tl_data_type_size(desc.type)];
          if (desc.type == TL_DATA_TYPE_INT32) {
            printf(" %"PRId32, *(int32_t*)n);
          } else if (desc.type == TL_DATA_TYPE_INT16) {
            printf(" %"PRId16, *(int16_t*)n);
          } else if (desc.type == TL_DATA_TYPE_FLOAT32) {
            printf(" %f", *(float*)n);
          } else {
            fprintf(stderr, "unsupported format (TODO)\n");
            return 1;
          }
        }
      }
      printf("\n");
    }
  }

  fclose(fp);

  return 0;
}
